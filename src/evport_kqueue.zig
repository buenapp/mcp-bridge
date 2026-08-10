// FreeBSD event port: kqueue backend.
//
// Global-rule discipline:
//   - Staged changelist: monitor*/unmonitor* accumulate struct kevent into a
//     local array; the next wait() submits changelist + eventlist in ONE
//     kevent() call. No kevent() call exists solely to register fds.
//   - EV_CLEAR (edge-triggered) on EVFILT_READ: read handlers must fully
//     drain buffered data (plain: read to EAGAIN; TLS: SSL_read to
//     WANT_READ, which implies the socket hit EAGAIN).
//   - EV_ONESHOT on EVFILT_WRITE: connect completion and buffer-space
//     events are single-shot; the connection re-arms on demand.
//   - Cross-thread wakeup: pipe trick (EVFILT_SIGNAL is unreliable for
//     that). wake() writes 1 byte; wait() coalesces/drains to one event.
//   - Closing fds need no unmonitoring: close(2) removes all filters. The
//     core defers close() until just after a wait() flush so staged entries
//     never reference a closed (and possibly recycled) fd.

const std = @import("std");

// FreeBSD 12+ struct kevent (sys/event.h): the plain kevent() syscall uses
// the EXTENDED 64-byte layout — omitting ext[4] corrupts multi-entry
// changelists (kernel strides 64 bytes per entry).
const Kevent = extern struct {
    ident: usize = 0,
    filter: i16 = 0,
    flags: u16 = 0,
    fflags: u32 = 0,
    data: i64 = 0,
    udata: ?*anyopaque = null,
    ext: [4]u64 = .{ 0, 0, 0, 0 },
};

extern "c" fn kqueue() c_int;
extern "c" fn kevent(
    kq: c_int,
    changelist: ?[*]const Kevent,
    nchanges: c_int,
    eventlist: ?[*]Kevent,
    nevents: c_int,
    timeout: ?*const std.c.timespec,
) c_int;
extern "c" fn pipe2(fds: *[2]c_int, flags: c_int) c_int;

const EVFILT_READ: i16 = -1;
const EVFILT_WRITE: i16 = -2;

const EV_ADD: u16 = 0x0001;
const EV_DELETE: u16 = 0x0002;
const EV_ONESHOT: u16 = 0x0010;
const EV_CLEAR: u16 = 0x0020;
const EV_EOF: u16 = 0x8000;
const EV_ERROR: u16 = 0x4000;

// O_NONBLOCK | O_CLOEXEC for pipe2 (FreeBSD fcntl.h values, verified
// against std.posix.O in the std-surface probe).
const PIPE2_FLAGS: c_int = 0x0004 | 0x00100000;

pub const Event = struct {
    udata: ?*anyopaque = null,
    readable: bool = false,
    writable: bool = false,
    eof: bool = false,
    err: bool = false,
    /// EV_ERROR payload (errno) when err is set.
    err_no: i64 = 0,
    wake: bool = false,
};

pub const Error = error{
    KqueueFailed,
    PipeFailed,
    WaitFailed,
    OutOfMemory,
};

/// Stable address used as the wake pipe's udata tag (module-level so a
/// by-value EvPort return never leaves it dangling).
var wake_sentinel: u8 = 0;

pub const EvPort = struct {
    kq: c_int = -1,
    alloc: std.mem.Allocator,
    /// Staged changelist, flushed by the next wait().
    changes: std.ArrayList(Kevent) = .empty,
    wake_r: c_int = -1,
    wake_w: c_int = -1,

    pub fn init(alloc: std.mem.Allocator) Error!EvPort {
        const kq = kqueue();
        if (kq < 0) return Error.KqueueFailed;
        errdefer _ = std.c.close(kq);

        var fds: [2]c_int = undefined;
        if (pipe2(&fds, PIPE2_FLAGS) != 0) return Error.PipeFailed;
        errdefer {
            _ = std.c.close(fds[0]);
            _ = std.c.close(fds[1]);
        }

        var self = EvPort{ .kq = kq, .alloc = alloc, .wake_r = fds[0], .wake_w = fds[1] };
        self.monitorRead(self.wake_r, @as(?*anyopaque, &wake_sentinel));
        return self;
    }

    pub fn deinit(self: *EvPort) void {
        if (self.kq >= 0) _ = std.c.close(self.kq);
        if (self.wake_r >= 0) _ = std.c.close(self.wake_r);
        if (self.wake_w >= 0) _ = std.c.close(self.wake_w);
        self.kq = -1;
        self.wake_r = -1;
        self.wake_w = -1;
        self.changes.deinit(self.alloc);
    }

    /// Persistent edge-triggered read interest (EV_ADD | EV_CLEAR).
    pub fn monitorRead(self: *EvPort, fd: c_int, udata: ?*anyopaque) void {
        self.stage(.{ .ident = @intCast(fd), .filter = EVFILT_READ, .flags = EV_ADD | EV_CLEAR, .udata = udata });
    }

    /// One-shot write interest (EV_ADD | EV_ONESHOT): connect completion or
    /// send-buffer space after a short write.
    pub fn monitorWrite(self: *EvPort, fd: c_int, udata: ?*anyopaque) void {
        self.stage(.{ .ident = @intCast(fd), .filter = EVFILT_WRITE, .flags = EV_ADD | EV_ONESHOT, .udata = udata });
    }

    /// Drop write interest on an fd that STAYS OPEN (flow control only).
    pub fn unmonitorWrite(self: *EvPort, fd: c_int) void {
        self.stage(.{ .ident = @intCast(fd), .filter = EVFILT_WRITE, .flags = EV_DELETE });
    }

    /// Drop read interest on an fd that STAYS OPEN (e.g. stdin after EOF).
    pub fn unmonitorRead(self: *EvPort, fd: c_int) void {
        self.stage(.{ .ident = @intCast(fd), .filter = EVFILT_READ, .flags = EV_DELETE });
    }

    /// Drop STAGED (unflushed) changelist entries for an fd about to be
    /// closed. close(2) itself removes the fd's live filters; this prevents
    /// staged entries from applying to a recycled fd number at the next
    /// wait() flush.
    pub fn purgeFd(self: *EvPort, fd: c_int) void {
        const ident: usize = @intCast(fd);
        var i: usize = 0;
        while (i < self.changes.items.len) {
            if (self.changes.items[i].ident == ident) {
                _ = self.changes.swapRemove(i);
            } else {
                i += 1;
            }
        }
    }

    /// Wake a wait() blocked in another thread. Non-blocking; a full pipe
    /// means the loop is already awake (coalesced).
    pub fn wake(self: *EvPort) void {
        const b = [1]u8{1};
        _ = std.c.write(self.wake_w, &b, 1);
    }

    fn stage(self: *EvPort, kev: Kevent) void {
        self.changes.append(self.alloc, kev) catch {};
    }

    /// Flush the staged changelist and harvest events in ONE kevent() call.
    /// timeout_ms: null = block until an event; 0 = harvest without blocking.
    pub fn wait(self: *EvPort, events: []Event, timeout_ms: ?i32) Error!usize {
        var kbuf: [64]Kevent = undefined;
        const cap = @min(events.len, kbuf.len);

        var ts: std.c.timespec = undefined;
        var tsp: ?*const std.c.timespec = null;
        if (timeout_ms) |ms| {
            ts = .{ .sec = @intCast(@divTrunc(ms, 1000)), .nsec = @intCast(@mod(ms, 1000) * 1_000_000) };
            tsp = &ts;
        }

        const changelist: ?[*]const Kevent = if (self.changes.items.len > 0) self.changes.items.ptr else null;
        const n = kevent(self.kq, changelist, @intCast(self.changes.items.len), &kbuf, @intCast(cap), tsp);
        self.changes.clearRetainingCapacity();
        if (n < 0) {
            const e = std.posix.errno(@as(isize, n));
            if (e == .INTR) return 0;
            return Error.WaitFailed;
        }

        var out: usize = 0;
        var woke = false;
        for (kbuf[0..@intCast(n)]) |kev| {
            if (kev.udata == @as(?*anyopaque, &wake_sentinel)) {
                if (!woke) {
                    woke = true;
                    self.drainWake();
                    events[out] = .{ .wake = true };
                    out += 1;
                }
                continue;
            }
            events[out] = .{
                .udata = kev.udata,
                .readable = kev.filter == EVFILT_READ,
                .writable = kev.filter == EVFILT_WRITE,
                .eof = (kev.flags & EV_EOF) != 0,
                .err = (kev.flags & EV_ERROR) != 0,
                .err_no = kev.data,
            };
            out += 1;
        }
        return out;
    }

    fn drainWake(self: *EvPort) void {
        var tmp: [64]u8 = undefined;
        while (true) {
            _ = std.posix.read(self.wake_r, &tmp) catch break;
        }
    }
};

// --------------------------------------------------------------- tests ----

test "kqueue: socket read readiness + EV_CLEAR edge semantics" {
    const alloc = std.testing.allocator;
    var evp = try EvPort.init(alloc);
    defer evp.deinit();

    var fds: [2]c_int = undefined;
    try std.testing.expectEqual(@as(c_int, 0), std.c.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM | std.posix.SOCK.NONBLOCK | std.posix.SOCK.CLOEXEC, 0, &fds));
    defer _ = std.c.close(fds[0]);
    defer _ = std.c.close(fds[1]);

    var tag: u8 = 1;
    evp.monitorRead(fds[0], &tag);

    _ = try std.posix.write(fds[1], "ab");

    var events: [8]Event = undefined;
    const n = try evp.wait(&events, 1000);
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expect(events[0].readable);
    try std.testing.expect(events[0].udata == @as(?*anyopaque, &tag));

    // The EV_CLEAR contract the core relies on: a handler that fully drains
    // (read to EAGAIN) gets exactly-once delivery per edge — no re-fire
    // until new data arrives.
    var buf: [4]u8 = undefined;
    while (true) {
        _ = std.posix.read(fds[0], &buf) catch |err| switch (err) {
            error.WouldBlock => break,
            else => return err,
        };
    }
    try std.testing.expectEqual(@as(usize, 0), try evp.wait(&events, 0));

    // New write = new edge.
    _ = try std.posix.write(fds[1], "c");
    try std.testing.expectEqual(@as(usize, 1), try evp.wait(&events, 1000));
    try std.testing.expect(events[0].readable);
}

test "kqueue: one-shot write interest re-arms on demand" {
    const alloc = std.testing.allocator;
    var evp = try EvPort.init(alloc);
    defer evp.deinit();

    var fds: [2]c_int = undefined;
    try std.testing.expectEqual(@as(c_int, 0), pipe2(&fds, PIPE2_FLAGS));
    defer _ = std.c.close(fds[0]);
    defer _ = std.c.close(fds[1]);

    var tag: u8 = 2;
    evp.monitorWrite(fds[1], &tag);

    var events: [8]Event = undefined;
    try std.testing.expectEqual(@as(usize, 1), try evp.wait(&events, 1000));
    try std.testing.expect(events[0].writable);

    // ONESHOT consumed: no second delivery without re-arming.
    try std.testing.expectEqual(@as(usize, 0), try evp.wait(&events, 0));

    evp.monitorWrite(fds[1], &tag);
    try std.testing.expectEqual(@as(usize, 1), try evp.wait(&events, 1000));
    try std.testing.expect(events[0].writable);
}

test "kqueue: peer close delivers eof" {
    const alloc = std.testing.allocator;
    var evp = try EvPort.init(alloc);
    defer evp.deinit();

    var fds: [2]c_int = undefined;
    try std.testing.expectEqual(@as(c_int, 0), pipe2(&fds, PIPE2_FLAGS));
    defer _ = std.c.close(fds[0]);

    var tag: u8 = 3;
    evp.monitorRead(fds[0], &tag);
    _ = std.c.close(fds[1]);

    var events: [8]Event = undefined;
    try std.testing.expectEqual(@as(usize, 1), try evp.wait(&events, 1000));
    try std.testing.expect(events[0].readable);
    try std.testing.expect(events[0].eof);
    var one: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 0), try std.posix.read(fds[0], &one));
}

test "kqueue: wake posts a single coalesced event" {
    const alloc = std.testing.allocator;
    var evp = try EvPort.init(alloc);
    defer evp.deinit();

    evp.wake();
    evp.wake();
    evp.wake();

    var events: [8]Event = undefined;
    const n = try evp.wait(&events, 1000);
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expect(events[0].wake);
    // Pipe drained: no further wake events.
    try std.testing.expectEqual(@as(usize, 0), try evp.wait(&events, 0));
}

test "kqueue: non-blocking connect completes via write filter" {
    const alloc = std.testing.allocator;

    const addr = try std.net.Address.parseIp4("127.0.0.1", 0);
    var server = try addr.listen(.{});
    defer server.deinit();

    const s = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.STREAM | std.posix.SOCK.NONBLOCK | std.posix.SOCK.CLOEXEC, 0);
    defer std.posix.close(s);

    std.posix.connect(s, &server.listen_address.any, server.listen_address.getOsSockLen()) catch |err| switch (err) {
        error.WouldBlock => {}, // EINPROGRESS: expected
        else => return err,
    };

    var evp = try EvPort.init(alloc);
    defer evp.deinit();
    var tag: u8 = 4;
    evp.monitorWrite(s, &tag);

    var events: [8]Event = undefined;
    try std.testing.expectEqual(@as(usize, 1), try evp.wait(&events, 1000));
    try std.testing.expect(events[0].writable);

    var so_error: c_int = -1;
    try std.posix.getsockopt(s, std.posix.SOL.SOCKET, std.posix.SO.ERROR, std.mem.asBytes(&so_error));
    try std.testing.expectEqual(@as(c_int, 0), so_error);
}
