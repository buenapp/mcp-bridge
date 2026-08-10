// POSIX counterparts to win.zig: fd-based stdio, blocking TCP connect with
// recv/send timeouts (30s/15s parity with the Windows build), and a
// plaintext stream with the same surface as plain.zig's PlainStream.
//
// The lower half (PlainNb) is the event-core non-blocking socket layer:
// EINPROGRESS connect, WouldBlock-mapped reads/writes, MSG_NOSIGNAL sends
// (the bridge never takes SIGPIPE). The blocking layer above retires once
// the event-core rework (issue #7) lands.

const std = @import("std");
const builtin = @import("builtin");

pub const RECV_TIMEOUT_MS = 30_000;
pub const SEND_TIMEOUT_MS = 15_000;

// ---------------------------------------------------------------- stdio ----

/// Read from stdin. Returns 0 on EOF. Caller treats error as fatal/EOF.
pub fn readStdin(buf: []u8) !usize {
    while (true) {
        return std.posix.read(std.posix.STDIN_FILENO, buf) catch |err| switch (err) {
            error.WouldBlock => continue, // stdin is blocking; defensive only
            else => return err,
        };
    }
}

/// Write all bytes to stdout.
pub fn writeStdoutAll(bytes: []const u8) !void {
    var off: usize = 0;
    while (off < bytes.len) {
        off += std.posix.write(std.posix.STDOUT_FILENO, bytes[off..]) catch |err| switch (err) {
            error.WouldBlock => continue,
            else => return error.WriteFailed,
        };
    }
}

// --------------------------------------------------------------- sockets --

fn setTimeouts(sock: std.posix.fd_t, recv_ms: u32, send_ms: u32) void {
    const rcv: std.posix.timeval = .{
        .sec = @intCast(recv_ms / 1000),
        .usec = @intCast((recv_ms % 1000) * 1000),
    };
    const snd: std.posix.timeval = .{
        .sec = @intCast(send_ms / 1000),
        .usec = @intCast((send_ms % 1000) * 1000),
    };
    std.posix.setsockopt(sock, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&rcv)) catch {};
    std.posix.setsockopt(sock, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, std.mem.asBytes(&snd)) catch {};
}

pub const ConnectError = error{
    ConnectFailed,
};

/// Blocking TCP connect to host:port, trying each resolved address.
/// Applies the standard recv/send timeouts before returning.
pub fn tcpConnect(alloc: std.mem.Allocator, host: []const u8, port: u16) ConnectError!std.posix.fd_t {
    const addr_list = std.net.getAddressList(alloc, host, port) catch return ConnectError.ConnectFailed;
    defer addr_list.deinit();
    if (addr_list.addrs.len == 0) return ConnectError.ConnectFailed;

    for (addr_list.addrs) |addr| {
        const s = std.posix.socket(addr.any.family, std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC, 0) catch continue;
        std.posix.connect(s, &addr.any, addr.getOsSockLen()) catch {
            std.posix.close(s);
            continue;
        };
        setTimeouts(s, RECV_TIMEOUT_MS, SEND_TIMEOUT_MS);
        return s;
    }
    return ConnectError.ConnectFailed;
}

// ---------------------------------------------------------- plain stream --

pub const PlainError = error{
    ConnectFailed,
    SocketError,
    Timeout,
};

pub const PlainStream = struct {
    sock: std.posix.fd_t = -1,
    alloc: std.mem.Allocator,

    pub fn connect(alloc: std.mem.Allocator, host: []const u8, port: u16) PlainError!PlainStream {
        const s = tcpConnect(alloc, host, port) catch return PlainError.ConnectFailed;
        return .{ .sock = s, .alloc = alloc };
    }

    pub fn read(self: *PlainStream, out: []u8) PlainError!usize {
        while (true) {
            return std.posix.read(self.sock, out) catch |err| switch (err) {
                error.WouldBlock => return PlainError.Timeout, // SO_RCVTIMEO expired
                else => return PlainError.SocketError,
            };
        }
    }

    pub fn writeAll(self: *PlainStream, data: []const u8) PlainError!void {
        var off: usize = 0;
        while (off < data.len) {
            off += std.posix.write(self.sock, data[off..]) catch |err| switch (err) {
                error.WouldBlock => return PlainError.Timeout, // SO_SNDTIMEO expired
                else => return PlainError.SocketError,
            };
        }
    }

    pub fn closeNotify(self: *PlainStream) void {
        _ = self;
    }

    /// Abruptly unblock a read() blocked in ANOTHER thread (pump
    /// teardown). shutdown() wakes the blocked recv immediately, unlike
    /// close().
    pub fn forceShutdown(self: *PlainStream) void {
        if (self.sock >= 0) std.posix.shutdown(self.sock, .both) catch {};
    }

    pub fn deinit(self: *PlainStream) void {
        if (self.sock >= 0) std.posix.close(self.sock);
        self.sock = -1;
    }
};

// ------------------------------------------------------- non-blocking ----

/// MSG_NOSIGNAL per target (std.os.freebsd exposes no MSG constants).
/// send()-only flag: writes to a torn-down socket return EPIPE instead of
/// raising SIGPIPE.
const MSG_NOSIGNAL: u32 = switch (builtin.os.tag) {
    .freebsd => 0x00020000,
    .linux => 0x00004000,
    else => 0,
};

/// Non-blocking read outcome.
pub const NbRead = union(enum) {
    data: usize, // > 0 bytes
    want_read, // drained to EAGAIN; wait for the next read event
    want_write, // TLS-only (post-handshake control messages); never for plain
    eof, // clean close
};

/// Non-blocking write outcome.
pub const NbWrite = union(enum) {
    done: usize, // bytes accepted (may be a partial write)
    want_read, // TLS-only; never for plain
    want_write, // send buffer full; wait for the write event
};

/// Non-blocking plaintext TCP stream for the event core.
pub const PlainNb = struct {
    sock: std.posix.fd_t = -1,

    pub const Error = error{
        ConnectFailed,
        SocketError,
    };

    /// socket(SOCK_NONBLOCK) + connect(). On success the fd is either in
    /// EINPROGRESS state or instantly connected (loopback) — register write
    /// interest and confirm with connectDone() on the first write event.
    pub fn startConnect(alloc: std.mem.Allocator, host: []const u8, port: u16) Error!PlainNb {
        const addr_list = std.net.getAddressList(alloc, host, port) catch return Error.ConnectFailed;
        defer addr_list.deinit();
        if (addr_list.addrs.len == 0) return Error.ConnectFailed;

        for (addr_list.addrs) |addr| {
            const s = std.posix.socket(addr.any.family, std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC | std.posix.SOCK.NONBLOCK, 0) catch continue;
            std.posix.connect(s, &addr.any, addr.getOsSockLen()) catch |err| switch (err) {
                error.WouldBlock => return .{ .sock = s }, // EINPROGRESS
                else => {
                    std.posix.close(s);
                    continue;
                },
            };
            return .{ .sock = s }; // connected immediately
        }
        return Error.ConnectFailed;
    }

    /// Confirm the connect after the first write event (SO_ERROR).
    pub fn connectDone(self: *PlainNb) Error!void {
        var so_error: c_int = 0;
        std.posix.getsockopt(self.sock, std.posix.SOL.SOCKET, std.posix.SO.ERROR, std.mem.asBytes(&so_error)) catch return Error.SocketError;
        if (so_error != 0) return Error.ConnectFailed;
    }

    pub fn readNb(self: *PlainNb, out: []u8) Error!NbRead {
        const n = std.posix.read(self.sock, out) catch |err| switch (err) {
            error.WouldBlock => return .want_read,
            else => return Error.SocketError,
        };
        if (n == 0) return .eof;
        return .{ .data = n };
    }

    pub fn writeNb(self: *PlainNb, data: []const u8) Error!NbWrite {
        const n = std.posix.send(self.sock, data, MSG_NOSIGNAL) catch |err| switch (err) {
            error.WouldBlock => return .want_write,
            else => return Error.SocketError,
        };
        return .{ .done = n };
    }

    pub fn closeNotify(self: *PlainNb) void {
        _ = self;
    }

    pub fn deinit(self: *PlainNb) void {
        if (self.sock >= 0) std.posix.close(self.sock);
        self.sock = -1;
    }
};

// --------------------------------------------------------------- tests ----

test "PlainNb: non-blocking connect + round trip over loopback" {
    const evport = @import("evport.zig");
    const alloc = std.testing.allocator;

    const addr = try std.net.Address.parseIp4("127.0.0.1", 0);
    var server = try addr.listen(.{});
    defer server.deinit();

    var client = try PlainNb.startConnect(alloc, "127.0.0.1", server.listen_address.getPort());
    defer client.deinit();

    var evp = try evport.EvPort.init(alloc);
    defer evp.deinit();
    var tag: u8 = 9;
    evp.monitorWrite(client.sock, &tag);

    var events: [8]evport.Event = undefined;
    try std.testing.expectEqual(@as(usize, 1), try evp.wait(&events, 1000));
    try std.testing.expect(events[0].writable);
    try client.connectDone();

    // Write a request; the server echoes it.
    switch (try client.writeNb("ping")) {
        .done => |n| try std.testing.expectEqual(@as(usize, 4), n),
        else => return error.TestUnexpectedResult,
    }
    var conn = try server.accept();
    var rbuf: [16]u8 = undefined;
    const rn = try conn.stream.read(&rbuf);
    try std.testing.expectEqualStrings("ping", rbuf[0..rn]);
    _ = try conn.stream.write("pong");

    // Read side: readable event, then data, then EAGAIN.
    evp.monitorRead(client.sock, &tag);
    try std.testing.expectEqual(@as(usize, 1), try evp.wait(&events, 1000));
    try std.testing.expect(events[0].readable);
    switch (try client.readNb(&rbuf)) {
        .data => |n| try std.testing.expectEqualStrings("pong", rbuf[0..n]),
        else => return error.TestUnexpectedResult,
    }
    switch (try client.readNb(&rbuf)) {
        .want_read => {},
        else => return error.TestUnexpectedResult,
    }

    // Peer close → readable + eof.
    conn.stream.close();
    try std.testing.expectEqual(@as(usize, 1), try evp.wait(&events, 1000));
    try std.testing.expect(events[0].readable or events[0].eof);
    switch (try client.readNb(&rbuf)) {
        .eof => {},
        else => return error.TestUnexpectedResult,
    }
}

test "PlainNb: connect refused surfaces at connectDone" {
    const evport = @import("evport.zig");
    const alloc = std.testing.allocator;

    // Bind+close to find a free port nothing listens on.
    const addr = try std.net.Address.parseIp4("127.0.0.1", 0);
    var server = try addr.listen(.{});
    const port = server.listen_address.getPort();
    server.deinit();

    var client = try PlainNb.startConnect(alloc, "127.0.0.1", port);
    defer client.deinit();

    var evp = try evport.EvPort.init(alloc);
    defer evp.deinit();
    var tag: u8 = 10;
    evp.monitorWrite(client.sock, &tag);

    var events: [8]evport.Event = undefined;
    _ = try evp.wait(&events, 1000);
    try std.testing.expectError(PlainNb.Error.ConnectFailed, client.connectDone());
}
