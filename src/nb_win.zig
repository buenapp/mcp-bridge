// Windows non-blocking stream layer for the event core (issue #7):
// overlapped WSA sockets on IOCP + the SChannel state machine (TlsNb lives
// in schannel.zig, re-exported here).
//
// Completion model: all socket I/O is overlapped. The conn posts ops via
// readNb/writeNb/startConnect; the IOCP port delivers completions; the
// conn classifies them by OVERLAPPED address via absorbCompletion() (the
// OVERLAPPED structs live in the conn-owned stream — heap-stable), which
// flips the ready state the conn's drive() logic then consumes.
//
// Teardown: cancelAndClose() (CancelIoEx + closesocket) aborts in-flight
// ops; their completions still arrive — the core reaps a conn only once
// pendingOps() == 0, so OVERLAPPED memory never outlives its ops.
//
// stdio is NOT here: IDE-spawned anonymous pipes can't do overlapped I/O
// (verified empirically), so stdin/stdout use libuv-style relay threads
// posting to the loop's IOCP (see main.zig).

const std = @import("std");
const windows = std.os.windows;
const win = @import("win.zig");
const platform = @import("platform.zig");
const evport = @import("evport.zig");
const schannel = @import("schannel.zig");

pub const TlsNb = schannel.TlsNb;
pub const Fd = win.SOCKET;

const ws2 = win.ws2;
const kernel32 = windows.kernel32;

pub var debug_probe: bool = false;

fn dbg(comptime fmt: []const u8, args: anytype) void {
    if (debug_probe) std.debug.print(fmt, args);
}

/// Same outcome shapes as the POSIX nb layer.
pub const NbRead = union(enum) {
    data: usize,
    want_read,
    want_write,
    eof,
};

pub const NbWrite = union(enum) {
    done: usize,
    want_read,
    want_write,
};

pub const Drive = union(enum) {
    done,
    want_read,
    want_write,
};

pub const IoError = error{
    ConnectFailed,
    SocketError,
    TlsError,
    OutOfMemory,
};

// Which overlapped op a completion belongs to.
pub const CompletionKind = enum { recv, send, connect, unknown };

const SIO_GET_EXTENSION_FUNCTION_POINTER: u32 = 0xC8000006;
const SO_UPDATE_CONNECT_CONTEXT: i32 = 0x7010;

var connect_ex_ptr: ?ConnectExFn = null; // cached at first use

const ConnectExFn = *const fn (
    s: win.SOCKET,
    name: *const windows.ws2_32.sockaddr,
    namelen: i32,
    lpSendBuffer: ?*anyopaque,
    dwSendDataLength: u32,
    lpdwBytesSent: ?*u32,
    lpOverlapped: *windows.OVERLAPPED,
) callconv(.winapi) i32;

// WSAID_CONNECTEX
const WSAID_CONNECTEX: windows.GUID = .{
    .Data1 = 0x25a207b9,
    .Data2 = 0xddf3,
    .Data3 = 0x4660,
    .Data4 = .{ 0x8e, 0xe9, 0x76, 0xe5, 0x8c, 0x74, 0x06, 0x3e },
};

fn ensureWsa() IoError!void {
    var wsa: ws2.WSADATA = undefined;
    if (ws2.WSAStartup(0x0202, &wsa) != 0) return IoError.SocketError;
}

fn connectEx(sock: win.SOCKET) IoError!ConnectExFn {
    if (connect_ex_ptr) |p| return p;
    var ptr: ?ConnectExFn = null;
    var ret: u32 = 0;
    const rc = ws2.WSAIoctl(
        sock,
        SIO_GET_EXTENSION_FUNCTION_POINTER,
        &WSAID_CONNECTEX,
        @sizeOf(windows.GUID),
        @ptrCast(&ptr),
        @sizeOf(?ConnectExFn),
        &ret,
        null,
        null,
    );
    if (rc != 0 or ptr == null) return IoError.SocketError;
    connect_ex_ptr = ptr.?;
    return ptr.?;
}

/// Non-blocking TCP stream over overlapped WSA sockets. Owns the socket.
pub const PlainNb = struct {
    sock: win.SOCKET = win.INVALID_SOCKET,

    // OVERLAPPED structs: addresses registered with in-flight ops.
    conn_ov: windows.OVERLAPPED = std.mem.zeroes(windows.OVERLAPPED),
    recv_ov: windows.OVERLAPPED = std.mem.zeroes(windows.OVERLAPPED),
    send_ov: windows.OVERLAPPED = std.mem.zeroes(windows.OVERLAPPED),

    // connect state
    connect_pending: bool = false,
    connect_done: bool = false,
    connect_err: ?usize = null,

    // recv state
    recv_buf: [16384]u8 = undefined,
    recv_off: usize = 0,
    recv_have: usize = 0,
    recv_pending: bool = false,
    recv_eof: bool = false,
    recv_err: ?usize = null,

    // send state
    send_pending: bool = false,
    send_just_done: ?usize = null,
    send_err: ?usize = null,

    /// Overlapped connect to host:port, CONSTRUCTED IN PLACE at `dest`
    /// (the OVERLAPPED structs are registered with in-flight ops — a
    /// by-value return would orphan the connect completion's address).
    /// The socket is associated with the event port (`key` = the conn)
    /// before ConnectEx posts.
    pub fn startConnectInto(self: *PlainNb, alloc: std.mem.Allocator, host: []const u8, port: u16, evp: *evport.EvPort, key: ?*anyopaque) IoError!void {
        self.* = .{};
        try ensureWsa();
        const addr_list = std.net.getAddressList(alloc, host, port) catch return IoError.ConnectFailed;
        defer addr_list.deinit();
        if (addr_list.addrs.len == 0) return IoError.ConnectFailed;

        var last_err: IoError = IoError.ConnectFailed;
        for (addr_list.addrs) |addr| {
            const s = ws2.socket(addr.any.family, ws2.SOCK.STREAM, 0);
            if (s == win.INVALID_SOCKET) continue;

            // ConnectEx requires the socket bound first (wildcard, target's
            // address family — use a std.net.Address so the layout is
            // target-correct).
            const any_addr = switch (addr.any.family) {
                2 => std.net.Address.parseIp4("0.0.0.0", 0) catch unreachable,
                else => std.net.Address.parseIp6("::", 0) catch unreachable,
            };
            if (ws2.bind(s, &any_addr.any, @intCast(any_addr.getOsSockLen())) != 0) {
                _ = ws2.closesocket(s);
                continue;
            }

            evp.monitorRead(s, key); // associate with the port

            self.sock = s;
            const cx = connectEx(s) catch {
                _ = ws2.closesocket(s);
                self.sock = win.INVALID_SOCKET;
                continue;
            };
            const rc = cx(s, @ptrCast(&addr.any), @intCast(addr.getOsSockLen()), null, 0, null, &self.conn_ov);
            if (rc != 0) {
                // Completed inline.
                self.connect_done = true;
                self.postConnectSetup();
                return;
            }
            const e = ws2.WSAGetLastError();
            if (e != .WSA_IO_PENDING) {
                _ = ws2.closesocket(s);
                self.sock = win.INVALID_SOCKET;
                last_err = IoError.ConnectFailed;
                continue;
            }
            self.connect_pending = true;
            return;
        }
        return last_err;
    }

    fn postConnectSetup(self: *PlainNb) void {
        const rc = ws2.setsockopt(self.sock, win.SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, null, 0);
        dbg("nbwin: SO_UPDATE_CONNECT_CONTEXT rc={d} err={d}\n", .{ rc, @intFromEnum(ws2.WSAGetLastError()) });
    }

    /// Confirm the connect after its completion (or inline completion).
    pub fn connectDone(self: *PlainNb) IoError!void {
        if (self.connect_err) |e| {
            _ = e;
            return IoError.ConnectFailed;
        }
        self.postConnectSetup();
    }

    /// Feed a completion from the port. Returns which op completed.
    pub fn absorbCompletion(self: *PlainNb, ov: ?*windows.OVERLAPPED, bytes: usize, err: ?usize) CompletionKind {
        if (ov == null) return .unknown;
        const o = ov.?;
        if (o == &self.conn_ov) {
            self.connect_pending = false;
            if (err) |e| self.connect_err = e else self.connect_done = true;
            return .connect;
        }
        if (o == &self.recv_ov) {
            self.recv_pending = false;
            if (err) |e| {
                self.recv_err = e;
            } else if (bytes == 0) {
                self.recv_eof = true;
            } else {
                self.recv_off = 0;
                self.recv_have = bytes;
            }
            return .recv;
        }
        if (o == &self.send_ov) {
            self.send_pending = false;
            if (err) |e| self.send_err = e else self.send_just_done = bytes;
            return .send;
        }
        return .unknown;
    }

    pub fn readNb(self: *PlainNb, out: []u8) IoError!NbRead {
        if (self.recv_err != null) return IoError.SocketError;
        // Serve buffered bytes first (they arrived via completion).
        if (self.recv_have > 0) {
            const n = @min(out.len, self.recv_have - self.recv_off);
            @memcpy(out[0..n], self.recv_buf[self.recv_off .. self.recv_off + n]);
            self.recv_off += n;
            if (self.recv_off == self.recv_have) self.recv_have = 0;
            return .{ .data = n };
        }
        if (self.recv_eof) return .eof;
        if (self.recv_pending) return .want_read;
        // Post the next overlapped read. Sockets ALWAYS queue a completion
        // (even on inline success), so all data arrives via absorbCompletion.
        var buf = ws2.WSABUF{ .len = self.recv_buf.len, .buf = &self.recv_buf };
        var flags: u32 = 0;
        const rc = ws2.WSARecv(self.sock, @ptrCast(&buf), 1, null, &flags, &self.recv_ov, null);
        dbg("nbwin: WSARecv post rc={d} err={d}\n", .{ rc, @intFromEnum(ws2.WSAGetLastError()) });
        if (rc == 0 or ws2.WSAGetLastError() == .WSA_IO_PENDING) {
            self.recv_pending = true;
            return .want_read;
        }
        return IoError.SocketError;
    }

    pub fn writeNb(self: *PlainNb, data: []const u8) IoError!NbWrite {
        // Account for a completed pending send first (completions carry the
        // byte count — inline WSASend success still queues a completion).
        if (self.send_just_done) |n| {
            self.send_just_done = null;
            return .{ .done = n };
        }
        if (self.send_err != null) return IoError.SocketError;
        if (self.send_pending) return .want_write;
        if (data.len == 0) return .{ .done = 0 };

        var buf = ws2.WSABUF{ .len = @intCast(data.len), .buf = @constCast(data.ptr) };
        const rc = ws2.WSASend(self.sock, @ptrCast(&buf), 1, null, 0, &self.send_ov, null);
        if (rc == 0 or ws2.WSAGetLastError() == .WSA_IO_PENDING) {
            self.send_pending = true;
            return .want_write;
        }
        return IoError.SocketError;
    }

    /// In-flight op count (for the core's deferred reap).
    pub fn pendingOps(self: *const PlainNb) usize {
        var n: usize = 0;
        if (self.connect_pending) n += 1;
        if (self.recv_pending) n += 1;
        if (self.send_pending) n += 1;
        return n;
    }

    /// Abort in-flight ops (their completions still arrive — absorbed as
    /// errors) and close the socket.
    pub fn cancelAndClose(self: *PlainNb) void {
        if (self.sock != win.INVALID_SOCKET) {
            _ = kernel32.CancelIoEx(@ptrCast(self.sock), null);
            _ = ws2.closesocket(self.sock);
            self.sock = win.INVALID_SOCKET;
        }
    }

    pub fn closeNotify(self: *PlainNb) void {
        _ = self;
    }

    pub fn deinit(self: *PlainNb) void {
        self.cancelAndClose();
    }
};

/// The platform stream union: plain TCP or SChannel TLS over one socket.
pub const Stream = union(enum) {
    plain: PlainNb,
    tls: TlsNb,

    pub fn fd(self: *const Stream) win.SOCKET {
        return switch (self.*) {
            .plain => |*s| s.sock,
            .tls => |*s| s.plain.sock,
        };
    }

    pub fn startConnectInto(self: *Stream, alloc: std.mem.Allocator, host: []const u8, port: u16, evp: *evport.EvPort, key: ?*anyopaque) IoError!void {
        self.* = .{ .plain = .{} };
        return self.plain.startConnectInto(alloc, host, port, evp, key);
    }

    pub fn connectDone(self: *Stream) IoError!void {
        return switch (self.*) {
            .plain => |*s| s.connectDone(),
            .tls => unreachable,
        };
    }

    /// Replace the plain variant with a TLS client on the same socket.
    /// No ops are in flight at this point (connect just completed), so the
    /// move is safe.
    pub fn swapToTls(self: *Stream, alloc: std.mem.Allocator, host: []const u8) schannel.TlsError!void {
        const p = switch (self.*) {
            .plain => |*s| s.*,
            .tls => unreachable,
        };
        self.* = .{ .tls = try TlsNb.initFromPlain(alloc, p, host) };
    }

    pub fn handshakeDrive(self: *Stream) schannel.TlsError!Drive {
        return switch (self.*) {
            .plain => .done,
            .tls => |*s| s.handshakeDrive(),
        };
    }

    /// DANE/PKI verify hook after a completed TLS handshake (synchronous;
    /// runs on the loop thread at connection setup).
    pub fn verifyPeer(self: *Stream, v: *platform.Verifier) bool {
        return switch (self.*) {
            .plain => true,
            .tls => |*s| s.verifyPeer(v),
        };
    }

    pub fn readNb(self: *Stream, out: []u8) IoError!NbRead {
        return switch (self.*) {
            .plain => |*s| s.readNb(out),
            .tls => |*s| s.readNb(out) catch |err| switch (err) {
                error.OutOfMemory => IoError.OutOfMemory,
                else => IoError.TlsError,
            },
        };
    }

    pub fn writeNb(self: *Stream, data: []const u8) IoError!NbWrite {
        return switch (self.*) {
            .plain => |*s| s.writeNb(data),
            .tls => |*s| s.writeNb(data) catch |err| switch (err) {
                error.OutOfMemory => IoError.OutOfMemory,
                else => IoError.TlsError,
            },
        };
    }

    /// Route a completion into the owning sub-stream.
    pub fn absorbCompletion(self: *Stream, ov: ?*windows.OVERLAPPED, bytes: usize, err: ?usize) CompletionKind {
        return switch (self.*) {
            .plain => |*s| s.absorbCompletion(ov, bytes, err),
            .tls => |*s| s.plain.absorbCompletion(ov, bytes, err),
        };
    }

    pub fn pendingOps(self: *const Stream) usize {
        return switch (self.*) {
            .plain => |*s| s.pendingOps(),
            .tls => |*s| s.plain.pendingOps(),
        };
    }

    /// Best-effort TLS close_notify (plain: no-op).
    pub fn closeNotify(self: *Stream) void {
        switch (self.*) {
            .plain => {},
            .tls => |*s| s.closeNotify(),
        }
    }

    /// Cancel in-flight ops + close the socket + free TLS state.
    pub fn deinit(self: *Stream) void {
        switch (self.*) {
            .plain => |*s| s.deinit(),
            .tls => |*s| s.deinit(),
        }
    }
};
