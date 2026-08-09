// POSIX counterparts to win.zig: fd-based stdio, blocking TCP connect with
// recv/send timeouts (30s/15s parity with the Windows build), and a
// plaintext stream with the same surface as plain.zig's PlainStream.

const std = @import("std");

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

    pub fn deinit(self: *PlainStream) void {
        if (self.sock >= 0) std.posix.close(self.sock);
        self.sock = -1;
    }
};
