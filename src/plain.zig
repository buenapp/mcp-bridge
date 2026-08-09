// Plaintext TCP stream with the same read/writeAll surface as TlsStream,
// for http:// endpoints (LAN testing, LittleRedPBX).

const std = @import("std");
const win = @import("win.zig");

const ws2 = win.ws2;

pub const PlainError = error{
    WsaStartup,
    ConnectFailed,
    SocketError,
    Timeout,
};

pub const PlainStream = struct {
    sock: ws2.SOCKET = win.INVALID_SOCKET,
    alloc: std.mem.Allocator,

    pub fn connect(alloc: std.mem.Allocator, host: []const u8, port: u16) PlainError!PlainStream {
        var wsa: ws2.WSADATA = undefined;
        if (ws2.WSAStartup(0x0202, &wsa) != 0) return PlainError.WsaStartup;

        const addr_list = std.net.getAddressList(alloc, host, port) catch return PlainError.ConnectFailed;
        defer addr_list.deinit();
        if (addr_list.addrs.len == 0) return PlainError.ConnectFailed;

        for (addr_list.addrs) |addr| {
            const s = ws2.socket(addr.any.family, ws2.SOCK.STREAM, 0);
            if (s == win.INVALID_SOCKET) continue;
            const rc = ws2.connect(s, &addr.any, @intCast(addr.getOsSockLen()));
            if (rc == 0) {
                win.setTimeouts(s, 30_000, 15_000);
                return .{ .sock = s, .alloc = alloc };
            }
            _ = ws2.closesocket(s);
        }
        return PlainError.ConnectFailed;
    }

    pub fn read(self: *PlainStream, out: []u8) PlainError!usize {
        const n = ws2.recv(self.sock, out.ptr, @intCast(out.len), 0);
        if (n == 0) return 0;
        if (n == ws2.SOCKET_ERROR) {
            if (@intFromEnum(ws2.WSAGetLastError()) == win.WSAETIMEDOUT) return PlainError.Timeout;
            return PlainError.SocketError;
        }
        return @intCast(n);
    }

    pub fn writeAll(self: *PlainStream, data: []const u8) PlainError!void {
        var off: usize = 0;
        while (off < data.len) {
            const n = ws2.send(self.sock, data.ptr + off, @intCast(data.len - off), 0);
            if (n <= 0) return PlainError.SocketError;
            off += @intCast(n);
        }
    }

    pub fn closeNotify(self: *PlainStream) void {
        _ = self;
    }

    /// Abruptly unblock a recv blocked in ANOTHER thread (pump teardown).
    pub fn forceShutdown(self: *PlainStream) void {
        if (self.sock != win.INVALID_SOCKET) _ = ws2.shutdown(self.sock, ws2.SD_BOTH);
    }

    pub fn deinit(self: *PlainStream) void {
        if (self.sock != win.INVALID_SOCKET) _ = ws2.closesocket(self.sock);
        self.sock = win.INVALID_SOCKET;
    }
};
