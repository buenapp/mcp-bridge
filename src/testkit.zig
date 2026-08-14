// Shared mock-server toolkit for the integration tests (test_transport,
// test_httpc): in-process plain-HTTP mock servers on 127.0.0.1.
//
// Windows note: std.net.Stream.read/write go through ReadFile/WriteFile on
// the socket handle, which Windows rejects for sockets (87) — mock I/O
// uses raw winsock calls there. The client under test is unaffected (it
// uses its own nb layer).

const std = @import("std");
const builtin = @import("builtin");

const ws2 = if (builtin.os.tag == .windows) std.os.windows.ws2_32 else struct {};

/// Read from a mock connection; 0 = peer closed.
pub fn sockRead(stream: *std.net.Stream, buf: []u8) !usize {
    if (builtin.os.tag == .windows) {
        const n = ws2.recv(stream.handle, buf.ptr, @intCast(buf.len), 0);
        if (n == 0) return 0;
        if (n == ws2.SOCKET_ERROR) return error.SocketError;
        return @intCast(n);
    }
    return stream.read(buf);
}

pub fn sockWriteAll(stream: *std.net.Stream, bytes: []const u8) !void {
    if (builtin.os.tag == .windows) {
        var off: usize = 0;
        while (off < bytes.len) {
            const n = ws2.send(stream.handle, bytes.ptr + off, @intCast(bytes.len - off), 0);
            if (n <= 0) return error.SocketError;
            off += @intCast(n);
        }
        return;
    }
    var off: usize = 0;
    while (off < bytes.len) off += try stream.write(bytes[off..]);
}

pub fn sockClose(stream: *std.net.Stream) void {
    if (builtin.os.tag == .windows) {
        _ = ws2.closesocket(stream.handle);
        return;
    }
    stream.close();
}

pub const Req = struct {
    method: []u8,
    path: []u8,
    body: []u8,
    head: []u8, // raw request line + headers (for header assertions)

    pub fn deinit(self: *Req, alloc: std.mem.Allocator) void {
        alloc.free(self.method);
        alloc.free(self.path);
        alloc.free(self.body);
        alloc.free(self.head);
    }
};

/// Read one HTTP/1.1 request (request line, headers, content-length body).
pub fn readRequest(alloc: std.mem.Allocator, stream: *std.net.Stream) !Req {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(alloc);
    var tmp: [4096]u8 = undefined;
    while (std.mem.indexOf(u8, buf.items, "\r\n\r\n") == null) {
        const n = try sockRead(stream, &tmp);
        if (n == 0) return error.Closed;
        try buf.appendSlice(alloc, tmp[0..n]);
    }
    const he = std.mem.indexOf(u8, buf.items, "\r\n\r\n").?;
    const head = buf.items[0..he];

    const sp1 = std.mem.indexOf(u8, head, " ") orelse return error.Malformed;
    const sp2 = std.mem.indexOfPos(u8, head, sp1 + 1, " ") orelse return error.Malformed;

    var content_length: usize = 0;
    var it = std.mem.splitSequence(u8, head, "\r\n");
    _ = it.next();
    while (it.next()) |line| {
        const colon = std.mem.indexOf(u8, line, ":") orelse continue;
        if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, line[0..colon], " "), "content-length")) {
            content_length = std.fmt.parseInt(usize, std.mem.trim(u8, line[colon + 1 ..], " "), 10) catch 0;
        }
    }

    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(alloc); // Req.body is a separate dupe
    try body.appendSlice(alloc, buf.items[he + 4 ..]);
    while (body.items.len < content_length) {
        const n = try sockRead(stream, &tmp);
        if (n == 0) return error.Closed;
        try body.appendSlice(alloc, tmp[0..n]);
    }

    return .{
        .method = try alloc.dupe(u8, head[0..sp1]),
        .path = try alloc.dupe(u8, head[sp1 + 1 .. sp2]),
        .body = try alloc.dupe(u8, body.items[0..@min(body.items.len, content_length)]),
        .head = try alloc.dupe(u8, head),
    };
}

/// Drain a connection until the peer closes.
pub fn drainUntilClose(stream: *std.net.Stream) void {
    var tmp: [4096]u8 = undefined;
    while (true) {
        const n = sockRead(stream, &tmp) catch return;
        if (n == 0) return;
    }
}

pub const Mock = struct {
    alloc: std.mem.Allocator,
    server: std.net.Server,
    thread: ?std.Thread = null,
    /// Set by handlers for test assertions (written before the event the
    /// test waits on, so no extra synchronization is needed).
    last_event_id_seen: bool = false,
    /// Sampling test: the client's answer POST arrived while stream 1 open.
    answer_seen: bool = false,
    /// Generic payload counter (e.g. bytes of a TLS ClientHello seen
    /// inside a proxy tunnel).
    extra: usize = 0,

    pub fn start(alloc: std.mem.Allocator) !Mock {
        const addr = try std.net.Address.parseIp("127.0.0.1", 0);
        return .{ .alloc = alloc, .server = try addr.listen(.{}) };
    }

    pub fn port(self: *const Mock) u16 {
        return self.server.listen_address.getPort();
    }

    pub fn spawn(self: *Mock, comptime handler: fn (*Mock) void) !void {
        self.thread = try std.Thread.spawn(.{}, handler, .{self});
    }

    pub fn join(self: *Mock) void {
        if (self.thread) |t| t.join();
        self.server.deinit();
    }
};

pub fn sseResponseHead() []const u8 {
    return "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\n\r\n";
}
