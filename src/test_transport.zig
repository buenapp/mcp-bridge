// Integration tests: legacy HTTP+SSE transport (2024-11-05), http-first
// auto-fallback, and the Streamable HTTP standalone GET push stream —
// against in-process mock servers (plain HTTP on 127.0.0.1).

const std = @import("std");
const main_mod = @import("main.zig");
const http = @import("http.zig");
const mcp = @import("mcp.zig");

const Bridge = main_mod.Bridge;
const Config = main_mod.Config;
const Out = main_mod.Out;

// ------------------------------------------------------- collector sink ----

/// Captures bridge output (an Out sink) for assertions.
const Collector = struct {
    alloc: std.mem.Allocator,
    /// Handed to the Out sink; held while writeFn runs.
    out_mutex: std.Thread.Mutex = .{},
    /// Protects buf for waitFor (lock order: out_mutex -> mutex).
    mutex: std.Thread.Mutex = .{},
    cond: std.Thread.Condition = .{},
    buf: std.ArrayList(u8) = .empty,

    fn writeFn(ctx: *anyopaque, bytes: []const u8) void {
        const self: *Collector = @ptrCast(@alignCast(ctx));
        self.mutex.lock();
        defer self.mutex.unlock();
        self.buf.appendSlice(self.alloc, bytes) catch {};
        self.cond.broadcast();
    }

    fn out(self: *Collector) Out {
        return .{ .ctx = self, .mutex = &self.out_mutex, .writeFn = writeFn };
    }

    fn deinit(self: *Collector) void {
        self.buf.deinit(self.alloc);
    }

    /// Wait until the captured output contains `needle` (or timeout).
    fn waitFor(self: *Collector, needle: []const u8, timeout_ns: u64) bool {
        var waited: u64 = 0;
        const step: u64 = 10 * std.time.ns_per_ms;
        self.mutex.lock();
        defer self.mutex.unlock();
        while (std.mem.indexOf(u8, self.buf.items, needle) == null) {
            if (waited >= timeout_ns) return false;
            _ = self.cond.timedWait(&self.mutex, step) catch {};
            waited += step;
        }
        return true;
    }
};

// ------------------------------------------------------------ mock HTTP ----

const Req = struct {
    method: []u8,
    path: []u8,
    body: []u8,
    head: []u8, // raw request line + headers (for header assertions)

    fn deinit(self: *Req, alloc: std.mem.Allocator) void {
        alloc.free(self.method);
        alloc.free(self.path);
        alloc.free(self.body);
        alloc.free(self.head);
    }
};

/// Read one HTTP/1.1 request (request line, headers, content-length body).
fn readRequest(alloc: std.mem.Allocator, stream: *std.net.Stream) !Req {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(alloc);
    var tmp: [4096]u8 = undefined;
    while (std.mem.indexOf(u8, buf.items, "\r\n\r\n") == null) {
        const n = try stream.read(&tmp);
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
        const n = try stream.read(&tmp);
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

fn writeAll(stream: *std.net.Stream, bytes: []const u8) !void {
    var off: usize = 0;
    while (off < bytes.len) off += try stream.write(bytes[off..]);
}

/// Drain a connection until the peer closes (pump teardown).
fn drainUntilClose(stream: *std.net.Stream) void {
    var tmp: [4096]u8 = undefined;
    while (true) {
        const n = stream.read(&tmp) catch return;
        if (n == 0) return;
    }
}

const Mock = struct {
    alloc: std.mem.Allocator,
    server: std.net.Server,
    thread: ?std.Thread = null,
    /// Set by handlers for test assertions (written before the event the
    /// test waits on, so no extra synchronization is needed).
    last_event_id_seen: bool = false,

    fn start(alloc: std.mem.Allocator) !Mock {
        const addr = try std.net.Address.parseIp("127.0.0.1", 0);
        return .{ .alloc = alloc, .server = try addr.listen(.{}) };
    }

    fn port(self: *const Mock) u16 {
        return self.server.listen_address.getPort();
    }

    fn spawn(self: *Mock, comptime handler: fn (*Mock) void) !void {
        self.thread = try std.Thread.spawn(.{}, handler, .{self});
    }

    fn join(self: *Mock) void {
        if (self.thread) |t| t.join();
        self.server.deinit();
    }
};

fn sseResponseHead() []const u8 {
    return "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\n\r\n";
}

// --------------------------------------- mock: legacy HTTP+SSE server ----

/// GET /sse -> event stream with endpoint event; POST /messages -> 202,
/// then a server-pushed notification and the JSON-RPC response on the
/// stream. Exits when the event stream connection closes.
fn mockLegacyMain(mock: *Mock) void {
    const alloc = mock.alloc;

    // 1: the event stream
    var c_get = mock.server.accept() catch return;
    defer c_get.stream.close();
    var req = readRequest(alloc, &c_get.stream) catch return;
    req.deinit(alloc);
    writeAll(&c_get.stream, sseResponseHead()) catch return;
    writeAll(&c_get.stream, "event: endpoint\ndata: /messages?session_id=test-session\n\n") catch return;

    // 2: one POST to the session endpoint
    var c_post = mock.server.accept() catch return;
    defer c_post.stream.close();
    var post = readRequest(alloc, &c_post.stream) catch return;
    defer post.deinit(alloc);
    writeAll(&c_post.stream, "HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n") catch return;

    // Server-pushed notification first, then the response to id 1.
    writeAll(&c_get.stream, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/test\"}\n\n") catch return;
    writeAll(&c_get.stream, "event: message\nid: ev-1\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\n\n") catch return;

    drainUntilClose(&c_get.stream);
}

test "legacy SSE: endpoint discovery, async response, server push" {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{ .thread_safe = true }){};
    // Registered first, runs last: fail the test on leaks.
    defer if (gpa_state.deinit() == .leak) @panic("memory leak");
    const alloc = gpa_state.allocator();

    var mock = try Mock.start(alloc);
    try mock.spawn(mockLegacyMain);

    var collector = Collector{ .alloc = alloc };
    defer collector.deinit();

    const url = try std.fmt.allocPrint(alloc, "http://127.0.0.1:{d}/sse", .{mock.port()});
    defer alloc.free(url);
    var cfg = Config{ .target = try http.parseUrl(url), .url = url, .transport = .sse_only };
    var bridge = Bridge{
        .alloc = alloc,
        .cfg = &cfg,
        .verifier = null,
        .out = collector.out(),
        .mode = .legacy,
        .probed = true,
    };

    const init = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2024-11-05\"}}";
    try std.testing.expect((try bridge.dispatchLine(init)) == null); // async

    // Response correlated by id arrives on the event stream.
    try std.testing.expect(collector.waitFor("\"id\":1,\"result\":{\"ok\":true}", 5 * std.time.ns_per_s));
    // Server-pushed notification was forwarded too.
    try std.testing.expect(collector.waitFor("notifications/test", 5 * std.time.ns_per_s));
    // The request id drained the pending set (no dangling waiter).
    try std.testing.expect(bridge.leg.?.pending.count() == 0);
    // The endpoint event was captured.
    try std.testing.expect(bridge.leg.?.ready);
    try std.testing.expectEqualStrings("/messages?session_id=test-session", bridge.leg.?.endpoint.?.path);

    bridge.deinit();
    mock.join();
}

// ------------------------------ mock: http-first fallback (405 -> SSE) ----

fn mockFallbackMain(mock: *Mock) void {
    const alloc = mock.alloc;

    // 1: POST /mcp -> 405 (no Streamable HTTP here)
    var c1 = mock.server.accept() catch return;
    var req1 = readRequest(alloc, &c1.stream) catch return;
    req1.deinit(alloc);
    writeAll(&c1.stream, "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n") catch return;
    c1.stream.close();

    // 2: GET /mcp -> legacy event stream
    var c_get = mock.server.accept() catch return;
    defer c_get.stream.close();
    var req2 = readRequest(alloc, &c_get.stream) catch return;
    req2.deinit(alloc);
    writeAll(&c_get.stream, sseResponseHead()) catch return;
    writeAll(&c_get.stream, "event: endpoint\ndata: /messages?session_id=fb\n\n") catch return;

    // 3: POST /messages -> 202, response on the stream
    var c_post = mock.server.accept() catch return;
    defer c_post.stream.close();
    var post = readRequest(alloc, &c_post.stream) catch return;
    defer post.deinit(alloc);
    writeAll(&c_post.stream, "HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n") catch return;
    writeAll(&c_get.stream, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"via\":\"sse\"}}\n\n") catch return;

    drainUntilClose(&c_get.stream);
}

test "http-first: 405 on POST falls back to legacy SSE" {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{ .thread_safe = true }){};
    // Registered first, runs last: fail the test on leaks.
    defer if (gpa_state.deinit() == .leak) @panic("memory leak");
    const alloc = gpa_state.allocator();

    var mock = try Mock.start(alloc);
    try mock.spawn(mockFallbackMain);

    var collector = Collector{ .alloc = alloc };
    defer collector.deinit();

    const url = try std.fmt.allocPrint(alloc, "http://127.0.0.1:{d}/mcp", .{mock.port()});
    defer alloc.free(url);
    var cfg = Config{ .target = try http.parseUrl(url), .url = url, .transport = .http_first };
    var bridge = Bridge{
        .alloc = alloc,
        .cfg = &cfg,
        .verifier = null,
        .out = collector.out(),
    };

    const init = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}";
    try std.testing.expect((try bridge.dispatchLine(init)) == null); // fell back: async
    try std.testing.expect(bridge.mode == .legacy);
    try std.testing.expect(collector.waitFor("\"result\":{\"via\":\"sse\"}", 5 * std.time.ns_per_s));

    bridge.deinit();
    mock.join();
}

// --------------------------- mock: streamable + standalone GET stream ----

fn mockPushMain(mock: *Mock) void {
    const alloc = mock.alloc;

    // 1: POST /mcp (initialize) -> 200 JSON with a session id
    var c1 = mock.server.accept() catch return;
    var req1 = readRequest(alloc, &c1.stream) catch return;
    defer req1.deinit(alloc);
    const body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2025-03-26\",\"serverInfo\":{\"name\":\"mock\"}}}";
    var head_buf: [256]u8 = undefined;
    const resp = std.fmt.bufPrint(&head_buf, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nMCP-Session-Id: sess-123\r\n\r\n{s}", .{ body.len, body }) catch return;
    writeAll(&c1.stream, resp) catch return;
    // Leave c1 open: the bridge may reuse it. It closes at deinit.

    // 2: GET /mcp -> standalone event stream; push a notification
    var c_get = mock.server.accept() catch return;
    defer c_get.stream.close();
    var req2 = readRequest(alloc, &c_get.stream) catch return;
    req2.deinit(alloc);
    writeAll(&c_get.stream, sseResponseHead()) catch return;
    writeAll(&c_get.stream, "event: message\nid: push-1\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}\n\n") catch return;

    drainUntilClose(&c_get.stream);
    c1.stream.close();
}

test "streamable: standalone GET stream delivers server-initiated messages" {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{ .thread_safe = true }){};
    // Registered first, runs last: fail the test on leaks.
    defer if (gpa_state.deinit() == .leak) @panic("memory leak");
    const alloc = gpa_state.allocator();

    var mock = try Mock.start(alloc);
    try mock.spawn(mockPushMain);

    var collector = Collector{ .alloc = alloc };
    defer collector.deinit();

    const url = try std.fmt.allocPrint(alloc, "http://127.0.0.1:{d}/mcp", .{mock.port()});
    defer alloc.free(url);
    var cfg = Config{ .target = try http.parseUrl(url), .url = url, .transport = .http_only };
    var bridge = Bridge{
        .alloc = alloc,
        .cfg = &cfg,
        .verifier = null,
        .out = collector.out(),
    };

    const init = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}";
    var resp = (try bridge.dispatchLine(init)).?;
    defer resp.deinit(alloc);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "serverInfo") != null);

    // Mimic the main loop: adopt the session id, open the GET stream.
    try std.testing.expect(resp.mcp_session_id != null);
    bridge.session_id = try alloc.dupe(u8, resp.mcp_session_id.?);
    bridge.maybeStartPush();

    try std.testing.expect(collector.waitFor("notifications/tools/list_changed", 5 * std.time.ns_per_s));

    bridge.deinit();
    mock.join();
}

// --------------------------------------- mock: SSE stream drop + resume ----

/// First GET stream ends abruptly after one message; the reconnect must
/// carry Last-Event-ID and re-deliver the endpoint event.
fn mockResumeMain(mock: *Mock) void {
    const alloc = mock.alloc;

    // 1: GET /sse -> stream, endpoint + one message, then close
    var c1 = mock.server.accept() catch return;
    var req1 = readRequest(alloc, &c1.stream) catch return;
    req1.deinit(alloc);
    writeAll(&c1.stream, sseResponseHead()) catch return;
    writeAll(&c1.stream, "event: endpoint\ndata: /messages?session_id=r1\n\n") catch return;
    writeAll(&c1.stream, "event: message\nid: 100\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/before-drop\"}\n\n") catch return;
    c1.stream.close();

    // 2: reconnect — must carry Last-Event-ID: 100
    var c2 = mock.server.accept() catch return;
    defer c2.stream.close();
    var req2 = readRequest(alloc, &c2.stream) catch return;
    mock.last_event_id_seen = std.ascii.indexOfIgnoreCase(req2.head, "last-event-id: 100") != null;
    req2.deinit(alloc);
    writeAll(&c2.stream, sseResponseHead()) catch return;
    writeAll(&c2.stream, "event: endpoint\ndata: /messages?session_id=r2\n\n") catch return;

    // 3: POST to the NEW session endpoint -> 202 + response on stream 2
    var c_post = mock.server.accept() catch return;
    defer c_post.stream.close();
    var post = readRequest(alloc, &c_post.stream) catch return;
    defer post.deinit(alloc);
    writeAll(&c_post.stream, "HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n") catch return;
    writeAll(&c2.stream, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"resumed\":true}}\n\n") catch return;

    drainUntilClose(&c2.stream);
}

test "legacy SSE: reconnect after stream drop resumes with Last-Event-ID" {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{ .thread_safe = true }){};
    // Registered first, runs last: fail the test on leaks.
    defer if (gpa_state.deinit() == .leak) @panic("memory leak");
    const alloc = gpa_state.allocator();

    var mock = try Mock.start(alloc);
    try mock.spawn(mockResumeMain);

    var collector = Collector{ .alloc = alloc };
    defer collector.deinit();

    const url = try std.fmt.allocPrint(alloc, "http://127.0.0.1:{d}/sse", .{mock.port()});
    defer alloc.free(url);
    var cfg = Config{ .target = try http.parseUrl(url), .url = url, .transport = .sse_only, .verbose = true };
    var bridge = Bridge{
        .alloc = alloc,
        .cfg = &cfg,
        .verifier = null,
        .out = collector.out(),
        .mode = .legacy,
        .probed = true,
    };

    // First stream: endpoint + one pushed message, then the mock drops it.
    // (Production opens the stream lazily on the first stdin line; the
    // test starts it explicitly.)
    try bridge.startLegacy();
    try std.testing.expect(collector.waitFor("notifications/before-drop", 5 * std.time.ns_per_s));
    // Wait until the pump noticed the drop.
    {
        var waited: u64 = 0;
        while (true) {
            bridge.leg.?.mutex.lock();
            const dead = bridge.leg.?.dead;
            bridge.leg.?.mutex.unlock();
            if (dead) break;
            if (waited > 5 * std.time.ns_per_s) return error.PumpDidNotNoticeDrop;
            std.Thread.sleep(10 * std.time.ns_per_ms);
            waited += 10 * std.time.ns_per_ms;
        }
    }
    // The message id was remembered for resumability.
    try std.testing.expectEqualStrings("100", bridge.leg.?.last_event_id.?);

    // Next send reconnects (the mock records whether Last-Event-ID came
    // through) and re-discovers the endpoint from the new stream.
    const call = "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{}}";
    try std.testing.expect((try bridge.dispatchLine(call)) == null);
    try std.testing.expect(collector.waitFor("\"resumed\":true", 5 * std.time.ns_per_s));
    try std.testing.expectEqualStrings("/messages?session_id=r2", bridge.leg.?.endpoint.?.path);
    try std.testing.expect(mock.last_event_id_seen);

    bridge.deinit();
    mock.join();
}
