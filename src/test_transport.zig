// Integration tests on the event core (issue #7): legacy HTTP+SSE
// transport (2024-11-05), http-first auto-fallback, the Streamable HTTP
// standalone GET push stream, and Last-Event-ID resume — against
// in-process mock servers (plain HTTP on 127.0.0.1; the server side runs
// on a thread and may block, the bridge under test never does).
//
// Tests drive the loop explicitly: injectLine() feeds stdin lines and
// waitFor()/stepUntil() pump the event port.

const std = @import("std");
const main_mod = @import("main.zig");
const http = @import("http.zig");
const mcp = @import("mcp.zig");

const Bridge = main_mod.Bridge;
const Config = main_mod.Config;
const Out = main_mod.Out;

// ------------------------------------------------------- collector sink ----

/// Captures bridge output (an Out sink) for assertions. Single-threaded:
/// the bridge's loop runs on the test thread via step().
const Collector = struct {
    alloc: std.mem.Allocator,
    buf: std.ArrayList(u8) = .empty,

    fn writeFn(ctx: *anyopaque, bytes: []const u8) void {
        const self: *Collector = @ptrCast(@alignCast(ctx));
        self.buf.appendSlice(self.alloc, bytes) catch {};
    }

    fn out(self: *Collector) Out {
        return .{ .ctx = self, .writeFn = writeFn };
    }

    fn deinit(self: *Collector) void {
        self.buf.deinit(self.alloc);
    }

    fn contains(self: *Collector, needle: []const u8) bool {
        return std.mem.indexOf(u8, self.buf.items, needle) != null;
    }
};

/// Step the loop until the collector contains `needle` (bounded ~5s).
fn waitFor(bridge: *Bridge, collector: *Collector, needle: []const u8) bool {
    var rounds: usize = 0;
    while (!collector.contains(needle)) {
        if (rounds > 500) return false;
        bridge.step(10) catch return false;
        rounds += 1;
    }
    return true;
}

/// Step the loop until `cond` holds (bounded ~5s).
fn stepUntil(bridge: *Bridge, cond: *const fn (b: *Bridge) bool) bool {
    var rounds: usize = 0;
    while (!cond(bridge)) {
        if (rounds > 500) return false;
        bridge.step(10) catch return false;
        rounds += 1;
    }
    return true;
}

// ------------------------------------------------------------ mock HTTP ----

const testkit = @import("testkit.zig");
const Req = testkit.Req;
const readRequest = testkit.readRequest;
const writeAll = testkit.sockWriteAll;
const sockRead = testkit.sockRead;
const drainUntilClose = testkit.drainUntilClose;
const Mock = testkit.Mock;
const sseResponseHead = testkit.sseResponseHead;
const sockClose = testkit.sockClose;

// --------------------------------------- mock: legacy HTTP+SSE server ----

/// GET /sse -> event stream with endpoint event; POST /messages -> 202,
/// then a server-pushed notification and the JSON-RPC response on the
/// stream. Exits when the event stream connection closes.
fn mockLegacyMain(mock: *Mock) void {
    const alloc = mock.alloc;

    // 1: the event stream
    var c_get = mock.server.accept() catch return;
    defer sockClose(&c_get.stream);
    var req = readRequest(alloc, &c_get.stream) catch return;
    req.deinit(alloc);
    writeAll(&c_get.stream, sseResponseHead()) catch return;
    writeAll(&c_get.stream, "event: endpoint\ndata: /messages?session_id=test-session\n\n") catch return;

    // 2: one POST to the session endpoint
    var c_post = mock.server.accept() catch return;
    defer sockClose(&c_post.stream);
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
    var bridge = try Bridge.init(alloc, &cfg, collector.out(), null);
    bridge.mode = .legacy;
    bridge.probed = true;

    const init = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2024-11-05\"}}";
    bridge.injectLine(init);

    // Response correlated by id arrives on the event stream.
    try std.testing.expect(waitFor(&bridge, &collector, "\"id\":1,\"result\":{\"ok\":true}"));
    // Server-pushed notification was forwarded too.
    try std.testing.expect(waitFor(&bridge, &collector, "notifications/test"));
    // The request id drained the pending set (no dangling waiter).
    try std.testing.expect(bridge.leg_pending.count() == 0);
    // The endpoint event was captured.
    try std.testing.expect(bridge.leg_ready);
    try std.testing.expectEqualStrings("/messages?session_id=test-session", bridge.leg_endpoint.?.path);

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
    sockClose(&c1.stream);

    // 2: GET /mcp -> legacy event stream
    var c_get = mock.server.accept() catch return;
    defer sockClose(&c_get.stream);
    var req2 = readRequest(alloc, &c_get.stream) catch return;
    req2.deinit(alloc);
    writeAll(&c_get.stream, sseResponseHead()) catch return;
    writeAll(&c_get.stream, "event: endpoint\ndata: /messages?session_id=fb\n\n") catch return;

    // 3: POST /messages -> 202, response on the stream
    var c_post = mock.server.accept() catch return;
    defer sockClose(&c_post.stream);
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
    var bridge = try Bridge.init(alloc, &cfg, collector.out(), null);

    const init = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}";
    bridge.injectLine(init);

    try std.testing.expect(waitFor(&bridge, &collector, "\"result\":{\"via\":\"sse\"}"));
    try std.testing.expect(bridge.mode == .legacy);

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
    defer sockClose(&c_get.stream);
    var req2 = readRequest(alloc, &c_get.stream) catch return;
    req2.deinit(alloc);
    writeAll(&c_get.stream, sseResponseHead()) catch return;
    writeAll(&c_get.stream, "event: message\nid: push-1\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}\n\n") catch return;

    drainUntilClose(&c_get.stream);
    sockClose(&c1.stream);
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
    var bridge = try Bridge.init(alloc, &cfg, collector.out(), null);

    const init = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}";
    bridge.injectLine(init);

    // The initialize response itself (session id captured internally,
    // push stream opened automatically).
    try std.testing.expect(waitFor(&bridge, &collector, "serverInfo"));
    try std.testing.expect(bridge.session_id != null);
    try std.testing.expectEqualStrings("sess-123", bridge.session_id.?);
    // Server-initiated notification arrives on the push stream.
    try std.testing.expect(waitFor(&bridge, &collector, "notifications/tools/list_changed"));

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
    sockClose(&c1.stream);

    // 2: reconnect — must carry Last-Event-ID: 100
    var c2 = mock.server.accept() catch return;
    defer sockClose(&c2.stream);
    var req2 = readRequest(alloc, &c2.stream) catch return;
    mock.last_event_id_seen = std.ascii.indexOfIgnoreCase(req2.head, "last-event-id: 100") != null;
    req2.deinit(alloc);
    writeAll(&c2.stream, sseResponseHead()) catch return;
    writeAll(&c2.stream, "event: endpoint\ndata: /messages?session_id=r2\n\n") catch return;

    // 3: POST to the NEW session endpoint -> 202 + response on stream 2
    var c_post = mock.server.accept() catch return;
    defer sockClose(&c_post.stream);
    var post = readRequest(alloc, &c_post.stream) catch return;
    defer post.deinit(alloc);
    writeAll(&c_post.stream, "HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n") catch return;
    writeAll(&c2.stream, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"resumed\":true}}\n\n") catch return;

    drainUntilClose(&c2.stream);
}

test "legacy SSE: reconnect carries Last-Event-ID after a dropped stream" {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{ .thread_safe = true }){};
    defer if (gpa_state.deinit() == .leak) @panic("memory leak");
    const alloc = gpa_state.allocator();

    var mock = try Mock.start(alloc);
    try mock.spawn(mockResumeMain);

    var collector = Collector{ .alloc = alloc };
    defer collector.deinit();

    const url = try std.fmt.allocPrint(alloc, "http://127.0.0.1:{d}/sse", .{mock.port()});
    defer alloc.free(url);
    var cfg = Config{ .target = try http.parseUrl(url), .url = url, .transport = .sse_only };
    var bridge = try Bridge.init(alloc, &cfg, collector.out(), null);
    bridge.mode = .legacy;
    bridge.probed = true;

    // First stream: endpoint + one pushed message, then the mock drops it.
    // (Production opens the stream lazily on the first stdin line; the
    // test starts it explicitly.)
    bridge.startLegacyTransport(false);
    try std.testing.expect(waitFor(&bridge, &collector, "notifications/before-drop"));

    // Wait for the bridge to register the drop before sending the next
    // line (the reconnect must happen via the dead-stream path).
    const deadCond = struct {
        fn f(b: *Bridge) bool {
            return b.leg_dead;
        }
    }.f;
    try std.testing.expect(stepUntil(&bridge, &deadCond));
    // The message id was remembered for resumability.
    try std.testing.expectEqualStrings("100", bridge.leg_last_event_id.?);

    // Next send reconnects (the mock records whether Last-Event-ID came
    // through) and re-discovers the endpoint from the new stream.
    const call = "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{}}";
    bridge.injectLine(call);

    try std.testing.expect(waitFor(&bridge, &collector, "\"resumed\":true"));
    try std.testing.expectEqualStrings("/messages?session_id=r2", bridge.leg_endpoint.?.path);
    try std.testing.expect(mock.last_event_id_seen);

    bridge.deinit();
    mock.join();
}

// ----------------------- mock: sampling inside a POST's own SSE stream ----

/// The issue #7 deadlock case: the server answers initialize with an SSE
/// stream that FIRST carries a server->client sampling request and stays
/// open; only after the client's answer arrives (on a separate POST) does
/// the initialize response come. A concurrent tools/list runs in between.
/// The serial blocking core deadlocked here forever (the main thread was
/// stuck reading the initialize stream).
fn mockSamplingMain(mock: *Mock) void {
    const alloc = mock.alloc;

    // 1: POST /mcp (initialize, id 1) -> SSE stream with a sampling request
    var c1 = mock.server.accept() catch return;
    defer sockClose(&c1.stream);
    var req1 = readRequest(alloc, &c1.stream) catch return;
    req1.deinit(alloc);
    writeAll(&c1.stream, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n") catch return;
    writeAll(&c1.stream, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":\"srv-1\",\"method\":\"sampling/createMessage\",\"params\":{\"messages\":[]}}\n\n") catch return;
    // The stream STAYS OPEN while the client works on the answer.

    // 2: a concurrent client request (tools/list, id 2) on its own conn.
    // Connection: close — the conn must NOT become the bridge's idle
    // keep-alive, so the sampling answer below deterministically gets a
    // fresh connection (accept #3).
    var c2 = mock.server.accept() catch return;
    defer sockClose(&c2.stream);
    var req2 = readRequest(alloc, &c2.stream) catch return;
    req2.deinit(alloc);
    const body2 = "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[]}}";
    var hb2: [256]u8 = undefined;
    const resp2 = std.fmt.bufPrint(&hb2, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{ body2.len, body2 }) catch return;
    writeAll(&c2.stream, resp2) catch return;

    // 3: the client's sampling answer (id "srv-1") -> 202 Accepted
    var c3 = mock.server.accept() catch return;
    defer sockClose(&c3.stream);
    var req3 = readRequest(alloc, &c3.stream) catch return;
    mock.answer_seen = std.mem.indexOf(u8, req3.body, "\"srv-1\"") != null;
    req3.deinit(alloc);
    writeAll(&c3.stream, "HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n") catch return;

    // 4: only now the initialize response on the (still open) stream 1
    writeAll(&c1.stream, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2025-03-26\",\"serverInfo\":{\"name\":\"mock\"}}}\n\n") catch return;

    drainUntilClose(&c1.stream);
    drainUntilClose(&c2.stream);
}

test "streamable: server request inside a POST SSE stream is answered (no deadlock)" {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{ .thread_safe = true }){};
    defer if (gpa_state.deinit() == .leak) @panic("memory leak");
    const alloc = gpa_state.allocator();

    var mock = try Mock.start(alloc);
    try mock.spawn(mockSamplingMain);

    var collector = Collector{ .alloc = alloc };
    defer collector.deinit();

    const url = try std.fmt.allocPrint(alloc, "http://127.0.0.1:{d}/mcp", .{mock.port()});
    defer alloc.free(url);
    var cfg = Config{ .target = try http.parseUrl(url), .url = url, .transport = .http_only };
    var bridge = try Bridge.init(alloc, &cfg, collector.out(), null);

    const init = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}";
    bridge.injectLine(init);

    // The sampling request is forwarded while the initialize response is
    // still pending on the same stream.
    try std.testing.expect(waitFor(&bridge, &collector, "sampling/createMessage"));
    try std.testing.expect(!collector.contains("\"id\":1,\"result\""));

    // A concurrent request round-trips on its own connection while stream
    // 1 is still in flight.
    const tools = "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{}}";
    bridge.injectLine(tools);
    try std.testing.expect(waitFor(&bridge, &collector, "\"id\":2,\"result\":{\"tools\":[]}"));

    // The client answers the sampling request; the bridge POSTs it on a
    // third connection. Only then does the server release initialize.
    const answer = "{\"jsonrpc\":\"2.0\",\"id\":\"srv-1\",\"result\":{\"role\":\"assistant\",\"content\":{\"type\":\"text\",\"text\":\"42\"}}}";
    bridge.injectLine(answer);
    try std.testing.expect(waitFor(&bridge, &collector, "\"id\":1,\"result\":{\"protocolVersion\":\"2025-03-26\""));

    // The answer provably arrived while stream 1 was open (mock ordering).
    try std.testing.expect(mock.answer_seen);

    bridge.deinit();
    mock.join();
}

// --------------------------- mock: proxy (CONNECT tunnel / absolute-form) ----

/// Proxy mock: expect a CONNECT with Proxy-Authorization, answer 200, then
/// HOLD the tunnel open and record the TLS ClientHello bytes the bridge
/// sends through it (proof the tunnel carried the origin TLS session).
fn mockProxyTunnelMain(mock: *Mock) void {
    const alloc = mock.alloc;
    var c1 = mock.server.accept() catch return;
    // NOTE: c1 is deliberately left OPEN at return (no sockClose): the
    // bridge holds the tunnel mid-handshake until ITS deinit; an early
    // close here EOFs the handshake and the tls layer error-logs, which
    // fails the test run. The fd dies with the process.
    var req = readRequest(alloc, &c1.stream) catch return;
    defer req.deinit(alloc);
    mock.answer_seen = std.mem.indexOf(u8, req.head, "CONNECT origin.example:443 HTTP/1.1") != null and
        std.mem.indexOf(u8, req.head, "Proxy-Authorization: Basic dTpw") != null;
    writeAll(&c1.stream, "HTTP/1.1 200 Connection established\r\n\r\n") catch return;
    // The TLS ClientHello arrives through the tunnel; then our job is done.
    var buf: [512]u8 = undefined;
    const n = sockRead(&c1.stream, &buf) catch 0;
    mock.extra = n;
}

test "proxy: https target tunnels via CONNECT with proxy auth" {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{ .thread_safe = true }){};
    defer if (gpa_state.deinit() == .leak) @panic("memory leak");
    const alloc = gpa_state.allocator();

    var mock = try Mock.start(alloc);
    try mock.spawn(mockProxyTunnelMain);
    defer mock.join(); // after bridge.deinit (LIFO); the mock returns once
    // the ClientHello lands, so join never blocks

    var collector = Collector{ .alloc = alloc };
    defer collector.deinit();

    const proxy_mod = @import("proxy.zig");
    proxy_mod.enabled = true;
    defer proxy_mod.enabled = false;
    const target = http.Target{ .secure = true, .host = "origin.example", .port = 443, .path = "/mcp" };
    proxy_mod.setForTest(target, .{ .host = "127.0.0.1", .port = mock.port(), .auth = "Basic dTpw" });
    defer proxy_mod.setForTest(target, null);

    var cfg = Config{ .target = target, .url = "https://origin.example/mcp", .transport = .http_only };
    var bridge = try Bridge.init(alloc, &cfg, collector.out(), null);
    defer bridge.deinit(); // teardown even when an expect fails

    bridge.injectLine("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}");
    // The ClientHello (through the tunnel) lands in the mock.
    const helloCond = struct {
        fn f(m: *Mock) bool {
            return m.extra > 0;
        }
    }.f;
    var rounds: usize = 0;
    while (!helloCond(&mock) and rounds < 500) : (rounds += 1) bridge.step(10) catch break;
    try std.testing.expect(mock.extra > 0);
    try std.testing.expect(mock.answer_seen); // CONNECT line + auth header
}

/// Proxy mock for a PLAIN http target: the request line must be
/// absolute-form; answer the JSON response directly (no tunnel).
fn mockProxyAbsMain(mock: *Mock) void {
    const alloc = mock.alloc;
    var c1 = mock.server.accept() catch return;
    defer sockClose(&c1.stream);
    var req = readRequest(alloc, &c1.stream) catch return;
    defer req.deinit(alloc);
    mock.answer_seen = std.mem.indexOf(u8, req.head, "POST http://127.0.0.1:1/mcp HTTP/1.1") != null;
    const body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"via\":\"proxy\"}}";
    var hb: [256]u8 = undefined;
    const resp = std.fmt.bufPrint(&hb, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{ body.len, body }) catch return;
    writeAll(&c1.stream, resp) catch return;
}

test "proxy: plain http target uses absolute-form through the proxy" {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{ .thread_safe = true }){};
    defer if (gpa_state.deinit() == .leak) @panic("memory leak");
    const alloc = gpa_state.allocator();

    var mock = try Mock.start(alloc);
    try mock.spawn(mockProxyAbsMain);

    var collector = Collector{ .alloc = alloc };
    defer collector.deinit();

    const proxy_mod = @import("proxy.zig");
    proxy_mod.enabled = true;
    defer proxy_mod.enabled = false;
    const target = http.Target{ .secure = false, .host = "127.0.0.1", .port = 1, .path = "/mcp" };
    proxy_mod.setForTest(target, .{ .host = "127.0.0.1", .port = mock.port() });
    defer proxy_mod.setForTest(target, null);

    var cfg = Config{ .target = target, .url = "http://127.0.0.1:1/mcp", .transport = .http_only };
    var bridge = try Bridge.init(alloc, &cfg, collector.out(), null);

    bridge.injectLine("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}");
    try std.testing.expect(waitFor(&bridge, &collector, "\"via\":\"proxy\""));
    try std.testing.expect(mock.answer_seen); // absolute-form request line

    bridge.deinit();
    mock.join();
}

/// Streamable mock with one POST per conn (Connection: close for a
/// deterministic sequence): initialize, a tools/call for the KEPT tool,
/// then tools/list carrying three tools (one ignored).
fn mockIgnoreToolMain(mock: *Mock) void {
    const alloc = mock.alloc;

    // 1: POST initialize
    var c1 = mock.server.accept() catch return;
    defer sockClose(&c1.stream);
    var req1 = readRequest(alloc, &c1.stream) catch return;
    req1.deinit(alloc);
    const body1 = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2025-03-26\",\"serverInfo\":{\"name\":\"mock\"}}}";
    var hb1: [384]u8 = undefined;
    const resp1 = std.fmt.bufPrint(&hb1, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{ body1.len, body1 }) catch return;
    writeAll(&c1.stream, resp1) catch return;

    // 2: POST tools/call (kept tool) — proves it was forwarded.
    var c2 = mock.server.accept() catch return;
    defer sockClose(&c2.stream);
    var req2 = readRequest(alloc, &c2.stream) catch return;
    mock.answer_seen = std.mem.indexOf(u8, req2.body, "list_issues") != null;
    req2.deinit(alloc);
    const body2 = "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"ok\"}]}}";
    var hb2: [384]u8 = undefined;
    const resp2 = std.fmt.bufPrint(&hb2, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{ body2.len, body2 }) catch return;
    writeAll(&c2.stream, resp2) catch return;

    // 3: POST tools/list → three tools, one ignored by the pattern.
    var c3 = mock.server.accept() catch return;
    defer sockClose(&c3.stream);
    var req3 = readRequest(alloc, &c3.stream) catch return;
    req3.deinit(alloc);
    const body3 = "{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"tools\":[{\"name\":\"list_issues\"},{\"name\":\"delete_issue\"},{\"name\":\"delete_everything\"}]}}";
    var hb: [384]u8 = undefined;
    const resp3 = std.fmt.bufPrint(&hb, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{ body3.len, body3 }) catch return;
    writeAll(&c3.stream, resp3) catch return;
}

test "tools: --ignore-tool blocks tools/call and filters tools/list" {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{ .thread_safe = true }){};
    defer if (gpa_state.deinit() == .leak) @panic("memory leak");
    const alloc = gpa_state.allocator();

    var mock = try Mock.start(alloc);
    try mock.spawn(mockIgnoreToolMain);

    var collector = Collector{ .alloc = alloc };
    defer collector.deinit();

    const url = try std.fmt.allocPrint(alloc, "http://127.0.0.1:{d}/mcp", .{mock.port()});
    defer alloc.free(url);
    var cfg = Config{ .target = try http.parseUrl(url), .url = url, .transport = .http_only };
    try cfg.ignore_tools.append(alloc, "delete*");
    defer cfg.ignore_tools.deinit(alloc);
    var bridge = try Bridge.init(alloc, &cfg, collector.out(), null);

    // A blocked tools/call is answered LOCALLY (mcp-remote's -32603) with
    // no network traffic — this runs before initialize on purpose.
    bridge.injectLine("{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"tools/call\",\"params\":{\"name\":\"delete_issue\",\"arguments\":{}}}");
    try std.testing.expect(collector.contains("\"id\":9"));
    try std.testing.expect(collector.contains("-32603"));
    try std.testing.expect(collector.contains("is not available"));

    // A kept tool's call goes upstream (mock asserts it saw it).
    bridge.injectLine("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}");
    try std.testing.expect(waitFor(&bridge, &collector, "serverInfo"));
    bridge.injectLine("{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"list_issues\",\"arguments\":{}}}");
    try std.testing.expect(waitFor(&bridge, &collector, "\"id\":2,\"result\""));
    try std.testing.expect(mock.answer_seen);

    // tools/list comes back filtered: the two delete* tools are gone.
    bridge.injectLine("{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/list\",\"params\":{}}");
    try std.testing.expect(waitFor(&bridge, &collector, "\"id\":3,\"result\""));
    try std.testing.expect(collector.contains("list_issues"));
    try std.testing.expect(!collector.contains("delete_everything"));

    bridge.deinit();
    mock.join();
}
