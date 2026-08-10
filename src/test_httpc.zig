// Tests for the event-driven HTTP connection state machine (issue #7):
// in-process mock servers (plain HTTP on 127.0.0.1, one thread each — the
// server side may block; the client under test never does) and a private
// event port driven to completion.

const std = @import("std");
const http = @import("http.zig");
const httpc = @import("httpc.zig");
const evport = @import("evport.zig");
const sse = @import("sse.zig");

// ------------------------------------------------------------ mock HTTP ----

const Req = struct {
    method: []u8,
    path: []u8,
    body: []u8,
    head: []u8,

    fn deinit(self: *Req, alloc: std.mem.Allocator) void {
        alloc.free(self.method);
        alloc.free(self.path);
        alloc.free(self.body);
        alloc.free(self.head);
    }
};

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
    defer body.deinit(alloc);
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

// -------------------------------------------------------- test harness ----

const Ctx = struct {
    alloc: std.mem.Allocator,
    done: bool = false,
    /// onResponse captures
    resp_status: ?u16 = null,
    resp_body: ?[]u8 = null, // owned dupe
    resp_session_id: ?[]u8 = null, // owned dupe
    resp_server_closed: bool = false,
    /// onStreamHead captures + decision
    head_status: ?u16 = null,
    head_is_sse: bool = false,
    head_www_authenticate: ?[]u8 = null,
    proceed: bool = true,
    /// onEvent captures (owned dupes)
    events: std.ArrayList([]u8) = .empty,
    /// onEnd captures
    ended: bool = false,
    end_err: ?anyerror = null,

    fn deinit(self: *Ctx) void {
        if (self.resp_body) |b| self.alloc.free(b);
        if (self.resp_session_id) |s| self.alloc.free(s);
        if (self.head_www_authenticate) |s| self.alloc.free(s);
        for (self.events.items) |e| self.alloc.free(e);
        self.events.deinit(self.alloc);
    }
};

fn onResponse(ctx: *anyopaque, conn: *httpc.Conn, resp: http.Response) void {
    const self: *Ctx = @ptrCast(@alignCast(ctx));
    var r = resp;
    self.resp_status = r.status;
    self.resp_body = self.alloc.dupe(u8, r.body) catch null;
    self.resp_session_id = if (r.mcp_session_id) |s| self.alloc.dupe(u8, s) catch null else null;
    self.resp_server_closed = r.server_closed;
    r.deinit(conn.alloc);
    conn.close();
    self.done = true;
}

fn onStreamHead(ctx: *anyopaque, conn: *httpc.Conn, status: u16, is_sse: bool, session_id: ?[]const u8, www_authenticate: ?[]const u8) void {
    const self: *Ctx = @ptrCast(@alignCast(ctx));
    _ = session_id;
    self.head_status = status;
    self.head_is_sse = is_sse;
    if (www_authenticate) |wa| self.head_www_authenticate = self.alloc.dupe(u8, wa) catch null;
    if (self.proceed) conn.proceedStream() else conn.close();
}

fn onEvent(ctx: *anyopaque, conn: *httpc.Conn, ev: *const sse.Event) void {
    const self: *Ctx = @ptrCast(@alignCast(ctx));
    _ = conn;
    const dupe = self.alloc.dupe(u8, ev.data) catch return;
    self.events.append(self.alloc, dupe) catch self.alloc.free(dupe);
}

fn onEnd(ctx: *anyopaque, conn: *httpc.Conn, err: ?anyerror) void {
    const self: *Ctx = @ptrCast(@alignCast(ctx));
    self.ended = true;
    self.end_err = err;
    conn.close();
    self.done = true;
}

/// Ctx + handler bound to the ctx's final address (never via an init
/// function — a returned-by-value struct would leave ctx dangling).
fn harness(ctx: *Ctx) httpc.Handler {
    return .{
        .ctx = ctx,
        .onResponse = onResponse,
        .onStreamHead = onStreamHead,
        .onEvent = onEvent,
        .onEnd = onEnd,
    };
}

/// Drive the private event port until the ctx completes (bounded).
fn runToDone(evp: *evport.EvPort, ctx: *Ctx) !void {
    var events: [16]evport.Event = undefined;
    var idle_rounds: usize = 0;
    while (!ctx.done and idle_rounds < 100) {
        const n = try evp.wait(&events, 100);
        if (n == 0) {
            idle_rounds += 1;
            continue;
        }
        idle_rounds = 0;
        for (events[0..n]) |ev| {
            if (ev.udata) |ud| {
                const conn: *httpc.Conn = @ptrCast(@alignCast(ud));
                conn.onEvent(ev);
            }
        }
    }
    if (!ctx.done) return error.TestTimedOut;
}

fn reap(conn: *httpc.Conn) void {
    conn.reapClose();
    conn.deinitMem();
}

// --------------------------------------------------------------- tests ----

fn mockJsonMain(mock: *Mock) void {
    const alloc = mock.alloc;
    var c = mock.server.accept() catch return;
    defer c.stream.close();
    var req = readRequest(alloc, &c.stream) catch return;
    defer req.deinit(alloc);
    const body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}";
    var hb: [256]u8 = undefined;
    const resp = std.fmt.bufPrint(&hb, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nMCP-Session-Id: sess-1\r\n\r\n{s}", .{ body.len, body }) catch return;
    writeAll(&c.stream, resp) catch return;
    drainUntilClose(&c.stream);
}

test "httpc post: JSON response with session id" {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{ .thread_safe = true }){};
    defer if (gpa_state.deinit() == .leak) @panic("memory leak");
    const alloc = gpa_state.allocator();

    var mock = try Mock.start(alloc);
    try mock.spawn(mockJsonMain);

    var evp = try evport.EvPort.init(alloc);
    defer evp.deinit();
    var ctx = Ctx{ .alloc = alloc };
    const hnd = harness(&ctx);
    defer ctx.deinit();

    const url = try std.fmt.allocPrint(alloc, "http://127.0.0.1:{d}/mcp", .{mock.port()});
    defer alloc.free(url);
    const target = try http.parseUrl(url);

    const line = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}";
    const req = try httpc.buildRequest(alloc, "POST", target.path, target.host, "application/json, text/event-stream", "application/json", &.{}, line);
    const conn = try httpc.Conn.startPost(alloc, &evp, &hnd, target, req, "1", line, null);
    try runToDone(&evp, &ctx);
    reap(conn);

    try std.testing.expectEqual(@as(u16, 200), ctx.resp_status.?);
    try std.testing.expect(std.mem.indexOf(u8, ctx.resp_body.?, "\"ok\":true") != null);
    try std.testing.expectEqualStrings("sess-1", ctx.resp_session_id.?);
    try std.testing.expect(!ctx.resp_server_closed);

    mock.join();
}

fn mockChunkedMain(mock: *Mock) void {
    const alloc = mock.alloc;
    var c = mock.server.accept() catch return;
    defer c.stream.close();
    var req = readRequest(alloc, &c.stream) catch return;
    defer req.deinit(alloc);
    writeAll(&c.stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n") catch return;
    writeAll(&c.stream, "11\r\n{\"jsonrpc\":\"2.0\",\r\n") catch return;
    writeAll(&c.stream, "13\r\n\"id\":2,\"result\":{}}\r\n") catch return;
    writeAll(&c.stream, "0\r\n\r\n") catch return;
    drainUntilClose(&c.stream);
}

test "httpc post: chunked transfer-encoding reassembled" {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{ .thread_safe = true }){};
    defer if (gpa_state.deinit() == .leak) @panic("memory leak");
    const alloc = gpa_state.allocator();

    var mock = try Mock.start(alloc);
    try mock.spawn(mockChunkedMain);

    var evp = try evport.EvPort.init(alloc);
    defer evp.deinit();
    var ctx = Ctx{ .alloc = alloc };
    const hnd = harness(&ctx);
    defer ctx.deinit();

    const url = try std.fmt.allocPrint(alloc, "http://127.0.0.1:{d}/mcp", .{mock.port()});
    defer alloc.free(url);
    const target = try http.parseUrl(url);

    const line = "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}";
    const req = try httpc.buildRequest(alloc, "POST", target.path, target.host, "application/json, text/event-stream", "application/json", &.{}, line);
    const conn = try httpc.Conn.startPost(alloc, &evp, &hnd, target, req, "2", line, null);
    try runToDone(&evp, &ctx);
    reap(conn);

    try std.testing.expectEqual(@as(u16, 200), ctx.resp_status.?);
    try std.testing.expectEqualStrings("{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{}}", ctx.resp_body.?);

    mock.join();
}

fn mockSsePostMain(mock: *Mock) void {
    const alloc = mock.alloc;
    var c = mock.server.accept() catch return;
    defer c.stream.close();
    var req = readRequest(alloc, &c.stream) catch return;
    defer req.deinit(alloc);
    writeAll(&c.stream, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n") catch return;
    // A server-pushed notification first (non-matching id), then the
    // response matching expect_id 1.
    writeAll(&c.stream, "43\r\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/x\"}\n\n\r\n") catch return;
    writeAll(&c.stream, "3b\r\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n\r\n") catch return;
    drainUntilClose(&c.stream);
}

test "httpc post: SSE-framed response — push events + id match" {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{ .thread_safe = true }){};
    defer if (gpa_state.deinit() == .leak) @panic("memory leak");
    const alloc = gpa_state.allocator();

    var mock = try Mock.start(alloc);
    try mock.spawn(mockSsePostMain);

    var evp = try evport.EvPort.init(alloc);
    defer evp.deinit();
    var ctx = Ctx{ .alloc = alloc };
    const hnd = harness(&ctx);
    defer ctx.deinit();

    const url = try std.fmt.allocPrint(alloc, "http://127.0.0.1:{d}/mcp", .{mock.port()});
    defer alloc.free(url);
    const target = try http.parseUrl(url);

    const line = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}";
    const req = try httpc.buildRequest(alloc, "POST", target.path, target.host, "application/json, text/event-stream", "application/json", &.{}, line);
    const conn = try httpc.Conn.startPost(alloc, &evp, &hnd, target, req, "1", line, null);
    try runToDone(&evp, &ctx);
    reap(conn);

    // The non-matching event arrived as a push...
    try std.testing.expectEqual(@as(usize, 1), ctx.events.items.len);
    try std.testing.expectEqualStrings("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/x\"}", ctx.events.items[0]);
    // ...and the matching event became the response.
    try std.testing.expectEqual(@as(u16, 200), ctx.resp_status.?);
    try std.testing.expectEqualStrings("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}", ctx.resp_body.?);
    try std.testing.expect(ctx.resp_server_closed); // SSE response ⇒ conn not reusable

    mock.join();
}

fn mockSseGetMain(mock: *Mock) void {
    const alloc = mock.alloc;
    var c = mock.server.accept() catch return;
    var req = readRequest(alloc, &c.stream) catch {
        c.stream.close();
        return;
    };
    defer req.deinit(alloc);
    writeAll(&c.stream, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\n\r\n") catch return;
    writeAll(&c.stream, "event: endpoint\ndata: /messages?session_id=t1\n\n") catch return;
    writeAll(&c.stream, "event: message\nid: ev-9\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/y\"}\n\n") catch return;
    c.stream.close(); // clean stream end
}

test "httpc sse_get: head, events, clean EOF" {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{ .thread_safe = true }){};
    defer if (gpa_state.deinit() == .leak) @panic("memory leak");
    const alloc = gpa_state.allocator();

    var mock = try Mock.start(alloc);
    try mock.spawn(mockSseGetMain);

    var evp = try evport.EvPort.init(alloc);
    defer evp.deinit();
    var ctx = Ctx{ .alloc = alloc };
    const hnd = harness(&ctx);
    defer ctx.deinit();

    const url = try std.fmt.allocPrint(alloc, "http://127.0.0.1:{d}/sse", .{mock.port()});
    defer alloc.free(url);
    const target = try http.parseUrl(url);

    const req = try httpc.buildRequest(alloc, "GET", target.path, target.host, "text/event-stream", null, &.{}, null);
    const conn = try httpc.Conn.startStreamGet(alloc, &evp, &hnd, target, req, null);
    try runToDone(&evp, &ctx);
    reap(conn);

    try std.testing.expectEqual(@as(u16, 200), ctx.head_status.?);
    try std.testing.expect(ctx.head_is_sse);
    try std.testing.expectEqual(@as(usize, 2), ctx.events.items.len);
    try std.testing.expectEqualStrings("/messages?session_id=t1", ctx.events.items[0]);
    try std.testing.expectEqualStrings("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/y\"}", ctx.events.items[1]);
    try std.testing.expect(ctx.ended);
    try std.testing.expect(ctx.end_err == null);

    mock.join();
}

fn mock404Main(mock: *Mock) void {
    const alloc = mock.alloc;
    var c = mock.server.accept() catch return;
    defer c.stream.close();
    var req = readRequest(alloc, &c.stream) catch return;
    defer req.deinit(alloc);
    writeAll(&c.stream, "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n") catch return;
    drainUntilClose(&c.stream);
}

test "httpc post: error status surfaces with empty body" {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{ .thread_safe = true }){};
    defer if (gpa_state.deinit() == .leak) @panic("memory leak");
    const alloc = gpa_state.allocator();

    var mock = try Mock.start(alloc);
    try mock.spawn(mock404Main);

    var evp = try evport.EvPort.init(alloc);
    defer evp.deinit();
    var ctx = Ctx{ .alloc = alloc };
    const hnd = harness(&ctx);
    defer ctx.deinit();

    const url = try std.fmt.allocPrint(alloc, "http://127.0.0.1:{d}/mcp", .{mock.port()});
    defer alloc.free(url);
    const target = try http.parseUrl(url);

    const line = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}";
    const req = try httpc.buildRequest(alloc, "POST", target.path, target.host, "application/json, text/event-stream", "application/json", &.{}, line);
    const conn = try httpc.Conn.startPost(alloc, &evp, &hnd, target, req, "1", line, null);
    try runToDone(&evp, &ctx);
    reap(conn);

    try std.testing.expectEqual(@as(u16, 405), ctx.resp_status.?);
    try std.testing.expectEqualStrings("", ctx.resp_body.?);
    try std.testing.expect(ctx.resp_server_closed);

    mock.join();
}

test "httpc post: connect failure surfaces via onEnd" {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{ .thread_safe = true }){};
    defer if (gpa_state.deinit() == .leak) @panic("memory leak");
    const alloc = gpa_state.allocator();

    // Find a port nothing listens on.
    const addr = try std.net.Address.parseIp4("127.0.0.1", 0);
    var server = try addr.listen(.{});
    const port = server.listen_address.getPort();
    server.deinit();

    var evp = try evport.EvPort.init(alloc);
    defer evp.deinit();
    var ctx = Ctx{ .alloc = alloc };
    const hnd = harness(&ctx);
    defer ctx.deinit();

    const url = try std.fmt.allocPrint(alloc, "http://127.0.0.1:{d}/mcp", .{port});
    defer alloc.free(url);
    const target = try http.parseUrl(url);

    const line = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}";
    const req = try httpc.buildRequest(alloc, "POST", target.path, target.host, "application/json, text/event-stream", "application/json", &.{}, line);
    const conn = try httpc.Conn.startPost(alloc, &evp, &hnd, target, req, "1", line, null);
    try runToDone(&evp, &ctx);
    reap(conn);

    try std.testing.expect(ctx.ended);
    try std.testing.expectEqual(error.ConnectFailed, ctx.end_err.?);
}
