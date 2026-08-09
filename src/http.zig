// Minimal HTTP/1.1 client over a TlsStream (request/response only).
// Sends Accept: application/json, text/event-stream per MCP spec; handles
// plain JSON responses AND SSE-framed responses (some servers, e.g. the
// Jenkins MCP plugin / Java SDK, require SSE). Chunked transfer-encoding
// supported. For SSE responses the connection is left mid-stream — caller
// must not reuse it.

const std = @import("std");
const mcp = @import("mcp.zig");
const sse = @import("sse.zig");

pub const Target = struct {
    secure: bool,
    host: []const u8,
    port: u16,
    path: []const u8,

    /// Origin as "https://host[:port]" (no path), for RFC 9728 discovery.
    pub fn origin(self: Target, alloc: std.mem.Allocator) ![]u8 {
        const scheme = if (self.secure) "https" else "http";
        const default_port: u16 = if (self.secure) 443 else 80;
        if (self.port == default_port)
            return std.fmt.allocPrint(alloc, "{s}://{s}", .{ scheme, self.host });
        return std.fmt.allocPrint(alloc, "{s}://{s}:{d}", .{ scheme, self.host, self.port });
    }
};

pub fn parseUrl(url: []const u8) !Target {
    var rest = url;
    var secure = true;
    if (std.mem.startsWith(u8, rest, "https://")) {
        rest = rest["https://".len..];
    } else if (std.mem.startsWith(u8, rest, "http://")) {
        rest = rest["http://".len..];
        secure = false;
    } else return error.BadScheme;

    const slash = std.mem.indexOf(u8, rest, "/") orelse rest.len;
    const authority = rest[0..slash];
    const path = if (slash < rest.len) rest[slash..] else "/";

    var host = authority;
    var port: u16 = if (secure) 443 else 80;
    if (std.mem.indexOfScalar(u8, authority, ':')) |colon| {
        host = authority[0..colon];
        port = std.fmt.parseInt(u16, authority[colon + 1 ..], 10) catch return error.BadPort;
    }
    if (host.len == 0) return error.BadHost;
    return .{ .secure = secure, .host = host, .port = port, .path = path };
}

pub const HttpError = error{
    WriteFailed,
    ReadFailed,
    /// Socket recv timeout (SO_RCVTIMEO). Only surfaces for the
    /// long-lived SseStream API, where an idle stream is normal; the
    /// one-shot request APIs keep the historical ReadFailed mapping.
    Timeout,
    MalformedResponse,
    ResponseTooLarge,
    SseEndedWithoutResponse,
    OutOfMemory,
};

pub const Response = struct {
    status: u16,
    body: []u8,
    mcp_session_id: ?[]u8, // owned slice into backing
    www_authenticate: ?[]u8, // owned slice into backing (401 challenges)
    server_closed: bool, // server sent Connection: close
    _backing: []u8, // owns body + session id memory

    pub fn deinit(self: *Response, alloc: std.mem.Allocator) void {
        alloc.free(self._backing);
    }
};

pub const SseSink = struct {
    ctx: ?*anyopaque = null,
    /// Called with each non-matching SSE message payload (server-pushed
    /// notifications etc.). May be null to drop them.
    push: ?*const fn (ctx: ?*anyopaque, data: []const u8) void = null,
};

/// POST `body` to `path` on an established TLS stream.
/// Extra headers (e.g. auth) are raw "Name: Value" strings.
/// `expect_id`: raw JSON id of the request (for SSE response matching;
/// null = notification, first SSE message event wins).
/// Returns owned Response (call deinit).
pub fn post(
    alloc: std.mem.Allocator,
    tls: anytype,
    host: []const u8,
    path: []const u8,
    body: []const u8,
    extra_headers: []const []const u8,
    expect_id: ?[]const u8,
    sse_sink: SseSink,
) HttpError!Response {
    return postWith(alloc, tls, host, path, body, "application/json", extra_headers, expect_id, sse_sink);
}

/// POST with an explicit Content-Type (OAuth form posts use
/// application/x-www-form-urlencoded).
pub fn postWith(
    alloc: std.mem.Allocator,
    tls: anytype,
    host: []const u8,
    path: []const u8,
    body: []const u8,
    content_type: []const u8,
    extra_headers: []const []const u8,
    expect_id: ?[]const u8,
    sse_sink: SseSink,
) HttpError!Response {
    var req: std.ArrayList(u8) = .empty;
    defer req.deinit(alloc);

    appendFmt(alloc, &req, "POST {s} HTTP/1.1\r\nHost: {s}\r\n", .{ path, host }) catch return HttpError.OutOfMemory;
    appendFmt(alloc, &req, "Content-Type: {s}\r\nAccept: application/json, text/event-stream\r\n", .{content_type}) catch return HttpError.OutOfMemory;
    for (extra_headers) |h| {
        appendFmt(alloc, &req, "{s}\r\n", .{h}) catch return HttpError.OutOfMemory;
    }
    appendFmt(alloc, &req, "Content-Length: {d}\r\n\r\n", .{body.len}) catch return HttpError.OutOfMemory;
    req.appendSlice(alloc, body) catch return HttpError.OutOfMemory;

    tls.writeAll(req.items) catch return HttpError.WriteFailed;

    return readResponse(alloc, tls, expect_id, sse_sink);
}

/// GET `path` on an established TLS stream (OAuth discovery metadata).
pub fn get(
    alloc: std.mem.Allocator,
    tls: anytype,
    host: []const u8,
    path: []const u8,
    extra_headers: []const []const u8,
) HttpError!Response {
    var req: std.ArrayList(u8) = .empty;
    defer req.deinit(alloc);

    appendFmt(alloc, &req, "GET {s} HTTP/1.1\r\nHost: {s}\r\n", .{ path, host }) catch return HttpError.OutOfMemory;
    req.appendSlice(alloc, "Accept: application/json\r\n") catch return HttpError.OutOfMemory;
    for (extra_headers) |h| {
        appendFmt(alloc, &req, "{s}\r\n", .{h}) catch return HttpError.OutOfMemory;
    }
    req.appendSlice(alloc, "\r\n") catch return HttpError.OutOfMemory;

    tls.writeAll(req.items) catch return HttpError.WriteFailed;

    return readResponse(alloc, tls, null, .{});
}

/// DELETE for session termination.
pub fn delete(
    alloc: std.mem.Allocator,
    tls: anytype,
    host: []const u8,
    path: []const u8,
    extra_headers: []const []const u8,
) HttpError!void {
    var req: std.ArrayList(u8) = .empty;
    defer req.deinit(alloc);

    appendFmt(alloc, &req, "DELETE {s} HTTP/1.1\r\nHost: {s}\r\n", .{ path, host }) catch return HttpError.OutOfMemory;
    for (extra_headers) |h| {
        appendFmt(alloc, &req, "{s}\r\n", .{h}) catch return HttpError.OutOfMemory;
    }
    req.appendSlice(alloc, "\r\n") catch return HttpError.OutOfMemory;

    tls.writeAll(req.items) catch return HttpError.WriteFailed;
    var resp = try readResponse(alloc, tls, null, .{});
    resp.deinit(alloc);
}

const MAX_RESPONSE: usize = 16 * 1024 * 1024;

fn appendFmt(alloc: std.mem.Allocator, list: *std.ArrayList(u8), comptime fmt: []const u8, args: anytype) !void {
    const s = try std.fmt.allocPrint(alloc, fmt, args);
    defer alloc.free(s);
    try list.appendSlice(alloc, s);
}

// Body framing mode determined from response headers.
const BodyMode = union(enum) {
    length: usize, // Content-Length
    chunked, // Transfer-Encoding: chunked
    until_close, // neither: read till EOF
};

/// Incremental de-chunking pump: decodes raw bytes from `buf` (cursor rpos)
/// into `body_buf`. Returns .data when body bytes were appended (or more may
/// follow), .end when the body is complete / stream closed.
/// Read from the wire. Stream reads surface error.Timeout when
/// `propagate_timeout` is set (long-lived SSE streams idle legitimately);
/// otherwise timeouts collapse to ReadFailed (historical behavior).
fn readWire(tls: anytype, tmp: []u8, propagate_timeout: bool) HttpError!usize {
    return tls.read(tmp) catch |err| {
        if (propagate_timeout and err == error.Timeout) return HttpError.Timeout;
        return HttpError.ReadFailed;
    };
}

const Pump = struct {
    mode: BodyMode,
    rpos: usize,
    chunk_left: usize = 0,
    propagate_timeout: bool = false,

    /// Drop consumed bytes so a long-lived stream doesn't grow `buf`
    /// unboundedly (the MAX_RESPONSE guard assumes bounded responses).
    fn compact(self: *Pump, buf: *std.ArrayList(u8)) void {
        if (self.rpos == 0) return;
        const rest = buf.items.len - self.rpos;
        std.mem.copyForwards(u8, buf.items[0..rest], buf.items[self.rpos..]);
        buf.items.len = rest;
        self.rpos = 0;
    }

    fn next(self: *Pump, alloc: std.mem.Allocator, tls: anytype, buf: *std.ArrayList(u8), body_buf: *std.ArrayList(u8)) HttpError!enum { data, end } {
        var tmp: [16384]u8 = undefined;
        switch (self.mode) {
            .length => |*remaining| {
                if (remaining.* == 0) return .end;
                if (self.rpos >= buf.items.len) {
                    if (buf.items.len > MAX_RESPONSE) return HttpError.ResponseTooLarge;
                    const n = readWire(tls, &tmp, self.propagate_timeout) catch |e| return e;
                    if (n == 0) return .end; // tolerate early close
                    buf.appendSlice(alloc, tmp[0..n]) catch return HttpError.OutOfMemory;
                }
                const avail = buf.items.len - self.rpos;
                const n = @min(avail, remaining.*);
                body_buf.appendSlice(alloc, buf.items[self.rpos .. self.rpos + n]) catch return HttpError.OutOfMemory;
                self.rpos += n;
                remaining.* -= n;
                return .data;
            },
            .until_close => {
                // Drain header-adjacent leftovers before touching the wire
                // (a single read can carry both headers and body bytes).
                if (self.rpos < buf.items.len) {
                    const n = buf.items.len - self.rpos;
                    if (body_buf.items.len + n > MAX_RESPONSE) return HttpError.ResponseTooLarge;
                    body_buf.appendSlice(alloc, buf.items[self.rpos..]) catch return HttpError.OutOfMemory;
                    self.rpos = buf.items.len;
                    return .data;
                }
                const n = try readWire(tls, &tmp, self.propagate_timeout);
                if (n == 0) return .end;
                if (body_buf.items.len + n > MAX_RESPONSE) return HttpError.ResponseTooLarge;
                body_buf.appendSlice(alloc, tmp[0..n]) catch return HttpError.OutOfMemory;
                return .data;
            },
            .chunked => {
                if (self.chunk_left == 0) {
                    // Need a chunk-size line
                    var line_end = std.mem.indexOfPos(u8, buf.items, self.rpos, "\r\n");
                    while (line_end == null) {
                        if (buf.items.len > MAX_RESPONSE) return HttpError.ResponseTooLarge;
                        const n = try readWire(tls, &tmp, self.propagate_timeout);
                        if (n == 0) return HttpError.MalformedResponse;
                        buf.appendSlice(alloc, tmp[0..n]) catch return HttpError.OutOfMemory;
                        line_end = std.mem.indexOfPos(u8, buf.items, self.rpos, "\r\n");
                    }
                    const size_str = std.mem.trim(u8, buf.items[self.rpos..line_end.?], " ");
                    const semi = std.mem.indexOfScalar(u8, size_str, ';') orelse size_str.len;
                    const chunk_size = std.fmt.parseInt(usize, size_str[0..semi], 16) catch return HttpError.MalformedResponse;
                    self.rpos = line_end.? + 2;
                    if (chunk_size == 0) return .end; // trailers ignored
                    self.chunk_left = chunk_size;
                }
                // Need chunk_left bytes + trailing CRLF
                while (buf.items.len - self.rpos < self.chunk_left + 2) {
                    if (buf.items.len > MAX_RESPONSE) return HttpError.ResponseTooLarge;
                    const n = try readWire(tls, &tmp, self.propagate_timeout);
                    if (n == 0) return HttpError.MalformedResponse;
                    buf.appendSlice(alloc, tmp[0..n]) catch return HttpError.OutOfMemory;
                }
                body_buf.appendSlice(alloc, buf.items[self.rpos .. self.rpos + self.chunk_left]) catch return HttpError.OutOfMemory;
                self.rpos += self.chunk_left + 2;
                self.chunk_left = 0;
                return .data;
            },
        }
    }
};

/// Parsed response headers. Slices point into the buffer read by
/// readHead — dupe before the buffer is mutated.
const Head = struct {
    status: u16,
    header_end: usize, // offset of "\r\n\r\n" within the buffer
    content_length: ?usize,
    session_id: ?[]const u8,
    www_authenticate: ?[]const u8,
    server_closed: bool,
    chunked: bool,
    is_sse: bool,
};

/// Read and parse response headers into `buf` (body bytes may follow
/// header_end in the buffer).
fn readHead(alloc: std.mem.Allocator, tls: anytype, buf: *std.ArrayList(u8)) HttpError!Head {
    var header_end: ?usize = null;
    var tmp: [16384]u8 = undefined;
    while (header_end == null) {
        if (buf.items.len > MAX_RESPONSE) return HttpError.ResponseTooLarge;
        const n = tls.read(&tmp) catch return HttpError.ReadFailed;
        if (n == 0) return HttpError.MalformedResponse;
        buf.appendSlice(alloc, tmp[0..n]) catch return HttpError.OutOfMemory;
        header_end = std.mem.indexOf(u8, buf.items, "\r\n\r\n");
    }

    const he = header_end.?;
    const head = buf.items[0..he];

    // Status line: "HTTP/1.1 200 OK"
    const sp1 = std.mem.indexOf(u8, head, " ") orelse return HttpError.MalformedResponse;
    const sp2 = std.mem.indexOfPos(u8, head, sp1 + 1, " ") orelse head.len;
    const status = std.fmt.parseInt(u16, head[sp1 + 1 .. sp2], 10) catch return HttpError.MalformedResponse;

    const conn_hdr = getHeaderValue(head, "connection");
    return .{
        .status = status,
        .header_end = he,
        .content_length = getHeaderNumeric(head, "content-length"),
        .session_id = getHeaderValue(head, "mcp-session-id"),
        .www_authenticate = getHeaderValue(head, "www-authenticate"),
        .server_closed = if (conn_hdr) |v| std.ascii.eqlIgnoreCase(v, "close") else false,
        .chunked = if (getHeaderValue(head, "transfer-encoding")) |v|
            std.ascii.indexOfIgnoreCase(v, "chunked") != null
        else
            false,
        .is_sse = if (getHeaderValue(head, "content-type")) |v|
            std.ascii.indexOfIgnoreCase(v, "text/event-stream") != null
        else
            false,
    };
}

fn bodyMode(h: Head) BodyMode {
    if (h.chunked) return .chunked;
    if (h.content_length) |cl| return .{ .length = cl };
    return .until_close;
}

fn readResponse(
    alloc: std.mem.Allocator,
    tls: anytype,
    expect_id: ?[]const u8,
    sse_sink: SseSink,
) HttpError!Response {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(alloc);

    const h = try readHead(alloc, tls, &buf);

    var pump = Pump{ .mode = bodyMode(h), .rpos = h.header_end + 4 };
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(alloc);

    if (!h.is_sse) {
        while (true) {
            switch (try pump.next(alloc, tls, &buf, &body)) {
                .data => {},
                .end => break,
            }
        }
    } else {
        // SSE stream: dispatch complete events as they arrive. The event
        // whose JSON-RPC id matches expect_id becomes the response body;
        // other message events go to the sink (server-pushed messages).
        var parser = sse.Parser.init(alloc);
        defer parser.deinit();
        var matched: ?[]u8 = null;
        while (matched == null) {
            while (try parser.next()) |ev_raw| {
                var ev = ev_raw;
                defer ev.deinit(alloc);
                const is_match = if (expect_id) |eid| blk: {
                    const pid = mcp.getRequestId(ev.data) orelse break :blk false;
                    break :blk std.mem.eql(u8, pid, eid);
                } else true; // notification: first message event wins
                if (is_match) {
                    matched = alloc.dupe(u8, ev.data) catch return HttpError.OutOfMemory;
                    break;
                }
                if (sse_sink.push) |push| push(sse_sink.ctx, ev.data);
            }
            if (matched != null) break;
            switch (try pump.next(alloc, tls, &buf, &body)) {
                .data => {
                    try parser.feed(body.items);
                    body.clearRetainingCapacity();
                },
                .end => return HttpError.SseEndedWithoutResponse,
            }
        }
        // Compact body to just the matched payload
        const m = matched.?;
        body.clearRetainingCapacity();
        body.appendSlice(alloc, m) catch return HttpError.OutOfMemory;
        alloc.free(m);
    }

    // Move body (+ optional session id / challenge) into one owned allocation
    const body_len = body.items.len;
    const sid_len: usize = if (h.session_id) |s| s.len else 0;
    const wa_len: usize = if (h.www_authenticate) |s| s.len else 0;

    const backing = alloc.alloc(u8, body_len + sid_len + wa_len) catch return HttpError.OutOfMemory;
    @memcpy(backing[0..body_len], body.items);
    var sid: ?[]u8 = null;
    if (h.session_id) |s| {
        @memcpy(backing[body_len..][0..sid_len], s);
        sid = backing[body_len..][0..sid_len];
    }
    var wa: ?[]u8 = null;
    if (h.www_authenticate) |s| {
        @memcpy(backing[body_len + sid_len ..][0..wa_len], s);
        wa = backing[body_len + sid_len ..][0..wa_len];
    }
    buf.deinit(alloc);

    return .{ .status = h.status, .body = backing[0..body_len], .mcp_session_id = sid, .www_authenticate = wa, .server_closed = h.server_closed or h.is_sse, ._backing = backing };
}

// -------------------------------------------------- long-lived SSE GET ----

/// A long-lived text/event-stream response (legacy HTTP+SSE transport
/// event stream, or the Streamable HTTP standalone GET stream). Headers
/// have been read; events are pulled incrementally via fill/nextEvent.
pub const SseStream = struct {
    status: u16,
    /// Content-Type was text/event-stream. Caller decides whether a
    /// non-SSE 200 is acceptable.
    is_sse: bool,
    mcp_session_id: ?[]u8 = null, // owned (_backing)
    www_authenticate: ?[]u8 = null, // owned (_backing)
    parser: sse.Parser,
    pump: Pump,
    raw: std.ArrayList(u8) = .empty, // undecoded wire bytes (pump input)
    decoded: std.ArrayList(u8) = .empty, // de-chunked scratch
    _backing: ?[]u8 = null,

    pub fn deinit(self: *SseStream, alloc: std.mem.Allocator) void {
        self.parser.deinit();
        self.raw.deinit(alloc);
        self.decoded.deinit(alloc);
        if (self._backing) |b| alloc.free(b);
    }

    pub const FillResult = enum { data, end };

    /// Pull more wire bytes into the parser. error.Timeout means the
    /// stream was idle for one socket-recv window — not fatal; check the
    /// stop flag and fill again. .end = stream closed by the server.
    pub fn fill(self: *SseStream, alloc: std.mem.Allocator, tls: anytype) HttpError!FillResult {
        self.pump.compact(&self.raw);
        self.decoded.clearRetainingCapacity();
        switch (try self.pump.next(alloc, tls, &self.raw, &self.decoded)) {
            .data => {
                try self.parser.feed(self.decoded.items);
                return .data;
            },
            .end => {
                self.parser.endOfStream();
                return .end;
            },
        }
    }

    /// Next complete event, or null when more bytes are needed.
    pub fn nextEvent(self: *SseStream) sse.Error!?sse.Event {
        return self.parser.next();
    }
};

/// GET `path` expecting a long-lived text/event-stream response
/// (Accept: text/event-stream). Returns once the response headers have
/// been read; the caller inspects .status (401/404/405 drive OAuth and
/// transport fallback) and then pulls events off the stream. The caller
/// owns the underlying connection afterwards: it must not be used for
/// anything else while the stream is open.
pub fn openSseStream(
    alloc: std.mem.Allocator,
    tls: anytype,
    host: []const u8,
    path: []const u8,
    extra_headers: []const []const u8,
) HttpError!SseStream {
    var req: std.ArrayList(u8) = .empty;
    defer req.deinit(alloc);

    appendFmt(alloc, &req, "GET {s} HTTP/1.1\r\nHost: {s}\r\n", .{ path, host }) catch return HttpError.OutOfMemory;
    req.appendSlice(alloc, "Accept: text/event-stream\r\n") catch return HttpError.OutOfMemory;
    for (extra_headers) |h| {
        appendFmt(alloc, &req, "{s}\r\n", .{h}) catch return HttpError.OutOfMemory;
    }
    req.appendSlice(alloc, "\r\n") catch return HttpError.OutOfMemory;

    tls.writeAll(req.items) catch return HttpError.WriteFailed;

    var stream = SseStream{
        .status = 0,
        .is_sse = false,
        .parser = sse.Parser.init(alloc),
        .pump = .{ .mode = .until_close, .rpos = 0, .propagate_timeout = true },
    };
    errdefer stream.deinit(alloc);

    const h = try readHead(alloc, tls, &stream.raw);
    stream.status = h.status;
    stream.is_sse = h.is_sse;
    stream.pump.mode = bodyMode(h);
    stream.pump.rpos = h.header_end + 4;

    // Header slices point into stream.raw and pump appends can
    // reallocate it — dupe into a backing allocation.
    const sid_len: usize = if (h.session_id) |s| s.len else 0;
    const wa_len: usize = if (h.www_authenticate) |s| s.len else 0;
    const backing = alloc.alloc(u8, sid_len + wa_len) catch return HttpError.OutOfMemory;
    stream._backing = backing;
    if (h.session_id) |s| {
        @memcpy(backing[0..sid_len], s);
        stream.mcp_session_id = backing[0..sid_len];
    }
    if (h.www_authenticate) |s| {
        @memcpy(backing[sid_len..][0..wa_len], s);
        stream.www_authenticate = backing[sid_len..][0..wa_len];
    }
    return stream;
}

fn getHeaderValue(head: []const u8, name: []const u8) ?[]const u8 {
    var it = std.mem.splitSequence(u8, head, "\r\n");
    _ = it.next(); // skip status line
    while (it.next()) |line| {
        const colon = std.mem.indexOf(u8, line, ":") orelse continue;
        const key = std.mem.trim(u8, line[0..colon], " ");
        if (std.ascii.eqlIgnoreCase(key, name)) {
            return std.mem.trim(u8, line[colon + 1 ..], " ");
        }
    }
    return null;
}

fn getHeaderNumeric(head: []const u8, name: []const u8) ?usize {
    const v = getHeaderValue(head, name) orelse return null;
    return std.fmt.parseInt(usize, v, 10) catch null;
}
