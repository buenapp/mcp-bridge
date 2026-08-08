// Minimal HTTP/1.1 client over a TlsStream (request/response only).
// Sends Accept: application/json, text/event-stream per MCP spec; handles
// plain JSON responses AND SSE-framed responses (some servers, e.g. the
// Jenkins MCP plugin / Java SDK, require SSE). Chunked transfer-encoding
// supported. For SSE responses the connection is left mid-stream — caller
// must not reuse it.

const std = @import("std");
const mcp = @import("mcp.zig");

pub const HttpError = error{
    WriteFailed,
    ReadFailed,
    MalformedResponse,
    ResponseTooLarge,
    SseEndedWithoutResponse,
    OutOfMemory,
};

pub const Response = struct {
    status: u16,
    body: []u8,
    mcp_session_id: ?[]u8, // owned slice into backing
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
    var req: std.ArrayList(u8) = .empty;
    defer req.deinit(alloc);

    appendFmt(alloc, &req, "POST {s} HTTP/1.1\r\nHost: {s}\r\n", .{ path, host }) catch return HttpError.OutOfMemory;
    req.appendSlice(alloc, "Content-Type: application/json\r\nAccept: application/json, text/event-stream\r\n") catch return HttpError.OutOfMemory;
    for (extra_headers) |h| {
        appendFmt(alloc, &req, "{s}\r\n", .{h}) catch return HttpError.OutOfMemory;
    }
    appendFmt(alloc, &req, "Content-Length: {d}\r\n\r\n", .{body.len}) catch return HttpError.OutOfMemory;
    req.appendSlice(alloc, body) catch return HttpError.OutOfMemory;

    tls.writeAll(req.items) catch return HttpError.WriteFailed;

    return readResponse(alloc, tls, expect_id, sse_sink);
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
const Pump = struct {
    mode: BodyMode,
    rpos: usize,
    chunk_left: usize = 0,

    fn next(self: *Pump, alloc: std.mem.Allocator, tls: anytype, buf: *std.ArrayList(u8), body_buf: *std.ArrayList(u8)) HttpError!enum { data, end } {
        var tmp: [16384]u8 = undefined;
        switch (self.mode) {
            .length => |*remaining| {
                if (remaining.* == 0) return .end;
                if (self.rpos >= buf.items.len) {
                    if (buf.items.len > MAX_RESPONSE) return HttpError.ResponseTooLarge;
                    const n = tls.read(&tmp) catch return HttpError.ReadFailed;
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
                const n = tls.read(&tmp) catch return HttpError.ReadFailed;
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
                        const n = tls.read(&tmp) catch return HttpError.ReadFailed;
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
                    const n = tls.read(&tmp) catch return HttpError.ReadFailed;
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

/// Find the end of the next complete SSE event (blank-line separator).
/// Returns the slice length INCLUDING the separator, or null if incomplete.
fn sseEventEnd(data: []const u8) ?usize {
    if (std.mem.indexOf(u8, data, "\r\n\r\n")) |i| return i + 4;
    if (std.mem.indexOf(u8, data, "\n\n")) |i| return i + 2;
    return null;
}

/// Extract the joined data: payload of an SSE event. Caller frees.
fn sseEventData(alloc: std.mem.Allocator, event: []const u8) ?[]u8 {
    var out: std.ArrayList(u8) = .empty;
    var any = false;
    var it = std.mem.splitScalar(u8, event, '\n');
    while (it.next()) |line_raw| {
        var line = line_raw;
        if (line.len > 0 and line[line.len - 1] == '\r') line = line[0 .. line.len - 1];
        if (line.len == 0 or line[0] == ':') continue; // blank / comment
        if (std.mem.startsWith(u8, line, "data:")) {
            var payload = line["data:".len..];
            if (payload.len > 0 and payload[0] == ' ') payload = payload[1..];
            if (any) out.append(alloc, '\n') catch return null;
            out.appendSlice(alloc, payload) catch return null;
            any = true;
        }
    }
    if (!any) {
        out.deinit(alloc);
        return null;
    }
    return out.toOwnedSlice(alloc) catch null;
}

fn readResponse(
    alloc: std.mem.Allocator,
    tls: anytype,
    expect_id: ?[]const u8,
    sse_sink: SseSink,
) HttpError!Response {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(alloc);

    // Read until end of headers
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

    // Headers of interest
    const content_length = getHeaderNumeric(head, "content-length");
    const session_id = getHeaderValue(head, "mcp-session-id");
    const conn_hdr = getHeaderValue(head, "connection");
    const server_closed = if (conn_hdr) |v| std.ascii.eqlIgnoreCase(v, "close") else false;
    const chunked = if (getHeaderValue(head, "transfer-encoding")) |v|
        std.ascii.indexOfIgnoreCase(v, "chunked") != null
    else
        false;
    const is_sse = if (getHeaderValue(head, "content-type")) |v|
        std.ascii.indexOfIgnoreCase(v, "text/event-stream") != null
    else
        false;

    const mode: BodyMode = if (chunked)
        .chunked
    else if (content_length) |cl|
        .{ .length = cl }
    else
        .until_close;

    var pump = Pump{ .mode = mode, .rpos = he + 4 };
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(alloc);

    if (!is_sse) {
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
        var bpos: usize = 0;
        var matched: ?[]u8 = null;
        while (matched == null) {
            while (sseEventEnd(body.items[bpos..])) |evlen| {
                const event = body.items[bpos .. bpos + evlen];
                bpos += evlen;
                const payload = sseEventData(alloc, event) orelse continue;
                const is_match = if (expect_id) |eid| blk: {
                    const pid = mcp.getRequestId(payload) orelse break :blk false;
                    break :blk std.mem.eql(u8, pid, eid);
                } else true; // notification: first message event wins
                if (is_match) {
                    matched = payload;
                    break;
                }
                if (sse_sink.push) |push| push(sse_sink.ctx, payload);
                alloc.free(payload);
            }
            if (matched != null) break;
            switch (try pump.next(alloc, tls, &buf, &body)) {
                .data => {},
                .end => return HttpError.SseEndedWithoutResponse,
            }
        }
        // Compact body to just the matched payload
        const m = matched.?;
        body.clearRetainingCapacity();
        body.appendSlice(alloc, m) catch return HttpError.OutOfMemory;
        alloc.free(m);
    }

    // Move body (+ optional session id) into one owned allocation
    const body_len = body.items.len;
    const sid_len: usize = if (session_id) |s| s.len else 0;

    const backing = alloc.alloc(u8, body_len + sid_len) catch return HttpError.OutOfMemory;
    @memcpy(backing[0..body_len], body.items);
    var sid: ?[]u8 = null;
    if (session_id) |s| {
        @memcpy(backing[body_len..][0..sid_len], s);
        sid = backing[body_len..][0..sid_len];
    }
    buf.deinit(alloc);

    return .{ .status = status, .body = backing[0..body_len], .mcp_session_id = sid, .server_closed = server_closed or is_sse, ._backing = backing };
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
