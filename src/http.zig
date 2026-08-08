// Minimal HTTP/1.1 client over a TlsStream (request/response only).
// MCP Streamable HTTP (2025-03-26) with Accept: application/json returns
// plain JSON bodies — no SSE parsing needed.

const std = @import("std");
const schannel = @import("schannel.zig");

pub const HttpError = error{
    WriteFailed,
    ReadFailed,
    MalformedResponse,
    ResponseTooLarge,
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

/// POST `body` to `path` on an established TLS stream.
/// Extra headers (e.g. auth) are raw "Name: Value" strings.
/// Returns owned Response (call deinit).
pub fn post(
    alloc: std.mem.Allocator,
    tls: anytype,
    host: []const u8,
    path: []const u8,
    body: []const u8,
    extra_headers: []const []const u8,
) HttpError!Response {
    var req: std.ArrayList(u8) = .empty;
    defer req.deinit(alloc);

    appendFmt(alloc, &req, "POST {s} HTTP/1.1\r\nHost: {s}\r\n", .{ path, host }) catch return HttpError.OutOfMemory;
    req.appendSlice(alloc, "Content-Type: application/json\r\nAccept: application/json\r\n") catch return HttpError.OutOfMemory;
    for (extra_headers) |h| {
        appendFmt(alloc, &req, "{s}\r\n", .{h}) catch return HttpError.OutOfMemory;
    }
    appendFmt(alloc, &req, "Content-Length: {d}\r\n\r\n", .{body.len}) catch return HttpError.OutOfMemory;
    req.appendSlice(alloc, body) catch return HttpError.OutOfMemory;

    tls.writeAll(req.items) catch return HttpError.WriteFailed;

    return readResponse(alloc, tls);
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
    var resp = try readResponse(alloc, tls);
    resp.deinit(alloc);
}

const MAX_RESPONSE: usize = 16 * 1024 * 1024;

fn appendFmt(alloc: std.mem.Allocator, list: *std.ArrayList(u8), comptime fmt: []const u8, args: anytype) !void {
    const s = try std.fmt.allocPrint(alloc, fmt, args);
    defer alloc.free(s);
    try list.appendSlice(alloc, s);
}

fn readResponse(alloc: std.mem.Allocator, tls: anytype) HttpError!Response {
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

    var body = std.ArrayList(u8){ .items = &.{}, .capacity = 0 };
    defer body.deinit(alloc);

    if (chunked) {
        // Chunked transfer-encoding: read chunks until terminal 0-chunk.
        // Remaining buffered bytes after the headers are chunk data.
        var pos: usize = he + 4;
        while (true) {
            // Need a chunk-size line
            var line_end = std.mem.indexOfPos(u8, buf.items, pos, "\r\n");
            while (line_end == null) {
                if (buf.items.len > MAX_RESPONSE) return HttpError.ResponseTooLarge;
                const n = tls.read(&tmp) catch return HttpError.ReadFailed;
                if (n == 0) return HttpError.MalformedResponse;
                buf.appendSlice(alloc, tmp[0..n]) catch return HttpError.OutOfMemory;
                line_end = std.mem.indexOfPos(u8, buf.items, pos, "\r\n");
            }
            const size_str = std.mem.trim(u8, buf.items[pos..line_end.?], " ");
            const semi = std.mem.indexOfScalar(u8, size_str, ';') orelse size_str.len;
            const chunk_size = std.fmt.parseInt(usize, size_str[0..semi], 16) catch return HttpError.MalformedResponse;
            pos = line_end.? + 2;
            if (chunk_size == 0) break; // terminal chunk (trailers ignored)

            // Read chunk data + trailing CRLF
            while (buf.items.len - pos < chunk_size + 2) {
                if (buf.items.len > MAX_RESPONSE) return HttpError.ResponseTooLarge;
                const n = tls.read(&tmp) catch return HttpError.ReadFailed;
                if (n == 0) return HttpError.MalformedResponse;
                buf.appendSlice(alloc, tmp[0..n]) catch return HttpError.OutOfMemory;
            }
            body.appendSlice(alloc, buf.items[pos .. pos + chunk_size]) catch return HttpError.OutOfMemory;
            pos += chunk_size + 2;
        }
    } else {
        const want = content_length orelse 0;
        var body_have = buf.items.len - (he + 4);
        while (body_have < want) {
            if (buf.items.len > MAX_RESPONSE) return HttpError.ResponseTooLarge;
            const n = tls.read(&tmp) catch return HttpError.ReadFailed;
            if (n == 0) break; // tolerate early close
            buf.appendSlice(alloc, tmp[0..n]) catch return HttpError.OutOfMemory;
            body_have = buf.items.len - (he + 4);
        }
        const body_raw = buf.items[he + 4 ..];
        const body_len = @min(body_raw.len, want);
        body.appendSlice(alloc, body_raw[0..body_len]) catch return HttpError.OutOfMemory;
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

    return .{ .status = status, .body = backing[0..body_len], .mcp_session_id = sid, .server_closed = server_closed, ._backing = backing };
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
