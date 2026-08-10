// Shared HTTP/1.1 protocol types: URL target, response container, header
// helpers. The request/response machinery lives in httpc.zig (event-driven
// connection state machine); the legacy blocking readers retired with the
// serial core (issue #7).

const std = @import("std");

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

pub const MAX_RESPONSE: usize = 16 * 1024 * 1024;

pub const Response = struct {
    status: u16,
    body: []u8,
    mcp_session_id: ?[]u8, // owned slice into backing
    www_authenticate: ?[]u8, // owned slice into backing (401 challenges)
    server_closed: bool, // server sent Connection: close (or SSE framing)
    _backing: []u8, // owns body + session id memory

    pub fn deinit(self: *Response, alloc: std.mem.Allocator) void {
        alloc.free(self._backing);
    }
};

pub fn getHeaderValue(head: []const u8, name: []const u8) ?[]const u8 {
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

pub fn getHeaderNumeric(head: []const u8, name: []const u8) ?usize {
    const v = getHeaderValue(head, name) orelse return null;
    return std.fmt.parseInt(usize, v, 10) catch null;
}
