// Optional JSON config file, keyed by server URL.
//
// Default lookup: ~/.config/mcp-bridge/config.json (POSIX, honoring
// XDG_CONFIG_HOME) or %APPDATA%\mcp-bridge\config.json (Windows).
//
// Example:
// {
//   "servers": {
//     "https://mcp.example.com/mcp": {
//       "oauth": true,
//       "client_id": "...",       // optional; DCR when absent
//       "client_secret": "...",   // optional (public clients omit)
//       "scope": "openid profile",// optional
//       "resource": "https://tenant.example.net/", // optional RFC 8707 resource
//       "grant": "authorization_code",             // optional: authorization_code|client_credentials
//       "transport": "sse-only",                   // optional: http-first|http-only|sse-first|sse-only
//       "headers": {"Authorization": "Bearer <token>"} // optional static request headers
//     }
//   }
// }
//
// Static headers: parsed into the same "Name: Value" line form as CLI
// --header entries. A CLI --header for the same name (case-insensitive)
// wins; otherwise file entries are sent too (see mergeHeaders). The config
// file is user-owned, so keeping tokens in it avoids exposing them in the
// process list the way --header argv values are.

const std = @import("std");
const builtin = @import("builtin");

pub const ServerConfig = struct {
    oauth: bool = false,
    client_id: ?[]const u8 = null,
    client_secret: ?[]const u8 = null,
    scope: ?[]const u8 = null,
    resource: ?[]const u8 = null,
    grant: ?[]const u8 = null,
    transport: ?[]const u8 = null, // http-first|http-only|sse-first|sse-only
    /// Static request headers from the config file, materialized as
    /// "Name: Value" lines (arena-owned) — the same representation as CLI
    /// --header entries so the merge path is uniform.
    headers: []const []const u8 = &.{},
};

/// Header name of a "Name: Value" line: the text before the first ':',
/// trimmed. Null for lines without a colon.
pub fn headerName(line: []const u8) ?[]const u8 {
    const idx = std.mem.indexOfScalar(u8, line, ':') orelse return null;
    return std.mem.trim(u8, line[0..idx], " \t");
}

/// Merge CLI --header lines with config-file header lines. CLI entries
/// come first and win name collisions (case-insensitive) — flags override
/// file values. Caller owns the returned slice; the referenced header
/// lines are NOT copied.
pub fn mergeHeaders(alloc: std.mem.Allocator, cli: []const []const u8, file: []const []const u8) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    try out.appendSlice(alloc, cli);
    for (file) |fh| {
        const fname = headerName(fh) orelse continue;
        var overridden = false;
        for (cli) |ch| {
            if (headerName(ch)) |cname| {
                if (std.ascii.eqlIgnoreCase(cname, fname)) {
                    overridden = true;
                    break;
                }
            }
        }
        if (!overridden) try out.append(alloc, fh);
    }
    return out.toOwnedSlice(alloc);
}

pub const ConfigFile = struct {
    arena: std.heap.ArenaAllocator,
    servers: std.StringHashMapUnmanaged(ServerConfig) = .empty,

    pub fn deinit(self: *ConfigFile) void {
        self.arena.deinit();
    }

    /// Look up by exact server URL, then by origin (scheme://host[:port]).
    pub fn lookup(self: *const ConfigFile, url: []const u8) ?ServerConfig {
        if (self.servers.get(url)) |sc| return sc;
        // Origin fallback: strip the path
        if (std.mem.indexOf(u8, url, "://")) |scheme_end| {
            const after = scheme_end + 3;
            const end = std.mem.indexOfScalarPos(u8, url, after, '/') orelse url.len;
            if (end != url.len) {
                if (self.servers.get(url[0..end])) |sc| return sc;
            }
        }
        return null;
    }
};

/// Default config file path. Caller owns the returned slice.
pub fn defaultPath(alloc: std.mem.Allocator) ![]u8 {
    if (builtin.os.tag == .windows) {
        const appdata = std.process.getEnvVarOwned(alloc, "APPDATA") catch
            return error.NoConfigDir;
        defer alloc.free(appdata);
        return std.fs.path.join(alloc, &.{ appdata, "mcp-bridge", "config.json" });
    }
    if (std.process.getEnvVarOwned(alloc, "XDG_CONFIG_HOME")) |xdg| {
        defer alloc.free(xdg);
        if (xdg.len > 0) return std.fs.path.join(alloc, &.{ xdg, "mcp-bridge", "config.json" });
    } else |_| {}
    const home = std.process.getEnvVarOwned(alloc, "HOME") catch return error.NoConfigDir;
    defer alloc.free(home);
    return std.fs.path.join(alloc, &.{ home, ".config", "mcp-bridge", "config.json" });
}

/// Load and parse a config file. Returns null when the file simply does
/// not exist; parse/IO errors propagate.
pub fn load(alloc: std.mem.Allocator, path: []const u8) !?ConfigFile {
    const text = std.fs.cwd().readFileAlloc(alloc, path, 1 << 20) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer alloc.free(text);

    var cf = ConfigFile{ .arena = std.heap.ArenaAllocator.init(alloc) };
    errdefer cf.deinit();
    const a = cf.arena.allocator();

    const parsed = try std.json.parseFromSlice(std.json.Value, a, text, .{});
    const root = switch (parsed.value) {
        .object => |o| o,
        else => return error.BadConfig,
    };
    const servers = root.get("servers") orelse return cf;
    const servers_obj = switch (servers) {
        .object => |o| o,
        else => return error.BadConfig,
    };

    var it = servers_obj.iterator();
    while (it.next()) |entry| {
        const sc = try parseServer(a, entry.value_ptr.*);
        try cf.servers.put(a, try a.dupe(u8, entry.key_ptr.*), sc);
    }
    return cf;
}

/// RFC 9110 field-name token characters only: no controls, no spaces,
/// no separators (':' in particular would corrupt the line form).
fn validHeaderName(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name) |c| {
        if (c <= 0x20 or c >= 0x7f) return false;
        switch (c) {
            ':', '(', ')', '<', '>', '@', ',', ';', '\\', '"', '/', '[', ']', '?', '=', '{', '}' => return false,
            else => {},
        }
    }
    return true;
}

/// No CR/LF — a config-file value must never inject extra header lines.
fn validHeaderValue(value: []const u8) bool {
    return std.mem.indexOfAny(u8, value, "\r\n") == null;
}

/// Parse a "headers" object {"Name": "Value", ...} into "Name: Value"
/// lines. Malformed names/values fail the whole config load (the file is
/// machine-managed; silently dropping headers would break auth quietly).
fn parseHeaders(a: std.mem.Allocator, v: std.json.Value) ![]const []const u8 {
    const obj = switch (v) {
        .object => |o| o,
        else => return error.BadConfig,
    };
    var list: std.ArrayList([]const u8) = .empty;
    var it = obj.iterator();
    while (it.next()) |entry| {
        const name = entry.key_ptr.*;
        const value = switch (entry.value_ptr.*) {
            .string => |s| s,
            else => return error.BadConfig,
        };
        if (!validHeaderName(name) or !validHeaderValue(value)) return error.BadConfig;
        try list.append(a, try std.fmt.allocPrint(a, "{s}: {s}", .{ name, value }));
    }
    return list.toOwnedSlice(a);
}

fn parseServer(a: std.mem.Allocator, v: std.json.Value) !ServerConfig {
    const obj = switch (v) {
        .object => |o| o,
        else => return error.BadConfig,
    };
    var sc = ServerConfig{};
    if (obj.get("oauth")) |b| sc.oauth = switch (b) {
        .bool => |x| x,
        else => return error.BadConfig,
    };
    if (obj.get("client_id")) |s| sc.client_id = try strOrNull(s);
    if (obj.get("client_secret")) |s| sc.client_secret = try strOrNull(s);
    if (obj.get("scope")) |s| sc.scope = try strOrNull(s);
    if (obj.get("resource")) |s| sc.resource = try strOrNull(s);
    if (obj.get("grant")) |s| sc.grant = try strOrNull(s);
    if (obj.get("transport")) |s| sc.transport = try strOrNull(s);
    if (obj.get("headers")) |h| sc.headers = try parseHeaders(a, h);
    return sc;
}

fn strOrNull(v: std.json.Value) !?[]const u8 {
    return switch (v) {
        .string => |s| if (s.len == 0) null else s,
        .null => null,
        else => error.BadConfig,
    };
}

test "load: parse, exact + origin lookup" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "config.json", .data =
        \\{"servers":{
        \\  "https://a.example.com/mcp": {"oauth": true, "client_id": "cid", "scope": "s1", "resource": "https://t1.example.net/", "grant": "authorization_code", "transport": "sse-only"},
        \\  "https://b.example.com": {"oauth": true, "client_secret": "sec"}
        \\}}
    });
    const path = try tmp.dir.realpathAlloc(alloc, "config.json");
    defer alloc.free(path);

    var cf = (try load(alloc, path)).?;
    defer cf.deinit();

    const a = cf.lookup("https://a.example.com/mcp").?;
    try std.testing.expect(a.oauth);
    try std.testing.expectEqualStrings("cid", a.client_id.?);
    try std.testing.expect(a.client_secret == null);
    try std.testing.expectEqualStrings("https://t1.example.net/", a.resource.?);
    try std.testing.expectEqualStrings("authorization_code", a.grant.?);
    try std.testing.expectEqualStrings("sse-only", a.transport.?);

    // origin fallback
    const b = cf.lookup("https://b.example.com/other/path").?;
    try std.testing.expectEqualStrings("sec", b.client_secret.?);
    try std.testing.expect(b.resource == null);
    try std.testing.expect(b.grant == null);
    try std.testing.expect(b.transport == null);

    try std.testing.expect(cf.lookup("https://c.example.com/mcp") == null);
}

test "load: headers parse to \"Name: Value\" lines" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "config.json", .data =
        \\{"servers":{
        \\  "https://auth.example.com/mcp": {"headers": {"Authorization": "Bearer tok-123", "X-Trace": "abc"}},
        \\  "https://auth2.example.com": {"headers": {"Authorization": "Basic c2VjcmV0"}}
        \\}}
    });
    const path = try tmp.dir.realpathAlloc(alloc, "config.json");
    defer alloc.free(path);

    var cf = (try load(alloc, path)).?;
    defer cf.deinit();

    const a = cf.lookup("https://auth.example.com/mcp").?;
    try std.testing.expectEqual(@as(usize, 2), a.headers.len);
    try std.testing.expectEqualStrings("Authorization: Bearer tok-123", a.headers[0]);
    try std.testing.expectEqualStrings("X-Trace: abc", a.headers[1]);

    // Origin fallback carries headers too.
    const b = cf.lookup("https://auth2.example.com/other/path").?;
    try std.testing.expectEqual(@as(usize, 1), b.headers.len);
    try std.testing.expectEqualStrings("Authorization: Basic c2VjcmV0", b.headers[0]);

    // Default config has no headers.
    const def = ServerConfig{};
    try std.testing.expectEqual(@as(usize, 0), def.headers.len);
}

test "load: malformed headers rejected" {
    const alloc = std.testing.allocator;
    const cases = [_][]const u8{
        // not an object
        \\{"servers":{"https://x/mcp":{"headers":"Authorization: Bearer t"}}}
        ,
        // value not a string
        \\{"servers":{"https://x/mcp":{"headers":{"Authorization": 42}}}}
        ,
        // name with colon
        \\{"servers":{"https://x/mcp":{"headers":{"Bad:Name": "v"}}}}
        ,
        // value with CR/LF (header injection)
        \\{"servers":{"https://x/mcp":{"headers":{"Inject": "v\r\nSet-Cookie: x"}}}}
        ,
        // empty name
        \\{"servers":{"https://x/mcp":{"headers":{"": "v"}}}}
        ,
        // name with space
        \\{"servers":{"https://x/mcp":{"headers":{"Bad Name": "v"}}}}
    };
    for (cases) |body| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        try tmp.dir.writeFile(.{ .sub_path = "config.json", .data = body });
        const path = try tmp.dir.realpathAlloc(alloc, "config.json");
        defer alloc.free(path);
        try std.testing.expectError(error.BadConfig, load(alloc, path));
    }
}

test "headerName" {
    try std.testing.expectEqualStrings("Authorization", headerName("Authorization: Bearer t").?);
    try std.testing.expectEqualStrings("x-trace", headerName("x-trace:abc").?);
    try std.testing.expectEqualStrings("X-Spaced", headerName("X-Spaced\t : v").?);
    try std.testing.expect(headerName("no-colon") == null);
    try std.testing.expect(headerName("") == null);
}

test "mergeHeaders: CLI wins on name collision" {
    const alloc = std.testing.allocator;
    const cli = [_][]const u8{ "authorization: Bearer cli-tok", "X-Cli: 1" };
    const file = [_][]const u8{ "Authorization: Bearer file-tok", "X-Trace: abc" };
    const merged = try mergeHeaders(alloc, &cli, &file);
    defer alloc.free(merged);
    try std.testing.expectEqual(@as(usize, 3), merged.len);
    try std.testing.expectEqualStrings("authorization: Bearer cli-tok", merged[0]);
    try std.testing.expectEqualStrings("X-Cli: 1", merged[1]);
    try std.testing.expectEqualStrings("X-Trace: abc", merged[2]);

    // No collision: all entries kept, CLI first.
    const merged2 = try mergeHeaders(alloc, &.{"A: 1"}, &.{"B: 2"});
    defer alloc.free(merged2);
    try std.testing.expectEqual(@as(usize, 2), merged2.len);

    // Malformed CLI lines (no colon) never suppress file entries.
    const merged3 = try mergeHeaders(alloc, &.{"garbage"}, &.{"B: 2"});
    defer alloc.free(merged3);
    try std.testing.expectEqual(@as(usize, 2), merged3.len);
    try std.testing.expectEqualStrings("garbage", merged3[0]);
    try std.testing.expectEqualStrings("B: 2", merged3[1]);
}

test "load: missing file returns null" {
    const alloc = std.testing.allocator;
    const res = try load(alloc, "/nonexistent/mcp-bridge/config.json");
    try std.testing.expect(res == null);
}
