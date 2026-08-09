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
//       "transport": "sse-only"                    // optional: http-first|http-only|sse-first|sse-only
//     }
//   }
// }

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
};

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
        const sc = try parseServer(entry.value_ptr.*);
        try cf.servers.put(a, try a.dupe(u8, entry.key_ptr.*), sc);
    }
    return cf;
}

fn parseServer(v: std.json.Value) !ServerConfig {
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

test "load: missing file returns null" {
    const alloc = std.testing.allocator;
    const res = try load(alloc, "/nonexistent/mcp-bridge/config.json");
    try std.testing.expect(res == null);
}
