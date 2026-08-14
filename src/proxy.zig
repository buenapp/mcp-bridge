// HTTP(S) proxy support via --enable-proxy (mcp-remote / undici
// EnvHttpProxyAgent parity): the proxy comes from the environment.
//
//   HTTPS targets: tunnel through the proxy with CONNECT (see httpc.zig's
//                  proxy_tunnel state); TLS + DANE/PKI verification still
//                  run end-to-end against the ORIGIN.
//   HTTP targets:  absolute-form requests (the request line carries the
//                  full origin URL); no tunnel.
//   NO_PROXY:      comma-separated bypass list — exact host, suffix match
//                  (".example.com" or "example.com" both cover subdomains),
//                  optional :port, "*" for everything. Case-insensitive.
//
// Env vars (curl convention): https targets read https_proxy/HTTPS_PROXY;
// plain http targets read http_proxy/HTTP_PROXY; bypass from
// no_proxy/NO_PROXY. Proxy URLs must be http://[user[:pass]@]host[:port]
// (https proxies are rejected — TLS-to-proxy is out of scope).

const std = @import("std");
const http = @import("http.zig");
const ulog = @import("ulog.zig");

const log = std.log.scoped(.proxy);

pub const Endpoint = struct {
    host: []const u8,
    port: u16,
    /// Proxy-Authorization header value ("Basic <base64(user:pass)>").
    auth: ?[]const u8 = null,
};

/// Set by --enable-proxy (initFromEnv). All config below is process-global
/// and immutable after startup.
pub var enabled = false;

var https_ep: ?Endpoint = null;
var http_ep: ?Endpoint = null;
var no_proxy: [][]const u8 = &.{};

/// Read the proxy environment. Invalid proxy URLs are logged and ignored
/// (a bridge that cannot start is worse than one that connects directly).
pub fn initFromEnv(alloc: std.mem.Allocator) void {
    enabled = true;
    if (envOwned(alloc, "https_proxy") orelse envOwned(alloc, "HTTPS_PROXY")) |u| {
        https_ep = parseProxyUrl(alloc, u) catch |err| blk: {
            log.err("ignoring invalid https_proxy '{s}': {s}", .{ u, @errorName(err) });
            break :blk null;
        };
    }
    if (envOwned(alloc, "http_proxy") orelse envOwned(alloc, "HTTP_PROXY")) |u| {
        http_ep = parseProxyUrl(alloc, u) catch |err| blk: {
            log.err("ignoring invalid http_proxy '{s}': {s}", .{ u, @errorName(err) });
            break :blk null;
        };
    }
    if (envOwned(alloc, "no_proxy") orelse envOwned(alloc, "NO_PROXY")) |v| {
        no_proxy = parseNoProxy(alloc, v) catch &.{};
    }
    if (ulog.verbose) {
        if (https_ep) |p| ulog.vprint("mcp-bridge: [proxy] https via {s}:{d}\n", .{ p.host, p.port });
        if (http_ep) |p| ulog.vprint("mcp-bridge: [proxy] http via {s}:{d}\n", .{ p.host, p.port });
        if (https_ep == null and http_ep == null)
            ulog.vprint("mcp-bridge: [proxy] --enable-proxy but no *_proxy env var set\n", .{});
    }
}

/// The proxy for a target, or null (direct). Null when disabled, when no
/// scheme-matching proxy is configured, or when NO_PROXY bypasses it.
pub fn forTarget(t: http.Target) ?Endpoint {
    if (!enabled) return null;
    if (bypassed(t.host, t.port)) return null;
    return if (t.secure) https_ep else http_ep;
}

/// Test hook: pin the endpoint for a target's scheme (null clears it) and
/// reset the bypass list.
pub fn setForTest(t: http.Target, ep: ?Endpoint) void {
    no_proxy = &.{};
    if (t.secure) https_ep = ep else http_ep = ep;
}

/// NO_PROXY matching (curl semantics).
pub fn bypassed(host: []const u8, port: u16) bool {
    for (no_proxy) |entry0| {
        var e = std.mem.trim(u8, entry0, " \t");
        if (e.len == 0) continue;
        if (std.mem.eql(u8, e, "*")) return true;
        // Leading "*" (e.g. *.corp.example): strip to a suffix match.
        if (e[0] == '*') e = e[1..];
        // Optional :port suffix.
        if (std.mem.lastIndexOfScalar(u8, e, ':')) |ci| {
            if (std.fmt.parseInt(u16, e[ci + 1 ..], 10) catch null) |p| {
                if (p != port) continue;
                e = e[0..ci];
            }
        }
        if (e.len == 0) continue;
        if (e[0] == '.') e = e[1..];
        if (e.len == 0) continue;
        if (std.ascii.eqlIgnoreCase(host, e)) return true;
        // Suffix match on a label boundary.
        if (host.len > e.len and
            std.ascii.eqlIgnoreCase(host[host.len - e.len ..], e) and
            host[host.len - e.len - 1] == '.') return true;
    }
    return false;
}

/// http://[user[:pass]@]host[:port] — default port 8080. IPv6 literals are
/// not supported (proxies are hostnames in practice).
pub fn parseProxyUrl(alloc: std.mem.Allocator, url: []const u8) !Endpoint {
    var rest = url;
    if (std.mem.startsWith(u8, rest, "http://")) {
        rest = rest["http://".len..];
    } else if (std.mem.startsWith(u8, rest, "https://")) {
        return error.ProxySchemeUnsupported;
    } else return error.BadProxyUrl;

    // Drop any path component ("/" or query).
    if (std.mem.indexOfAny(u8, rest, "/?")) |i| rest = rest[0..i];

    var auth: ?[]const u8 = null;
    if (std.mem.lastIndexOfScalar(u8, rest, '@')) |at| {
        const userinfo = rest[0..at];
        rest = rest[at + 1 ..];
        if (userinfo.len > 0) {
            const b64_len = std.base64.standard.Encoder.calcSize(userinfo.len);
            const out = try alloc.alloc(u8, "Basic ".len + b64_len);
            @memcpy(out[0.."Basic ".len], "Basic ");
            _ = std.base64.standard.Encoder.encode(out["Basic ".len..], userinfo);
            auth = out;
        }
    }
    if (rest.len == 0) return error.BadProxyUrl;

    var host = rest;
    var port: u16 = 8080;
    if (std.mem.lastIndexOfScalar(u8, rest, ':')) |ci| {
        host = rest[0..ci];
        port = std.fmt.parseInt(u16, rest[ci + 1 ..], 10) catch return error.BadProxyUrl;
    }
    if (host.len == 0) return error.BadProxyUrl;
    return .{ .host = host, .port = port, .auth = auth };
}

fn parseNoProxy(alloc: std.mem.Allocator, value: []const u8) ![][]const u8 {
    var list: std.ArrayList([]const u8) = .empty;
    var it = std.mem.splitScalar(u8, value, ',');
    while (it.next()) |entry| {
        const e = std.mem.trim(u8, entry, " \t");
        if (e.len > 0) try list.append(alloc, e);
    }
    return list.toOwnedSlice(alloc);
}

fn envOwned(alloc: std.mem.Allocator, name: []const u8) ?[]const u8 {
    const v = std.process.getEnvVarOwned(alloc, name) catch return null;
    if (v.len == 0) {
        alloc.free(v);
        return null;
    }
    return v;
}

// ------------------------------------------------------------------ tests --

test "parseProxyUrl: host/port/auth/scheme" {
    const alloc = std.testing.allocator;

    const a = try parseProxyUrl(alloc, "http://proxy.local");
    try std.testing.expectEqualStrings("proxy.local", a.host);
    try std.testing.expectEqual(@as(u16, 8080), a.port);
    try std.testing.expect(a.auth == null);

    const b = try parseProxyUrl(alloc, "http://user:pass@proxy.local:3128");
    try std.testing.expectEqualStrings("proxy.local", b.host);
    try std.testing.expectEqual(@as(u16, 3128), b.port);
    try std.testing.expectEqualStrings("Basic dXNlcjpwYXNz", b.auth.?);
    alloc.free(b.auth.?);

    const c = try parseProxyUrl(alloc, "http://user@proxy.local:8080/");
    try std.testing.expectEqualStrings("Basic dXNlcg==", c.auth.?);
    alloc.free(c.auth.?);

    try std.testing.expectError(error.ProxySchemeUnsupported, parseProxyUrl(alloc, "https://proxy.local"));
    try std.testing.expectError(error.BadProxyUrl, parseProxyUrl(alloc, "proxy.local:3128"));
    try std.testing.expectError(error.BadProxyUrl, parseProxyUrl(alloc, "http://"));
    try std.testing.expectError(error.BadProxyUrl, parseProxyUrl(alloc, "http://proxy.local:notaport"));
}

test "no_proxy bypass: exact, suffix, dot, port, star, case" {
    const alloc = std.testing.allocator;
    const rules = parseNoProxy(alloc, "internal.local, .corp.example, host.other:8443, *.wild.example") catch unreachable;
    defer alloc.free(rules);
    no_proxy = rules;
    defer no_proxy = &.{};

    try std.testing.expect(bypassed("internal.local", 443));
    try std.testing.expect(bypassed("INTERNAL.LOCAL", 443)); // case-insensitive
    try std.testing.expect(bypassed("app.corp.example", 443)); // leading-dot suffix
    try std.testing.expect(bypassed("corp.example", 443)); // the bare domain too
    try std.testing.expect(!bypassed("notcorp.example", 443)); // label boundary
    try std.testing.expect(bypassed("host.other", 8443)); // port-specific
    try std.testing.expect(!bypassed("host.other", 443));
    try std.testing.expect(bypassed("x.wild.example", 443));
    try std.testing.expect(bypassed("wild.example", 443)); // curl: *. covers the bare domain too
    try std.testing.expect(!bypassed("elsewhere.net", 443));

    const star = parseNoProxy(alloc, "*") catch unreachable;
    defer alloc.free(star);
    no_proxy = star;
    try std.testing.expect(bypassed("anything.example", 1));
    no_proxy = &.{};
    try std.testing.expect(!bypassed("anything.example", 1));
}

test "forTarget: scheme split + bypass" {
    const alloc = std.testing.allocator;
    enabled = true;
    defer enabled = false;
    https_ep = .{ .host = "secure-proxy", .port = 3128 };
    defer https_ep = null;
    const rules = parseNoProxy(alloc, "local.test") catch unreachable;
    defer alloc.free(rules);
    no_proxy = rules;
    defer no_proxy = &.{};

    const https_t = http.Target{ .secure = true, .host = "api.example", .port = 443, .path = "/mcp" };
    try std.testing.expectEqualStrings("secure-proxy", forTarget(https_t).?.host);
    const bypassed_t = http.Target{ .secure = true, .host = "local.test", .port = 443, .path = "/" };
    try std.testing.expect(forTarget(bypassed_t) == null);
    const http_t = http.Target{ .secure = false, .host = "api.example", .port = 80, .path = "/" };
    try std.testing.expect(forTarget(http_t) == null); // no http proxy configured

    enabled = false;
    try std.testing.expect(forTarget(https_t) == null);
    enabled = true;
}
