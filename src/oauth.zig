// OAuth 2.1 client core for MCP Streamable HTTP authorization:
// RFC 9728 protected-resource discovery, RFC 8414 AS metadata, RFC 7591
// dynamic client registration, token endpoint grants (client_credentials,
// authorization_code+PKCE, refresh_token), and a per-server token cache.
//
// Network functions are thin wrappers over platform TLS + http.zig; all
// parsing/encoding/path logic is pure and unit-tested.

const std = @import("std");
const builtin = @import("builtin");
const platform = @import("platform.zig");
const http = @import("http.zig");

const log = std.log.scoped(.oauth);

pub var verbose: bool = false;

fn vprint(comptime fmt: []const u8, args: anytype) void {
    if (verbose) std.debug.print(fmt, args);
}

pub const OAuthError = error{
    DiscoveryFailed,
    NoAuthorizationServer,
    NoTokenEndpoint,
    NoRegistrationEndpoint,
    TokenRequestFailed,
    RegistrationFailed,
    BadResponse,
    OutOfMemory,
    ConnectFailed,
    SslInitFailed,
    HandshakeFailed,
    NoRemoteCert,
    PkiValidationFailed,
    TlsClosed,
    TlsError,
    Timeout,
    WriteFailed,
    ReadFailed,
    MalformedResponse,
    ResponseTooLarge,
    SseEndedWithoutResponse,
    BadScheme,
    BadPort,
    BadHost,
    Utf16,
};

// ------------------------------------------------------------------ types --

pub const AsMetadata = struct {
    authorization_endpoint: ?[]const u8 = null,
    token_endpoint: []const u8,
    registration_endpoint: ?[]const u8 = null,
};

pub const TokenSet = struct {
    access_token: []const u8,
    refresh_token: ?[]const u8 = null,
    /// Unix time the access token expires; 0 = does not expire.
    expires_at: i64 = 0,

    pub fn isExpired(self: TokenSet, now: i64) bool {
        return self.expires_at != 0 and now >= self.expires_at;
    }
};

// ------------------------------------------------------- form/url encoding --

fn urlEncodeInto(alloc: std.mem.Allocator, out: *std.ArrayList(u8), s: []const u8) !void {
    const hex = "0123456789ABCDEF";
    for (s) |ch| {
        if (std.ascii.isAlphanumeric(ch) or ch == '-' or ch == '_' or ch == '.' or ch == '~') {
            try out.append(alloc, ch);
        } else {
            try out.append(alloc, '%');
            try out.append(alloc, hex[ch >> 4]);
            try out.append(alloc, hex[ch & 0xf]);
        }
    }
}

/// application/x-www-form-urlencoded body from key/value pairs.
pub fn formEncode(alloc: std.mem.Allocator, pairs: []const [2][]const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);
    for (pairs, 0..) |kv, i| {
        if (i > 0) try out.append(alloc, '&');
        try urlEncodeInto(alloc, &out, kv[0]);
        try out.append(alloc, '=');
        try urlEncodeInto(alloc, &out, kv[1]);
    }
    return out.toOwnedSlice(alloc);
}

// ------------------------------------------------------------ JSON parsing --

fn getStr(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const v = obj.get(key) orelse return null;
    return switch (v) {
        .string => |s| if (s.len == 0) null else s,
        else => null,
    };
}

/// Parse a token endpoint response. `now` is the current unix time; a 60s
/// clock-skew margin is subtracted from expires_in.
pub fn parseTokenResponse(alloc: std.mem.Allocator, body: []const u8, now: i64) !TokenSet {
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, body, .{});
    defer parsed.deinit();
    const obj = switch (parsed.value) {
        .object => |o| o,
        else => return OAuthError.BadResponse,
    };
    const access = getStr(obj, "access_token") orelse return OAuthError.BadResponse;
    const refresh_tok = getStr(obj, "refresh_token");

    var expires_at: i64 = 0;
    if (obj.get("expires_in")) |v| {
        const secs: i64 = switch (v) {
            .integer => |i| i,
            .float => |f| @intFromFloat(f),
            else => 0,
        };
        if (secs > 60) expires_at = now + secs - 60;
    }

    return .{
        .access_token = try alloc.dupe(u8, access),
        .refresh_token = if (refresh_tok) |r| try alloc.dupe(u8, r) else null,
        .expires_at = expires_at,
    };
}

/// Parse RFC 8414 / OIDC discovery metadata.
pub fn parseAsMetadata(alloc: std.mem.Allocator, body: []const u8) !AsMetadata {
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, body, .{});
    defer parsed.deinit();
    const obj = switch (parsed.value) {
        .object => |o| o,
        else => return OAuthError.BadResponse,
    };
    const token_ep = getStr(obj, "token_endpoint") orelse return OAuthError.NoTokenEndpoint;
    return .{
        .authorization_endpoint = if (getStr(obj, "authorization_endpoint")) |s| try alloc.dupe(u8, s) else null,
        .token_endpoint = try alloc.dupe(u8, token_ep),
        .registration_endpoint = if (getStr(obj, "registration_endpoint")) |s| try alloc.dupe(u8, s) else null,
    };
}

/// Parse RFC 9728 protected-resource metadata; returns the first
/// authorization server issuer URL (owned), or NoAuthorizationServer.
pub fn parseProtectedResource(alloc: std.mem.Allocator, body: []const u8) ![]u8 {
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, body, .{});
    defer parsed.deinit();
    const obj = switch (parsed.value) {
        .object => |o| o,
        else => return OAuthError.BadResponse,
    };
    const arr = switch (obj.get("authorization_servers") orelse return OAuthError.NoAuthorizationServer) {
        .array => |a| a,
        else => return OAuthError.BadResponse,
    };
    if (arr.items.len == 0) return OAuthError.NoAuthorizationServer;
    return switch (arr.items[0]) {
        .string => |s| if (s.len == 0) OAuthError.NoAuthorizationServer else alloc.dupe(u8, s),
        else => OAuthError.BadResponse,
    };
}

/// Extract the resource_metadata URL from a 401 WWW-Authenticate header
/// (e.g. `Bearer resource_metadata="https://.../.well-known/..."`).
pub fn parseWwwAuthenticateResourceMetadata(header: []const u8) ?[]const u8 {
    const key = "resource_metadata";
    const idx = std.ascii.indexOfIgnoreCase(header, key) orelse return null;
    var rest = header[idx + key.len ..];
    // skip whitespace and '='
    rest = std.mem.trimLeft(u8, rest, " \t");
    if (rest.len == 0 or rest[0] != '=') return null;
    rest = std.mem.trimLeft(u8, rest[1..], " \t");
    if (rest.len == 0) return null;
    if (rest[0] == '"') {
        const end = std.mem.indexOfScalarPos(u8, rest, 1, '"') orelse return null;
        return rest[1..end];
    }
    const end = std.mem.indexOfAny(u8, rest, ", \t") orelse rest.len;
    return rest[0..end];
}

// ------------------------------------------------------------- token cache --

/// Per-user token cache directory: $XDG_DATA_HOME/mcp-bridge/tokens
/// (~/.local/share fallback) on POSIX, %LOCALAPPDATA%\mcp-bridge\tokens on
/// Windows. Caller owns the returned slice.
pub fn tokensDir(alloc: std.mem.Allocator) ![]u8 {
    if (builtin.os.tag == .windows) {
        const base = std.process.getEnvVarOwned(alloc, "LOCALAPPDATA") catch return error.NoDataDir;
        defer alloc.free(base);
        return std.fs.path.join(alloc, &.{ base, "mcp-bridge", "tokens" });
    }
    if (std.process.getEnvVarOwned(alloc, "XDG_DATA_HOME")) |xdg| {
        defer alloc.free(xdg);
        if (xdg.len > 0) return std.fs.path.join(alloc, &.{ xdg, "mcp-bridge", "tokens" });
    } else |_| {}
    const home = std.process.getEnvVarOwned(alloc, "HOME") catch return error.NoDataDir;
    defer alloc.free(home);
    return std.fs.path.join(alloc, &.{ home, ".local", "share", "mcp-bridge", "tokens" });
}

/// Cache file path for a server URL: <tokens_dir>/<sha256hex>.json
pub fn tokenPath(alloc: std.mem.Allocator, server_url: []const u8) ![]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(server_url, &digest, .{});
    var hex: [64]u8 = undefined;
    const chars = "0123456789abcdef";
    for (digest, 0..) |b, i| {
        hex[i * 2] = chars[b >> 4];
        hex[i * 2 + 1] = chars[b & 0xf];
    }
    const dir = try tokensDir(alloc);
    defer alloc.free(dir);
    return std.fmt.allocPrint(alloc, "{s}" ++ std.fs.path.sep_str ++ "{s}.json", .{ dir, hex });
}

/// Load a cached token set. Returns null when absent or unparsable.
pub fn loadTokenCache(alloc: std.mem.Allocator, server_url: []const u8) !?TokenSet {
    const path = try tokenPath(alloc, server_url);
    defer alloc.free(path);
    const text = std.fs.cwd().readFileAlloc(alloc, path, 1 << 20) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer alloc.free(text);

    const parsed = std.json.parseFromSlice(std.json.Value, alloc, text, .{}) catch return null;
    defer parsed.deinit();
    const obj = switch (parsed.value) {
        .object => |o| o,
        else => return null,
    };
    const access = getStr(obj, "access_token") orelse return null;
    const refresh_tok = getStr(obj, "refresh_token");
    const expires_at: i64 = switch (obj.get("expires_at") orelse .null) {
        .integer => |i| i,
        else => 0,
    };
    return .{
        .access_token = try alloc.dupe(u8, access),
        .refresh_token = if (refresh_tok) |r| try alloc.dupe(u8, r) else null,
        .expires_at = expires_at,
    };
}

/// Persist a token set (0600, per-user dir). Contains bearer secrets.
pub fn saveTokenCache(alloc: std.mem.Allocator, server_url: []const u8, tokens: TokenSet) !void {
    const path = try tokenPath(alloc, server_url);
    defer alloc.free(path);
    if (std.fs.path.dirname(path)) |dir| std.fs.cwd().makePath(dir) catch {};

    const CacheFile = struct {
        access_token: []const u8,
        refresh_token: ?[]const u8 = null,
        expires_at: i64,
    };
    const text = try std.json.Stringify.valueAlloc(alloc, CacheFile{
        .access_token = tokens.access_token,
        .refresh_token = tokens.refresh_token,
        .expires_at = tokens.expires_at,
    }, .{});
    defer alloc.free(text);

    const file = try std.fs.cwd().createFile(path, .{ .truncate = true, .mode = 0o600 });
    defer file.close();
    // createFile mode only applies at creation; enforce on rewrite too.
    if (builtin.os.tag != .windows) try file.chmod(0o600);
    try file.writeAll(text);
}

/// Delete a server's cached tokens (--oauth-logout).
pub fn deleteTokenCache(alloc: std.mem.Allocator, server_url: []const u8) !void {
    const path = try tokenPath(alloc, server_url);
    defer alloc.free(path);
    std.fs.cwd().deleteFile(path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
}

// ---------------------------------------------------------------- transport --

/// One-shot HTTPS request to an arbitrary URL (own connection, own
/// verifier). Returns an owned http.Response.
fn request(
    alloc: std.mem.Allocator,
    method: enum { get, post_form, post_json },
    url: []const u8,
    body: ?[]const u8,
) !http.Response {
    const t = try http.parseUrl(url);
    if (!t.secure) return OAuthError.DiscoveryFailed; // OAuth requires TLS

    var verifier = try platform.Verifier.init(alloc, t.host, t.port, verbose);
    var tls = try platform.connectTls(alloc, t.host, t.port, &verifier);
    defer tls.deinit();

    return switch (method) {
        .get => try http.get(alloc, &tls, t.host, t.path, &.{}),
        .post_form => try http.postWith(alloc, &tls, t.host, t.path, body.?, "application/x-www-form-urlencoded", &.{}, null, .{}),
        .post_json => try http.postWith(alloc, &tls, t.host, t.path, body.?, "application/json", &.{}, null, .{}),
    };
}

fn getJson(alloc: std.mem.Allocator, url: []const u8) ![]u8 {
    vprint("mcp-bridge: [oauth] GET {s}\n", .{url});
    var resp = try request(alloc, .get, url, null);
    defer resp.deinit(alloc);
    if (resp.status != 200) return OAuthError.DiscoveryFailed;
    return try alloc.dupe(u8, resp.body);
}

// ------------------------------------------------------------- discovery ----

pub const Discovery = struct {
    as: AsMetadata,
    /// True when the authorization server exposes an interactive flow.
    pub fn interactive(self: Discovery) bool {
        return self.as.authorization_endpoint != null;
    }
};

/// Full discovery for an MCP server target. Starts from the 401's
/// WWW-Authenticate resource_metadata URL when present (MCP spec), else
/// falls back to <origin>/.well-known/oauth-protected-resource (RFC 9728).
pub fn discover(alloc: std.mem.Allocator, target: http.Target, www_authenticate: ?[]const u8) !Discovery {
    const origin = try target.origin(alloc);
    defer alloc.free(origin);

    // RFC 9728 protected-resource metadata
    var as_issuer: ?[]u8 = null;
    if (www_authenticate) |wa| {
        if (parseWwwAuthenticateResourceMetadata(wa)) |meta_url| {
            if (getJson(alloc, meta_url)) |body| {
                defer alloc.free(body);
                as_issuer = parseProtectedResource(alloc, body) catch null;
            } else |_| {}
        }
    }
    if (as_issuer == null) {
        const meta_url = try std.fmt.allocPrint(alloc, "{s}/.well-known/oauth-protected-resource", .{origin});
        defer alloc.free(meta_url);
        const body = getJson(alloc, meta_url) catch return OAuthError.DiscoveryFailed;
        defer alloc.free(body);
        as_issuer = try parseProtectedResource(alloc, body);
    }
    defer alloc.free(as_issuer.?);

    // RFC 8414 AS metadata (issuer may have a path component)
    const issuer = std.mem.trimRight(u8, as_issuer.?, "/");
    const as_url = try std.fmt.allocPrint(alloc, "{s}/.well-known/oauth-authorization-server", .{issuer});
    defer alloc.free(as_url);
    const as = blk: {
        const body = getJson(alloc, as_url) catch {
            // OIDC discovery fallback
            const oidc_url = try std.fmt.allocPrint(alloc, "{s}/.well-known/openid-configuration", .{issuer});
            defer alloc.free(oidc_url);
            const obody = getJson(alloc, oidc_url) catch return OAuthError.DiscoveryFailed;
            defer alloc.free(obody);
            break :blk try parseAsMetadata(alloc, obody);
        };
        defer alloc.free(body);
        break :blk try parseAsMetadata(alloc, body);
    };
    vprint("mcp-bridge: [oauth] AS token_endpoint={s}\n", .{as.token_endpoint});
    return .{ .as = as };
}

// ------------------------------------------------------------------ grants --

fn tokenRequest(alloc: std.mem.Allocator, token_endpoint: []const u8, pairs: []const [2][]const u8) !TokenSet {
    const form = try formEncode(alloc, pairs);
    defer alloc.free(form);
    vprint("mcp-bridge: [oauth] POST {s} (form)\n", .{token_endpoint});
    var resp = try request(alloc, .post_form, token_endpoint, form);
    defer resp.deinit(alloc);
    if (resp.status != 200) {
        log.err("token endpoint returned {d}: {s}", .{ resp.status, resp.body });
        return OAuthError.TokenRequestFailed;
    }
    return parseTokenResponse(alloc, resp.body, std.time.timestamp());
}

/// Client Credentials grant (headless).
pub fn clientCredentials(
    alloc: std.mem.Allocator,
    token_endpoint: []const u8,
    client_id: []const u8,
    client_secret: []const u8,
    scope: ?[]const u8,
) !TokenSet {
    var pairs: std.ArrayList([2][]const u8) = .empty;
    defer pairs.deinit(alloc);
    try pairs.append(alloc, .{ "grant_type", "client_credentials" });
    try pairs.append(alloc, .{ "client_id", client_id });
    try pairs.append(alloc, .{ "client_secret", client_secret });
    if (scope) |s| try pairs.append(alloc, .{ "scope", s });
    return tokenRequest(alloc, token_endpoint, pairs.items);
}

/// Refresh Token grant.
pub fn refresh(
    alloc: std.mem.Allocator,
    token_endpoint: []const u8,
    client_id: []const u8,
    client_secret: ?[]const u8,
    refresh_token: []const u8,
) !TokenSet {
    var pairs: std.ArrayList([2][]const u8) = .empty;
    defer pairs.deinit(alloc);
    try pairs.append(alloc, .{ "grant_type", "refresh_token" });
    try pairs.append(alloc, .{ "refresh_token", refresh_token });
    try pairs.append(alloc, .{ "client_id", client_id });
    if (client_secret) |s| try pairs.append(alloc, .{ "client_secret", s });
    return tokenRequest(alloc, token_endpoint, pairs.items);
}

/// Authorization Code + PKCE exchange.
pub fn exchangeCode(
    alloc: std.mem.Allocator,
    token_endpoint: []const u8,
    client_id: []const u8,
    code: []const u8,
    redirect_uri: []const u8,
    code_verifier: []const u8,
) !TokenSet {
    var pairs: std.ArrayList([2][]const u8) = .empty;
    defer pairs.deinit(alloc);
    try pairs.append(alloc, .{ "grant_type", "authorization_code" });
    try pairs.append(alloc, .{ "code", code });
    try pairs.append(alloc, .{ "redirect_uri", redirect_uri });
    try pairs.append(alloc, .{ "client_id", client_id });
    try pairs.append(alloc, .{ "code_verifier", code_verifier });
    return tokenRequest(alloc, token_endpoint, pairs.items);
}

/// RFC 7591 dynamic client registration (public client, loopback redirect).
pub fn registerClient(
    alloc: std.mem.Allocator,
    registration_endpoint: []const u8,
    redirect_uri: []const u8,
) ![]u8 {
    const redirect_json = try std.json.Stringify.valueAlloc(alloc, redirect_uri, .{});
    defer alloc.free(redirect_json);
    const body = try std.fmt.allocPrint(alloc,
        \\{{"client_name":"mcp-bridge","redirect_uris":[{s}],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"none"}}
    , .{redirect_json});
    defer alloc.free(body);

    vprint("mcp-bridge: [oauth] POST {s} (DCR)\n", .{registration_endpoint});
    var resp = try request(alloc, .post_json, registration_endpoint, body);
    defer resp.deinit(alloc);
    if (resp.status != 200 and resp.status != 201) {
        log.err("client registration returned {d}: {s}", .{ resp.status, resp.body });
        return OAuthError.RegistrationFailed;
    }

    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, resp.body, .{});
    defer parsed.deinit();
    const obj = switch (parsed.value) {
        .object => |o| o,
        else => return OAuthError.BadResponse,
    };
    const client_id = getStr(obj, "client_id") orelse return OAuthError.BadResponse;
    return try alloc.dupe(u8, client_id);
}
