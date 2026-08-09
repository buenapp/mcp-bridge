// Host-side unit tests for platform-independent modules.

const std = @import("std");
const dane = @import("dane.zig");
const mcp = @import("mcp.zig");
const pkce = @import("pkce.zig");
const oauth = @import("oauth.zig");
const config = @import("config.zig");

comptime {
    _ = pkce;
    _ = config;
}

fn spkiStub(alloc: std.mem.Allocator, cert_der: []const u8) anyerror![]u8 {
    _ = alloc;
    _ = cert_der;
    return error.Unsupported;
}

test "getRequestId: numeric, string, absent" {
    try std.testing.expectEqualStrings("7", mcp.getRequestId("{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"ping\"}").?);
    try std.testing.expectEqualStrings("\"abc\"", mcp.getRequestId("{\"id\": \"abc\" , \"method\":\"x\"}").?);
    try std.testing.expect(mcp.getRequestId("{\"method\":\"notifications/initialized\"}") == null);
}

test "formatTransportError" {
    var buf: [512]u8 = undefined;
    const s = mcp.formatTransportError(&buf, "3", "ConnectFailed");
    try std.testing.expect(std.mem.indexOf(u8, s, "\"id\":3") != null);
    try std.testing.expect(std.mem.indexOf(u8, s, "ConnectFailed") != null);
}

test "dane: DANE-EE full cert match" {
    const cert = "fake-der-bytes";
    const recs = [_]dane.TlsaRecord{.{ .usage = 3, .selector = 0, .matching_type = 0, .data = cert }};
    const chain = [_][]const u8{cert};
    try std.testing.expectEqual(dane.DaneResult.success, dane.verifyTlsaRecords(&recs, &chain, spkiStub, std.testing.allocator));
}

test "dane: DANE-EE sha256 match" {
    const cert = "fake-der-bytes";
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(cert, &digest, .{});
    const recs = [_]dane.TlsaRecord{.{ .usage = 3, .selector = 0, .matching_type = 1, .data = &digest }};
    const chain = [_][]const u8{cert};
    try std.testing.expectEqual(dane.DaneResult.success, dane.verifyTlsaRecords(&recs, &chain, spkiStub, std.testing.allocator));
}

test "dane: DANE-EE mismatch fails" {
    const recs = [_]dane.TlsaRecord{.{ .usage = 3, .selector = 0, .matching_type = 0, .data = "other" }};
    const chain = [_][]const u8{"fake-der-bytes"};
    try std.testing.expectEqual(dane.DaneResult.validation_failed, dane.verifyTlsaRecords(&recs, &chain, spkiStub, std.testing.allocator));
}

test "dane: DANE-TA walks chain, skips EE" {
    const ee = "leaf-cert";
    const inter = "intermediate-ca";
    // TA record matches the intermediate
    const recs = [_]dane.TlsaRecord{.{ .usage = 2, .selector = 0, .matching_type = 0, .data = inter }};
    const chain = [_][]const u8{ ee, inter };
    try std.testing.expectEqual(dane.DaneResult.success, dane.verifyTlsaRecords(&recs, &chain, spkiStub, std.testing.allocator));

    // TA record matching only the EE must NOT pass with a 2-cert chain
    const recs_ee = [_]dane.TlsaRecord{.{ .usage = 2, .selector = 0, .matching_type = 0, .data = ee }};
    try std.testing.expectEqual(dane.DaneResult.validation_failed, dane.verifyTlsaRecords(&recs_ee, &chain, spkiStub, std.testing.allocator));

    // Single-cert chain: TA matches EE (Bloom single-cert case)
    const single = [_][]const u8{ee};
    try std.testing.expectEqual(dane.DaneResult.success, dane.verifyTlsaRecords(&recs_ee, &single, spkiStub, std.testing.allocator));
}

test "dane: no records / empty chain" {
    const recs = [_]dane.TlsaRecord{};
    const chain = [_][]const u8{"x"};
    try std.testing.expectEqual(dane.DaneResult.no_tlsa_records, dane.verifyTlsaRecords(&recs, &chain, spkiStub, std.testing.allocator));

    const recs2 = [_]dane.TlsaRecord{.{ .usage = 3, .selector = 0, .matching_type = 0, .data = "x" }};
    const empty_chain = [_][]const u8{};
    try std.testing.expectEqual(dane.DaneResult.validation_failed, dane.verifyTlsaRecords(&recs2, &empty_chain, spkiStub, std.testing.allocator));
}

test "dane: invalid params skipped" {
    const cert = "c";
    const recs = [_]dane.TlsaRecord{.{ .usage = 9, .selector = 0, .matching_type = 0, .data = cert }};
    const chain = [_][]const u8{cert};
    try std.testing.expectEqual(dane.DaneResult.validation_failed, dane.verifyTlsaRecords(&recs, &chain, spkiStub, std.testing.allocator));
}

// ------------------------------------------------------------- oauth ------

test "oauth: formEncode escapes and joins" {
    const alloc = std.testing.allocator;
    const pairs = [_][2][]const u8{
        .{ "grant_type", "client_credentials" },
        .{ "client_secret", "a b+c/d=e" },
    };
    const form = try oauth.formEncode(alloc, &pairs);
    defer alloc.free(form);
    try std.testing.expectEqualStrings("grant_type=client_credentials&client_secret=a%20b%2Bc%2Fd%3De", form);
}

test "oauth: parseTokenResponse full + minimal" {
    const alloc = std.testing.allocator;
    const now: i64 = 1_000_000;
    var ts = try oauth.parseTokenResponse(alloc,
        \\{"access_token":"at","refresh_token":"rt","expires_in":3600,"token_type":"Bearer"}
    , now);
    defer alloc.free(ts.access_token);
    defer if (ts.refresh_token) |r| alloc.free(r);
    try std.testing.expectEqualStrings("at", ts.access_token);
    try std.testing.expectEqualStrings("rt", ts.refresh_token.?);
    try std.testing.expectEqual(now + 3540, ts.expires_at); // 60s skew margin
    try std.testing.expect(!ts.isExpired(now));
    try std.testing.expect(ts.isExpired(now + 3600));

    var ts2 = try oauth.parseTokenResponse(alloc, "{\"access_token\":\"x\"}", now);
    defer alloc.free(ts2.access_token);
    try std.testing.expect(ts2.refresh_token == null);
    try std.testing.expectEqual(@as(i64, 0), ts2.expires_at);
    try std.testing.expect(!ts2.isExpired(now + 999_999_999));

    try std.testing.expectError(error.BadResponse, oauth.parseTokenResponse(alloc, "{\"nope\":1}", now));
}

test "oauth: parseAsMetadata" {
    const alloc = std.testing.allocator;
    const md = try oauth.parseAsMetadata(alloc,
        \\{"issuer":"https://as.example.com","authorization_endpoint":"https://as.example.com/auth","token_endpoint":"https://as.example.com/token","registration_endpoint":"https://as.example.com/register"}
    );
    defer alloc.free(md.token_endpoint);
    defer if (md.authorization_endpoint) |s| alloc.free(s);
    defer if (md.registration_endpoint) |s| alloc.free(s);
    try std.testing.expectEqualStrings("https://as.example.com/token", md.token_endpoint);
    try std.testing.expectEqualStrings("https://as.example.com/auth", md.authorization_endpoint.?);
    try std.testing.expectEqualStrings("https://as.example.com/register", md.registration_endpoint.?);

    try std.testing.expectError(error.NoTokenEndpoint, oauth.parseAsMetadata(alloc, "{\"issuer\":\"x\"}"));
}

test "oauth: parseProtectedResource" {
    const alloc = std.testing.allocator;
    const as = try oauth.parseProtectedResource(alloc,
        \\{"resource":"https://mcp.example.com/mcp","authorization_servers":["https://as.example.com","https://backup.example.com"]}
    );
    defer alloc.free(as);
    try std.testing.expectEqualStrings("https://as.example.com", as);

    try std.testing.expectError(error.NoAuthorizationServer, oauth.parseProtectedResource(alloc, "{\"resource\":\"x\"}"));
}

test "oauth: parseWwwAuthenticateResourceMetadata" {
    const wa = "Bearer resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource\"";
    try std.testing.expectEqualStrings(
        "https://mcp.example.com/.well-known/oauth-protected-resource",
        oauth.parseWwwAuthenticateResourceMetadata(wa).?,
    );
    try std.testing.expect(oauth.parseWwwAuthenticateResourceMetadata("Bearer realm=\"x\"") == null);
    // unquoted + comma-terminated
    const wa2 = "Bearer resource_metadata=https://x.example.com/meta, other=1";
    try std.testing.expectEqualStrings("https://x.example.com/meta", oauth.parseWwwAuthenticateResourceMetadata(wa2).?);
}

extern "c" fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;
extern "c" fn unsetenv(name: [*:0]const u8) c_int;

test "oauth: token cache roundtrip + 0600 perms" {
    if (@import("builtin").os.tag == .windows) return; // env override is POSIX-only here

    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try tmp.dir.realpathAlloc(alloc, ".");
    defer alloc.free(base);
    const base_z = try alloc.dupeZ(u8, base);
    defer alloc.free(base_z);

    // Point the cache at the tmp dir via XDG_DATA_HOME
    const prev = std.posix.getenv("XDG_DATA_HOME");
    const prev_z: ?[:0]u8 = if (prev) |p| try alloc.dupeZ(u8, p) else null;
    defer if (prev_z) |pz| {
        defer alloc.free(pz);
        _ = setenv("XDG_DATA_HOME", pz.ptr, 1);
    } else {
        _ = unsetenv("XDG_DATA_HOME");
    };
    _ = setenv("XDG_DATA_HOME", base_z.ptr, 1);

    const url = "https://a.example.com/mcp";
    const ts = oauth.TokenSet{ .access_token = "secret-at", .refresh_token = "secret-rt", .expires_at = 12345 };
    try oauth.saveTokenCache(alloc, url, ts);

    // Key stability
    const p1 = try oauth.tokenPath(alloc, url);
    defer alloc.free(p1);
    const p3 = try oauth.tokenPath(alloc, "https://b.example.com/mcp");
    defer alloc.free(p3);
    try std.testing.expect(!std.mem.eql(u8, p1, p3));
    try std.testing.expect(std.mem.endsWith(u8, p1, ".json"));

    // 0600 perms
    const st = try std.fs.cwd().statFile(p1);
    try std.testing.expectEqual(@as(u32, 0o600), @as(u32, @intCast(st.mode & 0o777)));

    // Roundtrip
    const loaded = (try oauth.loadTokenCache(alloc, url)).?;
    defer alloc.free(loaded.access_token);
    defer if (loaded.refresh_token) |r| alloc.free(r);
    try std.testing.expectEqualStrings("secret-at", loaded.access_token);
    try std.testing.expectEqualStrings("secret-rt", loaded.refresh_token.?);
    try std.testing.expectEqual(@as(i64, 12345), loaded.expires_at);

    // Delete
    try oauth.deleteTokenCache(alloc, url);
    try std.testing.expect((try oauth.loadTokenCache(alloc, url)) == null);
}
