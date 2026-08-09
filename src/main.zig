// mcp-bridge: MCP stdio <-> HTTP(S) bridge (Windows, FreeBSD, Linux).
//
// Reads newline-delimited JSON-RPC from stdin, POSTs each message to a
// remote MCP server (Streamable HTTP transport), writes each JSON response
// to stdout. TLS with DANE TLSA verification (DANE-TA/DANE-EE, no DNSSEC)
// and root-store PKI fallback when no TLSA is published. Platform backends:
// SChannel/crypt32 on Windows, OpenSSL on POSIX (see platform.zig).
//
// Usage:
//   mcp-bridge.exe <url> [--header "Name: Value"]... [--verbose]
//                        [--oauth [--oauth-scope S]] [--config PATH]
//                        [--oauth-client-id ID] [--oauth-client-secret SECRET]
//                        [--oauth-logout]
//
// Example (mcp_config.json):
//   "memory": { "command": "C:\\tools\\mcp-bridge.exe",
//               "args": ["https://mcp.example.com/mcp"] }

const std = @import("std");
const platform = @import("platform.zig");
const http = @import("http.zig");
const mcp = @import("mcp.zig");
const oauth = @import("oauth.zig");
const pkce = @import("pkce.zig");
const loopback = @import("oauth_loopback.zig");
const config_file = @import("config.zig");

const log = std.log.scoped(.bridge);

const Target = http.Target;

const OAuthCfg = struct {
    client_id: ?[]const u8 = null,
    client_secret: ?[]const u8 = null,
    scope: ?[]const u8 = null,
};

const Config = struct {
    target: Target,
    url: []const u8 = "",
    headers: std.ArrayList([]const u8) = .empty,
    verbose: bool = false,
    oauth: ?OAuthCfg = null, // non-null: OAuth enabled for this server
};

fn usage() noreturn {
    std.debug.print(
        \\usage: mcp-bridge.exe <url> [options]
        \\
        \\  url                     http(s)://host[:port]/path of the MCP server
        \\  --header "Name: Value"  extra request header (repeatable)
        \\  --verbose               diagnostics on stderr
        \\
        \\OAuth 2.1 (auto-activates on a 401 even without flags):
        \\  --oauth                 enable OAuth for this server
        \\  --oauth-client-id ID    pre-registered client id (else DCR)
        \\  --oauth-client-secret S client secret (enables headless client-credentials)
        \\  --oauth-scope S         scopes to request
        \\  --config PATH           JSON config file (default: ~/.config/mcp-bridge/config.json)
        \\  --oauth-logout          delete cached tokens for <url> and exit
        \\
    , .{});
    std.process.exit(2);
}

fn parseUrl(url: []const u8) !Target {
    return http.parseUrl(url);
}

fn readLineFromStdin(alloc: std.mem.Allocator, carry: *std.ArrayList(u8)) !?[]u8 {
    // Returns the next complete line (without \n / \r), or null on EOF.
    while (true) {
        if (std.mem.indexOfScalar(u8, carry.items, '\n')) |nl| {
            var line = carry.items[0..nl];
            if (line.len > 0 and line[line.len - 1] == '\r') line = line[0 .. line.len - 1];
            const owned = try alloc.dupe(u8, line);
            const rest = carry.items.len - (nl + 1);
            std.mem.copyForwards(u8, carry.items[0..rest], carry.items[nl + 1 ..]);
            carry.items.len = rest;
            return owned;
        }
        var tmp: [16384]u8 = undefined;
        const nread = try platform.readStdin(&tmp);
        if (nread == 0) {
            // EOF: flush any unterminated remainder
            if (carry.items.len > 0) {
                var line = carry.items;
                if (line.len > 0 and line[line.len - 1] == '\r') line = line[0 .. line.len - 1];
                const owned = try alloc.dupe(u8, line);
                carry.clearRetainingCapacity();
                return owned;
            }
            return null;
        }
        try carry.appendSlice(alloc, tmp[0..nread]);
    }
}

const writeStdout = platform.writeStdoutAll;

const Conn = union(enum) {
    tls: platform.TlsStream,
    plain: platform.PlainStream,

    fn deinit(self: *Conn) void {
        switch (self.*) {
            inline else => |*s| s.deinit(),
        }
    }
};

/// Owns the persistent upstream connection, session id, and verifier.
const Bridge = struct {
    alloc: std.mem.Allocator,
    cfg: *const Config,
    verifier: ?*platform.Verifier,
    conn: ?Conn = null,
    session_id: ?[]const u8 = null,

    // OAuth state
    tokens: ?oauth.TokenSet = null,
    tokens_loaded: bool = false,
    discovered: ?oauth.Discovery = null,

    fn deinit(self: *Bridge) void {
        self.closeConn();
        if (self.session_id) |sid| self.alloc.free(@constCast(sid));
    }

    // ------------------------------------------------------------ OAuth --

    /// Make sure we hold a usable access token. Runs discovery on first
    /// use, refreshes expired tokens, and falls back to a full grant flow
    /// (client-credentials when a secret is configured, else interactive
    /// authorization code + PKCE).
    fn ensureAuth(self: *Bridge, www_authenticate: ?[]const u8) !void {
        const alloc = self.alloc;
        const now = std.time.timestamp();

        if (!self.tokens_loaded) {
            self.tokens_loaded = true;
            self.tokens = oauth.loadTokenCache(alloc, self.cfg.url) catch null;
            if (self.tokens != null and self.cfg.verbose)
                std.debug.print("mcp-bridge: [oauth] loaded cached tokens\n", .{});
        }

        if (self.tokens) |t| {
            if (!t.isExpired(now)) return;
            // Expired: refresh once if possible
            if (t.refresh_token) |rt| {
                if (self.refreshTokens(rt)) |_| return else |err| {
                    if (self.cfg.verbose) std.debug.print("mcp-bridge: [oauth] refresh failed ({s}), full flow\n", .{@errorName(err)});
                }
            }
        } else if (www_authenticate == null and self.cfg.oauth == null) {
            return; // OAuth not configured and no 401 yet — nothing to do
        }

        try self.fullAuthFlow(www_authenticate);
    }

    /// 401 path: token rejected while still "valid". Force a refresh (once)
    /// if we have a refresh token, else run the full flow.
    fn reauthOn401(self: *Bridge, www_authenticate: ?[]const u8) !void {
        if (self.tokens) |t| {
            if (t.refresh_token) |rt| {
                if (self.refreshTokens(rt)) |_| return else |_| {}
            }
        }
        try self.fullAuthFlow(www_authenticate);
    }

    fn refreshTokens(self: *Bridge, refresh_token: []const u8) !void {
        const disc = try self.discover(null);
        const cfg = self.cfg.oauth orelse OAuthCfg{};
        const client_id = cfg.client_id orelse return oauth.OAuthError.BadResponse;
        const t = try oauth.refresh(self.alloc, disc.as.token_endpoint, client_id, cfg.client_secret, refresh_token);
        self.adoptTokens(t);
        try oauth.saveTokenCache(self.alloc, self.cfg.url, self.tokens.?);
        if (self.cfg.verbose) std.debug.print("mcp-bridge: [oauth] token refreshed\n", .{});
    }

    fn adoptTokens(self: *Bridge, t: oauth.TokenSet) void {
        self.tokens = t;
    }

    fn discover(self: *Bridge, www_authenticate: ?[]const u8) !oauth.Discovery {
        if (self.discovered) |d| return d;
        const d = try oauth.discover(self.alloc, self.cfg.target, www_authenticate);
        self.discovered = d;
        return d;
    }

    fn fullAuthFlow(self: *Bridge, www_authenticate: ?[]const u8) !void {
        const alloc = self.alloc;
        const cfg = self.cfg.oauth orelse OAuthCfg{};
        const disc = try self.discover(www_authenticate);

        // Headless: client credentials when a secret is configured
        if (cfg.client_id != null and cfg.client_secret != null) {
            const t = try oauth.clientCredentials(alloc, disc.as.token_endpoint, cfg.client_id.?, cfg.client_secret.?, cfg.scope);
            self.adoptTokens(t);
            try oauth.saveTokenCache(alloc, self.cfg.url, self.tokens.?);
            if (self.cfg.verbose) std.debug.print("mcp-bridge: [oauth] client-credentials token acquired\n", .{});
            return;
        }

        // Interactive: authorization code + PKCE with loopback redirect
        const authz_ep = disc.as.authorization_endpoint orelse {
            log.err("authorization server has no authorization_endpoint and no client credentials configured", .{});
            return oauth.OAuthError.NoAuthorizationServer;
        };

        var listener = try loopback.Listener.init(180_000);
        defer listener.deinit();
        const redirect_uri = try listener.redirectUri(alloc);
        defer alloc.free(redirect_uri);

        const client_id = cfg.client_id orelse blk: {
            const reg_ep = disc.as.registration_endpoint orelse {
                log.err("no client_id configured and AS has no registration_endpoint (DCR)", .{});
                return oauth.OAuthError.NoRegistrationEndpoint;
            };
            if (self.cfg.verbose) std.debug.print("mcp-bridge: [oauth] registering client via DCR\n", .{});
            break :blk try oauth.registerClient(alloc, reg_ep, redirect_uri);
        };
        defer if (cfg.client_id == null) alloc.free(client_id);

        const verifier = pkce.generateVerifier();
        const challenge = pkce.challengeS256(&verifier);
        var state_rand: [16]u8 = undefined;
        std.crypto.random.bytes(&state_rand);
        var state: [32]u8 = undefined;
        _ = std.fmt.bufPrint(&state, "{x}", .{state_rand}) catch unreachable;

        // Scope: configured, else the one the resource server demanded in
        // its 401 challenge (RFC 9728 / MCP spec).
        const scope = cfg.scope orelse
            if (www_authenticate) |wa| oauth.parseWwwAuthenticateScope(wa) else null;

        const auth_url = try buildAuthUrl(alloc, authz_ep, client_id, redirect_uri, &challenge, &state, scope);
        defer alloc.free(auth_url);

        std.debug.print("mcp-bridge: authorize at:\n{s}\n", .{auth_url});
        if (!loopback.openUrl(alloc, auth_url)) {
            std.debug.print(
                "mcp-bridge: could not open a browser automatically; open the URL above manually.\n" ++
                    "mcp-bridge: over ssh, forward the callback port first: ssh -L {d}:localhost:{d} <this-host>\n",
                .{ listener.port, listener.port },
            );
        }

        const code = listener.waitForCode(alloc, &state) catch |err| {
            log.err("authorization redirect failed: {s}", .{@errorName(err)});
            return err;
        };
        defer alloc.free(code);

        const t = try oauth.exchangeCode(alloc, disc.as.token_endpoint, client_id, code, redirect_uri, &verifier);
        self.adoptTokens(t);
        try oauth.saveTokenCache(alloc, self.cfg.url, self.tokens.?);
        std.debug.print("mcp-bridge: [oauth] authorization complete, token cached\n", .{});
    }

    fn buildAuthUrl(
        alloc: std.mem.Allocator,
        endpoint: []const u8,
        client_id: []const u8,
        redirect_uri: []const u8,
        challenge: []const u8,
        state: []const u8,
        scope: ?[]const u8,
    ) ![]u8 {
        var pairs: std.ArrayList([2][]const u8) = .empty;
        defer pairs.deinit(alloc);
        try pairs.append(alloc, .{ "response_type", "code" });
        try pairs.append(alloc, .{ "client_id", client_id });
        try pairs.append(alloc, .{ "redirect_uri", redirect_uri });
        try pairs.append(alloc, .{ "state", state });
        try pairs.append(alloc, .{ "code_challenge", challenge });
        try pairs.append(alloc, .{ "code_challenge_method", "S256" });
        if (scope) |s| try pairs.append(alloc, .{ "scope", s });
        const qs = try oauth.formEncode(alloc, pairs.items);
        defer alloc.free(qs);
        const sep: []const u8 = if (std.mem.indexOfScalar(u8, endpoint, '?') != null) "&" else "?";
        return std.fmt.allocPrint(alloc, "{s}{s}{s}", .{ endpoint, sep, qs });
    }

    /// Inject the bearer token header when we hold one. `auth_hdr` is owned
    /// by the caller (freed via the same defer pattern as session_hdr).
    fn authHeader(self: *Bridge, auth_hdr: *?[]const u8) !?[]const u8 {
        const t = self.tokens orelse return null;
        if (t.isExpired(std.time.timestamp())) return null;
        auth_hdr.* = try std.fmt.allocPrint(self.alloc, "Authorization: Bearer {s}", .{t.access_token});
        return auth_hdr.*.?;
    }

    fn closeConn(self: *Bridge) void {
        if (self.conn) |*c| {
            switch (c.*) {
                .tls => |*s| s.closeNotify(),
                .plain => {},
            }
            c.deinit();
            self.conn = null;
        }
    }

    fn ensureConn(self: *Bridge) !void {
        if (self.conn != null) return;
        const t = self.cfg.target;
        if (t.secure) {
            const tls = try platform.connectTls(self.alloc, t.host, t.port, self.verifier.?);
            self.conn = .{ .tls = tls };
        } else {
            const ps = try platform.PlainStream.connect(self.alloc, t.host, t.port);
            self.conn = .{ .plain = ps };
        }
        if (self.cfg.verbose) std.debug.print("mcp-bridge: connected\n", .{});
    }

    fn buildHeaders(self: *Bridge, headers: *std.ArrayList([]const u8), session_hdr: *?[]const u8, auth_hdr: *?[]const u8) !void {
        try headers.appendSlice(self.alloc, self.cfg.headers.items);
        if (try self.authHeader(auth_hdr)) |h| try headers.append(self.alloc, h);
        if (self.session_id) |sid| {
            session_hdr.* = try std.fmt.allocPrint(self.alloc, "MCP-Session-Id: {s}", .{sid});
            try headers.append(self.alloc, session_hdr.*.?);
        }
        try headers.append(self.alloc, "MCP-Protocol-Version: 2025-03-26");
    }

    /// SSE sink: server-pushed (non-matching) message payloads go straight
    /// to stdout so the client sees server-initiated notifications.
    fn ssePush(ctx: ?*anyopaque, data: []const u8) void {
        _ = ctx;
        writeStdout(data) catch {};
        writeStdout("\n") catch {};
    }

    /// POST one JSON-RPC message. Reuses the persistent connection; on
    /// failure of a PRE-EXISTING (possibly idle-stale) connection, drops it
    /// and retries exactly once on a fresh connection. A 401 triggers the
    /// OAuth flow (once) and a retry with the new token.
    fn request(self: *Bridge, line: []const u8) !http.Response {
        const t = self.cfg.target;
        var attempt: usize = 0;
        var auth_retried = false;
        while (attempt < 2) : (attempt += 1) {
            // Proactive: acquire/refresh a token when OAuth is configured.
            if (self.cfg.oauth != null) try self.ensureAuth(null);

            const reused = self.conn != null;
            try self.ensureConn();

            var headers: std.ArrayList([]const u8) = .empty;
            defer headers.deinit(self.alloc);
            var session_hdr: ?[]const u8 = null;
            defer if (session_hdr) |h| self.alloc.free(h);
            var auth_hdr: ?[]const u8 = null;
            defer if (auth_hdr) |h| self.alloc.free(h);
            try self.buildHeaders(&headers, &session_hdr, &auth_hdr);

            var resp = switch (self.conn.?) {
                inline else => |*s| http.post(self.alloc, s, t.host, t.path, line, headers.items, mcp.getRequestId(line), .{ .push = ssePush }),
            } catch |err| {
                self.closeConn();
                if (reused and attempt == 0) {
                    if (self.cfg.verbose) std.debug.print("mcp-bridge: stale connection ({s}), retrying once on fresh connection\n", .{@errorName(err)});
                    continue;
                }
                return err;
            };
            if (resp.server_closed) self.closeConn();

            if (resp.status == 401 and !auth_retried) {
                auth_retried = true;
                const wa = if (resp.www_authenticate) |h| try self.alloc.dupe(u8, h) else null;
                defer if (wa) |h| self.alloc.free(h);
                resp.deinit(self.alloc);
                if (self.cfg.verbose) std.debug.print("mcp-bridge: [oauth] 401 received, running OAuth\n", .{});
                if (self.tokens != null)
                    try self.reauthOn401(wa)
                else
                    try self.ensureAuth(wa);
                attempt = 0; // fresh retry budget with the new token
                continue;
            }
            return resp;
        }
        unreachable;
    }

    /// Best-effort session termination (DELETE) on clean shutdown.
    fn terminateSession(self: *Bridge) void {
        if (self.session_id == null) return;
        const t = self.cfg.target;
        self.closeConn();
        self.ensureConn() catch return;
        defer self.closeConn();

        var headers: std.ArrayList([]const u8) = .empty;
        defer headers.deinit(self.alloc);
        var session_hdr: ?[]const u8 = null;
        defer if (session_hdr) |h| self.alloc.free(h);
        var auth_hdr: ?[]const u8 = null;
        defer if (auth_hdr) |h| self.alloc.free(h);
        self.buildHeaders(&headers, &session_hdr, &auth_hdr) catch return;

        switch (self.conn.?) {
            inline else => |*s| http.delete(self.alloc, s, t.host, t.path, headers.items) catch {},
        }
        if (self.cfg.verbose) std.debug.print("mcp-bridge: session terminated via DELETE\n", .{});
    }
};

pub fn main() !void {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{}){};
    const alloc = gpa_state.allocator();

    const args = try std.process.argsAlloc(alloc);

    var cfg = Config{ .target = undefined };
    var url: ?[]const u8 = null;
    var oauth_flag = false;
    var oauth_client_id: ?[]const u8 = null;
    var oauth_client_secret: ?[]const u8 = null;
    var oauth_scope: ?[]const u8 = null;
    var oauth_logout = false;
    var config_path: ?[]const u8 = null;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--verbose") or std.mem.eql(u8, a, "-v")) {
            cfg.verbose = true;
        } else if (std.mem.eql(u8, a, "--header") or std.mem.eql(u8, a, "-H")) {
            i += 1;
            if (i >= args.len) usage();
            try cfg.headers.append(alloc, args[i]);
        } else if (std.mem.eql(u8, a, "--oauth")) {
            oauth_flag = true;
        } else if (std.mem.eql(u8, a, "--oauth-client-id")) {
            i += 1;
            if (i >= args.len) usage();
            oauth_client_id = args[i];
        } else if (std.mem.eql(u8, a, "--oauth-client-secret")) {
            i += 1;
            if (i >= args.len) usage();
            oauth_client_secret = args[i];
        } else if (std.mem.eql(u8, a, "--oauth-scope")) {
            i += 1;
            if (i >= args.len) usage();
            oauth_scope = args[i];
        } else if (std.mem.eql(u8, a, "--oauth-logout")) {
            oauth_logout = true;
        } else if (std.mem.eql(u8, a, "--config")) {
            i += 1;
            if (i >= args.len) usage();
            config_path = args[i];
        } else if (url == null) {
            url = a;
        } else {
            usage();
        }
    }
    cfg.target = parseUrl(url orelse usage()) catch usage();
    cfg.url = url.?;
    platform.setVerbose(cfg.verbose);
    oauth.verbose = cfg.verbose;

    // Config file (flags override file values)
    const cf_path = config_path orelse (config_file.defaultPath(alloc) catch null) orelse "";
    var cf: ?config_file.ConfigFile = if (cf_path.len > 0)
        config_file.load(alloc, cf_path) catch |err| blk: {
            log.err("config file {s}: {s}", .{ cf_path, @errorName(err) });
            break :blk null;
        }
    else
        null;
    defer if (cf) |*c| c.deinit();

    var file_sc: ?config_file.ServerConfig = null;
    if (cf) |*c| file_sc = c.lookup(cfg.url);

    if (oauth_logout) {
        try oauth.deleteTokenCache(alloc, cfg.url);
        std.debug.print("mcp-bridge: deleted cached tokens for {s}\n", .{cfg.url});
        return;
    }

    if (oauth_flag or (file_sc != null and file_sc.?.oauth)) {
        cfg.oauth = .{
            .client_id = oauth_client_id orelse if (file_sc) |sc| sc.client_id else null,
            .client_secret = oauth_client_secret orelse if (file_sc) |sc| sc.client_secret else null,
            .scope = oauth_scope orelse if (file_sc) |sc| sc.scope else null,
        };
    }

    if (cfg.verbose) {
        std.debug.print("mcp-bridge: {s}://{s}:{d}{s}\n", .{
            if (cfg.target.secure) "https" else "http",
            cfg.target.host,
            cfg.target.port,
            cfg.target.path,
        });
    }

    // Verifier (TLS only)
    var verifier: ?platform.Verifier = null;
    if (cfg.target.secure) {
        verifier = platform.Verifier.init(alloc, cfg.target.host, cfg.target.port, cfg.verbose) catch |err| {
            log.err("verifier init failed: {s}", .{@errorName(err)});
            return err;
        };
    }

    var carry: std.ArrayList(u8) = .empty;
    defer carry.deinit(alloc);

    var bridge = Bridge{
        .alloc = alloc,
        .cfg = &cfg,
        .verifier = if (verifier != null) &verifier.? else null,
    };
    defer bridge.deinit();

    // Preload a cached token so the first request doesn't eat a 401
    // (skipped when the user passed an explicit Authorization header).
    var has_auth_header = false;
    for (cfg.headers.items) |h| {
        if (std.ascii.startsWithIgnoreCase(h, "authorization:")) has_auth_header = true;
    }
    if (!has_auth_header and cfg.target.secure) {
        bridge.tokens = oauth.loadTokenCache(alloc, cfg.url) catch null;
        bridge.tokens_loaded = true;
        if (bridge.tokens != null and cfg.verbose)
            std.debug.print("mcp-bridge: [oauth] using cached token\n", .{});
    }

    while (true) {
        const maybe_line = readLineFromStdin(alloc, &carry) catch null;
        const line = maybe_line orelse break;
        defer alloc.free(line);
        if (line.len == 0) continue;

        if (cfg.verbose) std.debug.print("mcp-bridge: >> {s}\n", .{line});

        var resp = bridge.request(line) catch |err| {
            // Synthesize a JSON-RPC error so the client isn't left hanging.
            var ebuf: [512]u8 = undefined;
            const emsg = mcp.formatTransportError(&ebuf, mcp.getRequestId(line), @errorName(err));
            try writeStdout(emsg);
            try writeStdout("\n");
            continue;
        };
        defer resp.deinit(alloc);

        // Error status without a JSON-RPC body (e.g. a bare 401 page):
        // synthesize a proper JSON-RPC error instead of forwarding junk.
        if (resp.status >= 400 and std.mem.indexOf(u8, resp.body, "\"jsonrpc\"") == null) {
            var ebuf: [512]u8 = undefined;
            var msg_buf: [64]u8 = undefined;
            const msg = std.fmt.bufPrint(&msg_buf, "HTTP {d}", .{resp.status}) catch "HTTP error";
            const emsg = mcp.formatTransportError(&ebuf, mcp.getRequestId(line), msg);
            try writeStdout(emsg);
            try writeStdout("\n");
            if (cfg.verbose) std.debug.print("mcp-bridge: << {d} non-JSON-RPC body, synthesized error\n", .{resp.status});
            continue;
        }

        // Capture session id from initialize response
        if (resp.mcp_session_id) |sid| {
            const copy = try alloc.dupe(u8, sid);
            if (bridge.session_id) |old| alloc.free(@constCast(old));
            bridge.session_id = copy;
            if (cfg.verbose) std.debug.print("mcp-bridge: session {s}\n", .{sid});
        }

        if (resp.body.len > 0) {
            if (cfg.verbose) std.debug.print("mcp-bridge: << {d} {s}\n", .{ resp.status, resp.body });
            try writeStdout(resp.body);
            try writeStdout("\n");
        } else if (cfg.verbose) {
            std.debug.print("mcp-bridge: << {d} (no body)\n", .{resp.status});
        }
    }

    if (cfg.verbose) std.debug.print("mcp-bridge: stdin closed, exiting\n", .{});
    bridge.terminateSession();
}
