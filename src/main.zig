// mcp-bridge: MCP stdio <-> HTTP(S) bridge (Windows, FreeBSD, Linux).
//
// Reads newline-delimited JSON-RPC from stdin and forwards it to a remote
// MCP server. Transports: Streamable HTTP (2025-03-26, POST to a single
// endpoint, plus the standalone GET stream for server-initiated messages)
// and the legacy HTTP+SSE transport (2024-11-05: GET event stream +
// per-session POST endpoint, pump-thread driven). TLS with DANE TLSA
// verification (DANE-TA/DANE-EE, no DNSSEC) and root-store PKI fallback
// when no TLSA is published. Platform backends: SChannel/crypt32 on
// Windows, OpenSSL on POSIX (see platform.zig).
//
// Usage:
//   mcp-bridge.exe <url> [--header "Name: Value"]... [--verbose]
//                        [--transport http-first|http-only|sse-first|sse-only]
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
const sse = @import("sse.zig");
const oauth = @import("oauth.zig");
const pkce = @import("pkce.zig");
const loopback = @import("oauth_loopback.zig");
const config_file = @import("config.zig");

const log = std.log.scoped(.bridge);

const Target = http.Target;

/// CLI/config transport strategy (mcp-remote parity). The resolved
/// per-session transport is TransportMode.
pub const TransportStrategy = enum {
    http_first, // default: Streamable HTTP, fall back to legacy SSE on 404/405
    http_only,
    sse_first, // probe GET SSE first, fall back to Streamable HTTP on 404/405
    sse_only,

    pub fn parse(s: []const u8) ?TransportStrategy {
        if (std.mem.eql(u8, s, "http-first")) return .http_first;
        if (std.mem.eql(u8, s, "http-only")) return .http_only;
        if (std.mem.eql(u8, s, "sse-first")) return .sse_first;
        if (std.mem.eql(u8, s, "sse-only")) return .sse_only;
        return null;
    }
};

/// The transport actually in use for the session.
const TransportMode = enum { streamable, legacy };

/// Serialized writes to the bridge's message sink (stdout in production;
/// captured in tests). Pump threads and the main thread both write.
pub const Out = struct {
    ctx: *anyopaque,
    mutex: *std.Thread.Mutex,
    writeFn: *const fn (ctx: *anyopaque, bytes: []const u8) void,

    pub fn write(self: *const Out, bytes: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.writeFn(self.ctx, bytes);
    }

    /// One JSON-RPC message per line.
    pub fn writeLine(self: *const Out, bytes: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.writeFn(self.ctx, bytes);
        self.writeFn(self.ctx, "\n");
    }
};

var stdout_mutex: std.Thread.Mutex = .{};

fn stdoutWrite(_: *anyopaque, bytes: []const u8) void {
    platform.writeStdoutAll(bytes) catch {};
}

var stdout_sink_ctx: u8 = 0;

pub fn stdoutOut() Out {
    return .{ .ctx = &stdout_sink_ctx, .mutex = &stdout_mutex, .writeFn = stdoutWrite };
}

pub const OAuthCfg = struct {
    client_id: ?[]const u8 = null,
    client_secret: ?[]const u8 = null,
    scope: ?[]const u8 = null,
    /// Explicit RFC 8707 resource indicator (--resource). When null the
    /// server URL is sent as the resource but the token cache stays keyed
    /// by URL alone (preserving pre-resource cache files).
    resource: ?[]const u8 = null,
    grant: Grant = .auto,
};

pub const Grant = enum { auto, authorization_code, client_credentials };

pub const Config = struct {
    target: Target,
    url: []const u8 = "",
    headers: std.ArrayList([]const u8) = .empty,
    verbose: bool = false,
    oauth: ?OAuthCfg = null, // non-null: OAuth enabled for this server
    transport: TransportStrategy = .http_first,
};

fn usage() noreturn {
    std.debug.print(
        \\usage: mcp-bridge.exe <url> [options]
        \\
        \\  url                     http(s)://host[:port]/path of the MCP server
        \\  --header "Name: Value"  extra request header (repeatable)
        \\  --transport T           http-first (default) | http-only | sse-first | sse-only
        \\  --verbose               diagnostics on stderr
        \\
        \\OAuth 2.1 (auto-activates on a 401 even without flags):
        \\  --oauth                 enable OAuth for this server
        \\  --oauth-client-id ID    pre-registered client id (else DCR)
        \\  --oauth-client-secret S client secret (enables headless client-credentials)
        \\  --oauth-scope S         scopes to request
        \\  --oauth-grant G         authorization_code | client_credentials (default: auto)
        \\  --resource URI          RFC 8707 resource indicator (default: the server URL)
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
pub const Bridge = struct {
    alloc: std.mem.Allocator,
    cfg: *const Config,
    verifier: ?*platform.Verifier,
    conn: ?Conn = null,
    session_id: ?[]const u8 = null,
    out: Out,

    // Resolved transport (strategy probing may switch once)
    mode: TransportMode = .streamable,
    probed: bool = false, // strategy probing has run

    // Legacy HTTP+SSE transport state
    leg: ?LegacyState = null,

    // Streamable HTTP standalone GET push stream
    push: PushState = .{},

    // OAuth state
    tokens: ?oauth.TokenSet = null,
    tokens_loaded: bool = false,
    discovered: ?oauth.Discovery = null,

    pub fn deinit(self: *Bridge) void {
        self.stopLegacy();
        self.stopPush();
        self.closeConn();
        if (self.session_id) |sid| self.alloc.free(@constCast(sid));
        if (self.leg) |*l| l.deinit(self.alloc);
        self.push.deinit(self.alloc);
    }

    // ------------------------------------------------- legacy SSE (2024-11-05) --

    /// Connection + open event stream handed to a pump thread. The pump
    /// owns and frees it; the owning state keeps a raw pointer to the
    /// conn (under the state mutex) purely so stopXxx can forceShutdown
    /// the socket and unblock the pump's read.
    const PumpHandoff = struct {
        conn: Conn,
        stream: http.SseStream,
    };

    /// Legacy HTTP+SSE transport: a long-lived GET event stream carries
    /// server->client JSON-RPC; client->server messages are POSTed to a
    /// per-session endpoint URL delivered by the stream's `endpoint`
    /// event. A pump thread owns the GET connection so server-pushed
    /// messages flow even while the main thread is idle on stdin;
    /// responses to POSTed requests are correlated by id.
    const LegacyState = struct {
        /// GET stream conn while the pump runs (points into the pump's
        /// handoff; forceShutdown only). Null otherwise.
        conn: ?*Conn = null,
        pump_thread: ?std.Thread = null,
        stop: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
        mutex: std.Thread.Mutex = .{},
        cond: std.Thread.Condition = .{}, // signals: endpoint ready, dead
        endpoint: ?Target = null, // slices point into endpoint_url
        endpoint_url: ?[]u8 = null, // owned absolute URL
        /// Outstanding request ids (raw JSON) awaiting a stream response.
        pending: std.StringHashMapUnmanaged(void) = .empty,
        last_event_id: ?[]u8 = null, // Last-Event-ID resumability
        ready: bool = false, // endpoint event received
        dead: bool = false, // stream dropped; reconnect on next send
        /// Incremented per (re)start; endpoint/dead are tagged with the
        /// generation that produced them so a fast stream death can't
        /// race the readiness wait.
        generation: u64 = 0,
        endpoint_gen: u64 = 0,
        dead_gen: u64 = 0,

        fn deinit(self: *LegacyState, alloc: std.mem.Allocator) void {
            if (self.endpoint_url) |u| alloc.free(u);
            if (self.last_event_id) |i| alloc.free(i);
            var it = self.pending.keyIterator();
            while (it.next()) |k| alloc.free(k.*);
            self.pending.deinit(alloc);
        }
    };

    /// Streamable HTTP standalone GET stream (server-initiated messages).
    const PushState = struct {
        conn: ?*Conn = null, // same handoff pattern as LegacyState.conn
        thread: ?std.Thread = null,
        stop: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
        mutex: std.Thread.Mutex = .{},
        dead: bool = false,
        unsupported: bool = false, // server answered 404/405: never retry
        retried: bool = false, // one post-death restart allowed
        last_event_id: ?[]u8 = null,

        fn deinit(self: *PushState, alloc: std.mem.Allocator) void {
            if (self.last_event_id) |i| alloc.free(i);
        }
    };

    /// Extra headers every upstream request carries: configured custom
    /// headers + bearer token snapshot. The auth header backing is
    /// caller-owned (auth_hdr out-param).
    fn commonHeaders(self: *Bridge, headers: *std.ArrayList([]const u8), auth_hdr: *?[]const u8) !void {
        try headers.appendSlice(self.alloc, self.cfg.headers.items);
        if (try self.authHeader(auth_hdr)) |h| try headers.append(self.alloc, h);
    }

    fn connectTarget(self: *Bridge, t: Target) !Conn {
        if (t.secure) {
            if (self.verifier) |v| {
                if (std.mem.eql(u8, v.host, t.host) and v.port == t.port) {
                    return .{ .tls = try platform.connectTls(self.alloc, t.host, t.port, v) };
                }
            }
            // Endpoint on a different origin: dedicated stack verifier
            // (verification happens synchronously inside connectTls).
            var pv = try platform.Verifier.init(self.alloc, t.host, t.port, self.cfg.verbose);
            return .{ .tls = try platform.connectTls(self.alloc, t.host, t.port, &pv) };
        }
        return .{ .plain = try platform.PlainStream.connect(self.alloc, t.host, t.port) };
    }

    /// Build headers for a GET event stream: custom + auth + optional
    /// Last-Event-ID resume token. Extra owned headers must be freed by
    /// the caller via freeHeaderList.
    fn streamHeaders(self: *Bridge, last_event_id: ?[]const u8, headers: *std.ArrayList([]const u8), owned: *std.ArrayList([]const u8)) !void {
        var auth_hdr: ?[]const u8 = null;
        try self.commonHeaders(headers, &auth_hdr);
        if (auth_hdr) |h| try owned.append(self.alloc, h);
        if (last_event_id) |lei| {
            const h = try std.fmt.allocPrint(self.alloc, "Last-Event-ID: {s}", .{lei});
            try headers.append(self.alloc, h);
            try owned.append(self.alloc, h);
        }
    }

    fn freeHeaderList(self: *Bridge, headers: *std.ArrayList([]const u8), owned: *std.ArrayList([]const u8)) void {
        for (owned.items) |h| self.alloc.free(@constCast(h));
        owned.deinit(self.alloc);
        headers.deinit(self.alloc);
    }

    /// Open a GET event stream against `target` with OAuth handling:
    /// proactive auth when configured, one 401-driven re-auth + retry.
    /// The returned handoff (connection + header-read stream) is owned by
    /// the caller. status 404/405 surfaces as error.NoSseEndpoint to
    /// drive transport fallback.
    fn openEventStream(self: *Bridge, target: Target, last_event_id: ?[]const u8) !*PumpHandoff {
        var auth_retried = false;
        var last_status: u16 = 0;
        while (true) {
            var headers: std.ArrayList([]const u8) = .empty;
            var owned: std.ArrayList([]const u8) = .empty;
            defer self.freeHeaderList(&headers, &owned);
            try self.streamHeaders(last_event_id, &headers, &owned);

            var conn = try self.connectTarget(target);
            var stream = switch (conn) {
                inline else => |*s| http.openSseStream(self.alloc, s, target.host, target.path, headers.items) catch |err| {
                    conn.deinit();
                    return err;
                },
            };

            if (stream.status == 404 or stream.status == 405) {
                const st = stream.status;
                stream.deinit(self.alloc);
                conn.deinit();
                if (self.cfg.verbose) std.debug.print("mcp-bridge: [sse] GET {s} -> {d} (no event stream)\n", .{ target.path, st });
                return error.NoSseEndpoint;
            }
            if (stream.status == 401 and !auth_retried) {
                auth_retried = true;
                const wa = if (stream.www_authenticate) |h| try self.alloc.dupe(u8, h) else null;
                defer if (wa) |h| self.alloc.free(h);
                stream.deinit(self.alloc);
                conn.deinit();
                if (self.cfg.verbose) std.debug.print("mcp-bridge: [sse] 401 on GET stream, running OAuth\n", .{});
                if (self.tokens != null)
                    try self.reauthOn401(wa)
                else
                    try self.ensureAuth(wa);
                continue;
            }
            if (stream.status != 200 or !stream.is_sse) {
                last_status = stream.status;
                if (self.cfg.verbose) std.debug.print("mcp-bridge: [sse] GET stream -> HTTP {d} (sse={})\n", .{ stream.status, stream.is_sse });
                stream.deinit(self.alloc);
                conn.deinit();
                log.err("event stream endpoint returned HTTP {d}", .{last_status});
                return error.SseEndpointUnavailable;
            }

            const handoff = try self.alloc.create(PumpHandoff);
            handoff.* = .{ .conn = conn, .stream = stream };
            return handoff;
        }
    }

    /// Pump thread entry: legacy event stream. Reads events until the
    /// stream ends or stop is requested, then marks the state dead (the
    /// main thread reconnects on the next send, resuming with
    /// Last-Event-ID).
    fn legacyPumpMain(self: *Bridge, handoff: *PumpHandoff) void {
        var l = &self.leg.?;
        defer {
            l.mutex.lock();
            l.conn = null;
            l.mutex.unlock();
            handoff.stream.deinit(self.alloc);
            handoff.conn.deinit();
            self.alloc.destroy(handoff);
        }
        switch (handoff.conn) {
            inline else => |*s| self.legacyEventLoop(s, &handoff.stream),
        }
        if (!l.stop.load(.acquire)) self.legacyMarkDead();
    }

    fn legacyEventLoop(self: *Bridge, stream_io: anytype, stream: *http.SseStream) void {
        var l = &self.leg.?;
        while (true) {
            if (l.stop.load(.acquire)) return;
            // Drain all complete events before blocking on the wire.
            while (stream.nextEvent() catch null) |ev_raw| {
                var ev = ev_raw;
                defer ev.deinit(self.alloc);
                self.legacyDispatch(&ev);
                if (l.stop.load(.acquire)) return;
            }
            const r = stream.fill(self.alloc, stream_io) catch |err| {
                if (err == error.Timeout) continue; // idle window; re-check stop
                if (self.cfg.verbose and !l.stop.load(.acquire))
                    std.debug.print("mcp-bridge: [sse] stream read failed: {s}\n", .{@errorName(err)});
                break;
            };
            if (r == .end) {
                // One last drain, then the stream is done.
                while (stream.nextEvent() catch null) |ev_raw| {
                    var ev = ev_raw;
                    defer ev.deinit(self.alloc);
                    self.legacyDispatch(&ev);
                }
                break;
            }
        }
    }

    fn legacyDispatch(self: *Bridge, ev: *const sse.Event) void {
        var l = &self.leg.?;
        if (std.mem.eql(u8, ev.event, "endpoint")) {
            // POST endpoint URL for client->server messages.
            self.setLegacyEndpoint(ev.data);
            return;
        }
        if (ev.id) |id| {
            l.mutex.lock();
            if (l.last_event_id) |old| self.alloc.free(old);
            l.last_event_id = self.alloc.dupe(u8, id) catch null;
            l.mutex.unlock();
        }
        // A response drains its pending id; everything (responses AND
        // server-pushed messages) goes to the client.
        if (mcp.getRequestId(ev.data)) |rid| {
            l.mutex.lock();
            if (l.pending.fetchRemove(rid)) |kv| self.alloc.free(kv.key);
            l.mutex.unlock();
        }
        if (self.cfg.verbose) std.debug.print("mcp-bridge: [sse] << {s}\n", .{ev.data});
        self.out.writeLine(ev.data);
    }

    fn setLegacyEndpoint(self: *Bridge, url_data: []const u8) void {
        var l = &self.leg.?;
        // Resolve the endpoint event payload to an absolute URL. Per the
        // 2024-11-05 spec it's usually a relative reference against the
        // SSE endpoint's origin; absolute URLs are accepted as-is.
        var abs: []u8 = undefined;
        if (std.mem.startsWith(u8, url_data, "http://") or std.mem.startsWith(u8, url_data, "https://")) {
            abs = self.alloc.dupe(u8, url_data) catch {
                self.legacyMarkDead();
                return;
            };
        } else {
            const origin = self.cfg.target.origin(self.alloc) catch {
                self.legacyMarkDead();
                return;
            };
            defer self.alloc.free(origin);
            abs = (if (url_data.len > 0 and url_data[0] == '/')
                std.fmt.allocPrint(self.alloc, "{s}{s}", .{ origin, url_data })
            else
                std.fmt.allocPrint(self.alloc, "{s}/{s}", .{ origin, url_data })) catch {
                self.legacyMarkDead();
                return;
            };
        }
        const target = http.parseUrl(abs) catch {
            self.alloc.free(abs);
            if (self.cfg.verbose) std.debug.print("mcp-bridge: [sse] bad endpoint URL '{s}'\n", .{url_data});
            // Without an endpoint the transport is unusable; fail the
            // startLegacy wait instead of hanging.
            self.legacyMarkDead();
            return;
        };
        l.mutex.lock();
        if (l.endpoint_url) |old| self.alloc.free(old);
        l.endpoint_url = abs;
        l.endpoint = target;
        l.endpoint_gen = l.generation;
        l.ready = true;
        l.mutex.unlock();
        l.cond.broadcast();
        if (self.cfg.verbose) std.debug.print("mcp-bridge: [sse] endpoint: {s}\n", .{abs});
    }

    /// Stream dropped: fail every pending request so the client never
    /// hangs, and let the next send reconnect.
    fn legacyMarkDead(self: *Bridge) void {
        var l = &self.leg.?;
        l.mutex.lock();
        const was_ready = l.ready;
        l.dead = true;
        l.ready = false;
        l.dead_gen = l.generation;
        var it = l.pending.iterator();
        while (it.next()) |entry| {
            var ebuf: [512]u8 = undefined;
            const emsg = mcp.formatTransportError(&ebuf, entry.key_ptr.*, "event stream lost");
            self.out.writeLine(emsg);
            self.alloc.free(entry.key_ptr.*);
        }
        l.pending.clearRetainingCapacity();
        l.mutex.unlock();
        if (was_ready and self.cfg.verbose) std.debug.print("mcp-bridge: [sse] event stream lost\n", .{});
        l.cond.broadcast();
    }

    fn stopLegacy(self: *Bridge) void {
        if (self.leg == null) return;
        var l = &self.leg.?;
        l.stop.store(true, .release);
        l.mutex.lock();
        if (l.conn) |cp| {
            switch (cp.*) {
                inline else => |*s| s.forceShutdown(),
            }
        }
        l.mutex.unlock();
        if (l.pump_thread) |th| {
            th.join();
            l.pump_thread = null;
        }
    }

    /// Open (or re-open) the legacy event stream and spawn the pump.
    /// Blocks until the endpoint event arrives or the stream fails.
    pub fn startLegacy(self: *Bridge) !void {
        if (self.leg == null) self.leg = .{};
        var l = &self.leg.?;
        if (l.pump_thread != null and !l.dead and l.ready) return;

        // (Re)start: join any dead pump first.
        self.stopLegacy();
        l.mutex.lock();
        l.stop.store(false, .release);
        l.dead = false;
        l.ready = false;
        l.generation += 1;
        const gen = l.generation;
        const lei: ?[]u8 = if (l.last_event_id) |v| (self.alloc.dupe(u8, v) catch null) else null;
        l.mutex.unlock();
        defer if (lei) |v| self.alloc.free(v);

        if (self.cfg.oauth != null) try self.ensureAuth(null);

        const handoff = try self.openEventStream(self.cfg.target, lei);
        l.mutex.lock();
        l.conn = &handoff.conn;
        l.mutex.unlock();
        l.pump_thread = std.Thread.spawn(.{}, Bridge.legacyPumpMain, .{ self, handoff }) catch |err| {
            l.mutex.lock();
            l.conn = null;
            l.mutex.unlock();
            handoff.stream.deinit(self.alloc);
            handoff.conn.deinit();
            self.alloc.destroy(handoff);
            return err;
        };

        // Wait for THIS stream's endpoint event (generation-tagged: a
        // previous stream's stale endpoint or death must not count).
        l.mutex.lock();
        while (!(l.ready and l.endpoint_gen == gen) and !(l.dead and l.dead_gen == gen)) l.cond.wait(&l.mutex);
        const ok = l.ready and l.endpoint_gen == gen;
        l.mutex.unlock();
        if (!ok) {
            self.stopLegacy();
            return error.SseEndpointUnavailable;
        }
        if (self.cfg.verbose) std.debug.print("mcp-bridge: [sse] legacy transport ready\n", .{});
    }

    /// Entry point for one stdin line in legacy mode. Never fails the
    /// client silently: errors are synthesized as JSON-RPC responses.
    fn legacySendLine(self: *Bridge, line: []const u8) void {
        const rid: ?[]const u8 = mcp.getRequestId(line);
        const is_request = std.mem.indexOf(u8, line, "\"method\"") != null;

        // Ensure the event stream is up (reconnect on drop).
        if (self.leg == null or self.leg.?.pump_thread == null or self.leg.?.dead or !self.leg.?.ready) {
            self.startLegacy() catch |err| {
                if (rid != null and is_request) {
                    var ebuf: [512]u8 = undefined;
                    self.out.writeLine(mcp.formatTransportError(&ebuf, rid, @errorName(err)));
                }
                return;
            };
        }

        var l = &self.leg.?;
        // Copy the endpoint target under the lock: setLegacyEndpoint may
        // swap it from the pump thread after a reconnect.
        var host_buf: [256]u8 = undefined;
        var path_buf: [2048]u8 = undefined;
        l.mutex.lock();
        const ep = l.endpoint orelse {
            l.mutex.unlock();
            if (rid != null and is_request) {
                var ebuf: [512]u8 = undefined;
                self.out.writeLine(mcp.formatTransportError(&ebuf, rid, "SseEndpointUnavailable"));
            }
            return;
        };
        if (ep.host.len > host_buf.len or ep.path.len > path_buf.len) {
            l.mutex.unlock();
            if (rid != null and is_request) {
                var ebuf: [512]u8 = undefined;
                self.out.writeLine(mcp.formatTransportError(&ebuf, rid, "SseEndpointUnavailable"));
            }
            return;
        }
        @memcpy(host_buf[0..ep.host.len], ep.host);
        @memcpy(path_buf[0..ep.path.len], ep.path);
        const target = Target{
            .secure = ep.secure,
            .host = host_buf[0..ep.host.len],
            .port = ep.port,
            .path = path_buf[0..ep.path.len],
        };
        l.mutex.unlock();

        // Register the id before POSTing so a fast response can't race
        // ahead of the pending insert.
        if (rid != null and is_request) {
            const key = self.alloc.dupe(u8, rid.?) catch return;
            l.mutex.lock();
            l.pending.put(self.alloc, key, {}) catch {
                l.mutex.unlock();
                self.alloc.free(key);
                return;
            };
            l.mutex.unlock();
        }

        self.legacyPost(target, line) catch |err| {
            if (rid != null and is_request) {
                l.mutex.lock();
                if (l.pending.fetchRemove(rid.?)) |kv| self.alloc.free(kv.key);
                l.mutex.unlock();
                var ebuf: [512]u8 = undefined;
                self.out.writeLine(mcp.formatTransportError(&ebuf, rid, @errorName(err)));
            }
        };
    }

    /// POST one JSON-RPC message to the legacy session endpoint. The
    /// server answers 2xx (202 Accepted, no body); the JSON-RPC response
    /// arrives on the event stream and is written by the pump.
    fn legacyPost(self: *Bridge, target: Target, line: []const u8) !void {
        var headers: std.ArrayList([]const u8) = .empty;
        defer headers.deinit(self.alloc);
        var auth_hdr: ?[]const u8 = null;
        defer if (auth_hdr) |h| self.alloc.free(h);
        try self.commonHeaders(&headers, &auth_hdr);

        var auth_retried = false;
        while (true) {
            var conn = try self.connectTarget(target);
            defer conn.deinit();
            var resp = switch (conn) {
                inline else => |*s| try http.post(self.alloc, s, target.host, target.path, line, headers.items, null, .{}),
            };
            defer resp.deinit(self.alloc);
            if (resp.status == 401 and !auth_retried) {
                auth_retried = true;
                const wa = if (resp.www_authenticate) |h| try self.alloc.dupe(u8, h) else null;
                defer if (wa) |h| self.alloc.free(h);
                if (self.tokens != null)
                    try self.reauthOn401(wa)
                else
                    try self.ensureAuth(wa);
                // Refresh the header snapshot for the retry.
                headers.clearRetainingCapacity();
                if (auth_hdr) |h| {
                    self.alloc.free(h);
                    auth_hdr = null;
                }
                try self.commonHeaders(&headers, &auth_hdr);
                continue;
            }
            if (resp.status >= 200 and resp.status < 300) return;
            if (self.cfg.verbose) std.debug.print("mcp-bridge: [sse] POST rejected: HTTP {d}\n", .{resp.status});
            return error.SsePostRejected;
        }
    }

    // -------------------------------------- streamable GET push stream ----

    /// Open the standalone GET SSE stream (issue #2) once initialize has
    /// produced a session id. Server-initiated messages (notifications,
    /// sampling/elicitation requests) arrive here instead of being
    /// silently missed. Tolerates 404/405 (server has no GET stream).
    /// Called from the main loop after each request; cheap no-op while
    /// the stream is healthy. One restart after a dropped stream.
    pub fn maybeStartPush(self: *Bridge) void {
        if (self.mode != .streamable) return;
        if (self.session_id == null) return;
        if (self.push.unsupported) return;
        if (self.push.thread != null and !self.push.dead) return;
        if (self.push.dead) {
            if (self.push.retried) return;
            self.push.retried = true;
        }
        self.stopPush(); // join a dead pump, if any
        self.openPush() catch |err| {
            if (self.cfg.verbose) std.debug.print("mcp-bridge: [push] open failed: {s}\n", .{@errorName(err)});
            self.push.dead = true;
        };
    }

    fn openPush(self: *Bridge) !void {
        if (self.cfg.oauth != null) try self.ensureAuth(null);
        self.push.mutex.lock();
        const lei: ?[]u8 = if (self.push.last_event_id) |v| (self.alloc.dupe(u8, v) catch null) else null;
        self.push.mutex.unlock();
        defer if (lei) |v| self.alloc.free(v);

        var headers: std.ArrayList([]const u8) = .empty;
        var owned: std.ArrayList([]const u8) = .empty;
        defer self.freeHeaderList(&headers, &owned);
        try self.streamHeaders(lei, &headers, &owned);
        const session_hdr = try std.fmt.allocPrint(self.alloc, "MCP-Session-Id: {s}", .{self.session_id.?});
        defer self.alloc.free(session_hdr);
        try headers.append(self.alloc, session_hdr);
        try headers.append(self.alloc, "MCP-Protocol-Version: 2025-03-26");

        var auth_retried = false;
        while (true) {
            var conn = try self.connectTarget(self.cfg.target);
            var stream = switch (conn) {
                inline else => |*s| http.openSseStream(self.alloc, s, self.cfg.target.host, self.cfg.target.path, headers.items) catch |err| {
                    conn.deinit();
                    return err;
                },
            };

            if (stream.status == 404 or stream.status == 405) {
                if (self.cfg.verbose) std.debug.print("mcp-bridge: [push] server has no GET stream ({d})\n", .{stream.status});
                self.push.unsupported = true;
                stream.deinit(self.alloc);
                conn.deinit();
                return;
            }
            if (stream.status == 401 and !auth_retried and
                (self.cfg.oauth != null or self.tokens != null))
            {
                // Push is optional: only chase auth when OAuth is already
                // in play — never pop a surprise browser flow for it.
                auth_retried = true;
                const wa = if (stream.www_authenticate) |h| try self.alloc.dupe(u8, h) else null;
                defer if (wa) |h| self.alloc.free(h);
                stream.deinit(self.alloc);
                conn.deinit();
                if (self.tokens != null)
                    try self.reauthOn401(wa)
                else
                    try self.ensureAuth(wa);
                headers.clearRetainingCapacity();
                for (owned.items) |h| self.alloc.free(@constCast(h));
                owned.clearRetainingCapacity();
                try self.streamHeaders(lei, &headers, &owned);
                try headers.append(self.alloc, session_hdr);
                try headers.append(self.alloc, "MCP-Protocol-Version: 2025-03-26");
                continue;
            }
            if (stream.status != 200 or !stream.is_sse) {
                if (self.cfg.verbose) std.debug.print("mcp-bridge: [push] HTTP {d} (sse={})\n", .{ stream.status, stream.is_sse });
                stream.deinit(self.alloc);
                conn.deinit();
                self.push.dead = true;
                return;
            }

            const handoff = try self.alloc.create(PumpHandoff);
            handoff.* = .{ .conn = conn, .stream = stream };
            self.push.stop.store(false, .release);
            self.push.dead = false;
            self.push.mutex.lock();
            self.push.conn = &handoff.conn;
            self.push.mutex.unlock();
            self.push.thread = std.Thread.spawn(.{}, Bridge.pushPumpMain, .{ self, handoff }) catch |err| {
                self.push.mutex.lock();
                self.push.conn = null;
                self.push.mutex.unlock();
                handoff.stream.deinit(self.alloc);
                handoff.conn.deinit();
                self.alloc.destroy(handoff);
                return err;
            };
            if (self.cfg.verbose) std.debug.print("mcp-bridge: [push] GET stream open\n", .{});
            return;
        }
    }

    fn stopPush(self: *Bridge) void {
        self.push.stop.store(true, .release);
        self.push.mutex.lock();
        if (self.push.conn) |cp| {
            switch (cp.*) {
                inline else => |*s| s.forceShutdown(),
            }
        }
        self.push.mutex.unlock();
        if (self.push.thread) |th| {
            th.join();
            self.push.thread = null;
        }
    }

    fn pushPumpMain(self: *Bridge, handoff: *PumpHandoff) void {
        defer {
            self.push.mutex.lock();
            self.push.conn = null;
            self.push.mutex.unlock();
            handoff.stream.deinit(self.alloc);
            handoff.conn.deinit();
            self.alloc.destroy(handoff);
        }
        switch (handoff.conn) {
            inline else => |*s| {
                while (true) {
                    if (self.push.stop.load(.acquire)) return;
                    while (handoff.stream.nextEvent() catch null) |ev_raw| {
                        var ev = ev_raw;
                        defer ev.deinit(self.alloc);
                        if (ev.id) |id| {
                            self.push.mutex.lock();
                            if (self.push.last_event_id) |old| self.alloc.free(old);
                            self.push.last_event_id = self.alloc.dupe(u8, id) catch null;
                            self.push.mutex.unlock();
                        }
                        if (self.cfg.verbose) std.debug.print("mcp-bridge: [push] << {s}\n", .{ev.data});
                        self.out.writeLine(ev.data);
                        if (self.push.stop.load(.acquire)) return;
                    }
                    const r = handoff.stream.fill(self.alloc, s) catch |err| {
                        if (err == error.Timeout) continue;
                        if (self.cfg.verbose and !self.push.stop.load(.acquire))
                            std.debug.print("mcp-bridge: [push] stream read failed: {s}\n", .{@errorName(err)});
                        break;
                    };
                    if (r == .end) {
                        while (handoff.stream.nextEvent() catch null) |ev_raw| {
                            var ev = ev_raw;
                            defer ev.deinit(self.alloc);
                            self.out.writeLine(ev.data);
                        }
                        break;
                    }
                }
            },
        }
        if (!self.push.stop.load(.acquire)) {
            self.push.mutex.lock();
            self.push.dead = true;
            self.push.mutex.unlock();
            if (self.cfg.verbose) std.debug.print("mcp-bridge: [push] stream lost\n", .{});
        }
    }

    // ------------------------------------------------------------ OAuth --

    /// Make sure we hold a usable access token. Runs discovery on first
    /// use, refreshes expired tokens, and falls back to a full grant flow
    /// (client-credentials when a secret is configured, else interactive
    /// authorization code + PKCE).
    /// RFC 8707 resource sent on the wire: the explicit --resource value,
    /// else the server URL itself (per the MCP authorization spec).
    fn wireResource(self: *Bridge) []const u8 {
        return if (self.cfg.oauth) |o| o.resource orelse self.cfg.url else self.cfg.url;
    }

    /// Resource used for the token cache key: only an explicit --resource
    /// namespaces the cache (multi-tenant); otherwise URL-only (legacy).
    fn cacheResource(self: *Bridge) ?[]const u8 {
        return if (self.cfg.oauth) |o| o.resource else null;
    }

    /// Another instance may have refreshed concurrently (refresh-token
    /// rotation invalidates the old refresh token). Reload the cache and
    /// adopt newer tokens when they differ from what we hold.
    fn reloadCacheIfChanged(self: *Bridge) bool {
        const fresh = (oauth.loadTokenCache(self.alloc, self.cfg.url, self.cacheResource()) catch null) orelse return false;
        if (self.tokens) |cur| {
            if (std.mem.eql(u8, fresh.access_token, cur.access_token)) return false;
        }
        self.tokens = fresh;
        if (self.cfg.verbose) std.debug.print("mcp-bridge: [oauth] adopted tokens refreshed by another instance\n", .{});
        return true;
    }

    fn ensureAuth(self: *Bridge, www_authenticate: ?[]const u8) !void {
        const alloc = self.alloc;
        const now = std.time.timestamp();

        if (!self.tokens_loaded) {
            self.tokens_loaded = true;
            self.tokens = oauth.loadTokenCache(alloc, self.cfg.url, self.cacheResource()) catch null;
            if (self.tokens != null and self.cfg.verbose)
                std.debug.print("mcp-bridge: [oauth] loaded cached tokens\n", .{});
        }

        if (self.tokens) |t| {
            if (!t.isExpired(now)) return;
            // Expired: refresh once if possible
            if (t.refresh_token) |rt| {
                if (self.refreshTokens(rt)) |_| return else |err| {
                    if (self.reloadCacheIfChanged()) return;
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
                if (self.refreshTokens(rt)) |_| return else |_| {
                    if (self.reloadCacheIfChanged()) return;
                }
            }
        }
        try self.fullAuthFlow(www_authenticate);
    }

    fn refreshTokens(self: *Bridge, refresh_token: []const u8) !void {
        const disc = try self.discover(null);
        const cfg = self.cfg.oauth orelse OAuthCfg{};
        const client_id = cfg.client_id orelse
            (self.tokens orelse return oauth.OAuthError.BadResponse).client_id orelse
            return oauth.OAuthError.BadResponse;
        var t = try oauth.refresh(self.alloc, disc.as.token_endpoint, client_id, cfg.client_secret, refresh_token, self.wireResource());
        t.client_id = try self.alloc.dupe(u8, client_id);
        self.adoptTokens(t);
        try oauth.saveTokenCache(self.alloc, self.cfg.url, self.cacheResource(), self.tokens.?);
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
        const resource = self.wireResource();

        // Headless: client credentials when forced, or (auto) when a
        // secret is configured without an explicit grant choice
        const use_client_credentials = cfg.grant == .client_credentials or
            (cfg.grant == .auto and cfg.client_id != null and cfg.client_secret != null);
        if (use_client_credentials) {
            const cid = cfg.client_id orelse {
                log.err("--oauth-grant client_credentials requires --oauth-client-id and --oauth-client-secret", .{});
                return oauth.OAuthError.BadResponse;
            };
            const secret = cfg.client_secret orelse {
                log.err("--oauth-grant client_credentials requires --oauth-client-secret", .{});
                return oauth.OAuthError.BadResponse;
            };
            var t = try oauth.clientCredentials(alloc, disc.as.token_endpoint, cid, secret, cfg.scope, resource);
            t.client_id = cid;
            self.adoptTokens(t);
            try oauth.saveTokenCache(alloc, self.cfg.url, self.cacheResource(), self.tokens.?);
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

        const auth_url = try oauth.buildAuthUrl(alloc, authz_ep, client_id, redirect_uri, &challenge, &state, scope, resource);
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

        var t = try oauth.exchangeCode(alloc, disc.as.token_endpoint, client_id, code, redirect_uri, &verifier, cfg.client_secret, resource);
        t.client_id = try alloc.dupe(u8, client_id);
        self.adoptTokens(t);
        try oauth.saveTokenCache(alloc, self.cfg.url, self.cacheResource(), self.tokens.?);
        std.debug.print("mcp-bridge: [oauth] authorization complete, token cached\n", .{});
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
    /// to the client so it sees server-initiated notifications.
    fn ssePush(ctx: ?*anyopaque, data: []const u8) void {
        const self: *Bridge = @ptrCast(@alignCast(ctx orelse return));
        self.out.writeLine(data);
    }

    /// Send one stdin line. Returns the response for streamable mode, or
    /// null when the line was handed to the legacy transport (responses
    /// arrive asynchronously on the event stream).
    pub fn dispatchLine(self: *Bridge, line: []const u8) !?http.Response {
        if (self.mode == .legacy) {
            self.legacySendLine(line);
            return null;
        }
        var resp = try self.request(line);
        // http-first probing: a 404/405 from the POST endpoint means the
        // server doesn't speak Streamable HTTP — try the legacy SSE
        // transport on the same URL (mcp-remote's default strategy).
        if (!self.probed and self.cfg.transport == .http_first and
            (resp.status == 404 or resp.status == 405))
        {
            const st = resp.status;
            resp.deinit(self.alloc);
            self.closeConn();
            if (self.cfg.verbose) std.debug.print("mcp-bridge: POST -> {d}, trying legacy SSE transport\n", .{st});
            self.startLegacy() catch |err| {
                self.probed = true;
                if (self.cfg.verbose) std.debug.print("mcp-bridge: [sse] fallback failed: {s}\n", .{@errorName(err)});
                return err;
            };
            self.mode = .legacy;
            self.probed = true;
            if (self.cfg.verbose) std.debug.print("mcp-bridge: switched to legacy SSE transport\n", .{});
            self.legacySendLine(line);
            return null;
        }
        self.probed = true;
        return resp;
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
                inline else => |*s| http.post(self.alloc, s, t.host, t.path, line, headers.items, mcp.getRequestId(line), .{ .ctx = self, .push = ssePush }),
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

/// A value-taking CLI flag matched in any of these forms:
///   --name value        (two argv entries)
///   --name=value
///   --name "value"      (single argv entry — GUI MCP clients glue these)
///   -h value            (optional short form)
/// Returns .no if the current arg is not this flag, .missing if the value
/// is absent, else .value.
const FlagMatch = union(enum) { no, missing, value: []const u8 };

fn matchValueFlag(args: []const []const u8, i: *usize, long: []const u8, short: ?[]const u8) ?FlagMatch {
    const a = args[i.*];
    if (std.mem.eql(u8, a, long) or (short != null and std.mem.eql(u8, a, short.?))) {
        if (i.* + 1 >= args.len) return .missing;
        i.* += 1;
        return .{ .value = args[i.*] };
    }
    if (std.mem.startsWith(u8, a, long) and a.len > long.len and
        (a[long.len] == '=' or a[long.len] == ' '))
    {
        const v = std.mem.trim(u8, a[long.len + 1 ..], " \t\"'");
        if (v.len == 0) return .missing;
        return .{ .value = v };
    }
    return null;
}

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
    var oauth_grant: ?[]const u8 = null;
    var oauth_resource: ?[]const u8 = null;
    var oauth_logout = false;
    var transport_flag: ?[]const u8 = null;
    var config_path: ?[]const u8 = null;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--verbose") or std.mem.eql(u8, a, "-v")) {
            cfg.verbose = true;
        } else if (matchValueFlag(args, &i, "--header", "-H")) |m| {
            const v = switch (m) {
                .missing => usage(),
                .value => |v| v,
                .no => unreachable,
            };
            try cfg.headers.append(alloc, v);
        } else if (std.mem.eql(u8, a, "--oauth")) {
            oauth_flag = true;
        } else if (matchValueFlag(args, &i, "--oauth-client-id", null)) |m| {
            oauth_client_id = switch (m) {
                .missing => usage(),
                .value => |v| v,
                .no => unreachable,
            };
        } else if (matchValueFlag(args, &i, "--oauth-client-secret", null)) |m| {
            oauth_client_secret = switch (m) {
                .missing => usage(),
                .value => |v| v,
                .no => unreachable,
            };
        } else if (matchValueFlag(args, &i, "--oauth-scope", null)) |m| {
            oauth_scope = switch (m) {
                .missing => usage(),
                .value => |v| v,
                .no => unreachable,
            };
        } else if (matchValueFlag(args, &i, "--oauth-grant", null)) |m| {
            oauth_grant = switch (m) {
                .missing => usage(),
                .value => |v| v,
                .no => unreachable,
            };
        } else if (matchValueFlag(args, &i, "--resource", null)) |m| {
            oauth_resource = switch (m) {
                .missing => usage(),
                .value => |v| v,
                .no => unreachable,
            };
        } else if (std.mem.eql(u8, a, "--oauth-logout")) {
            oauth_logout = true;
        } else if (matchValueFlag(args, &i, "--transport", null)) |m| {
            transport_flag = switch (m) {
                .missing => usage(),
                .value => |v| v,
                .no => unreachable,
            };
        } else if (matchValueFlag(args, &i, "--config", null)) |m| {
            config_path = switch (m) {
                .missing => usage(),
                .value => |v| v,
                .no => unreachable,
            };
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

    const resource: ?[]const u8 = oauth_resource orelse if (file_sc) |sc| sc.resource else null;
    const transport_str: ?[]const u8 = transport_flag orelse if (file_sc) |sc| sc.transport else null;
    if (transport_str) |ts| {
        cfg.transport = TransportStrategy.parse(ts) orelse {
            log.err("invalid --transport '{s}' (expected http-first|http-only|sse-first|sse-only)", .{ts});
            usage();
        };
    }
    const grant_str: ?[]const u8 = oauth_grant orelse if (file_sc) |sc| sc.grant else null;
    const grant: Grant = if (grant_str) |g| blk: {
        if (std.mem.eql(u8, g, "authorization_code")) break :blk .authorization_code;
        if (std.mem.eql(u8, g, "client_credentials")) break :blk .client_credentials;
        if (std.mem.eql(u8, g, "auto")) break :blk .auto;
        log.err("invalid --oauth-grant '{s}' (expected authorization_code|client_credentials|auto)", .{g});
        usage();
    } else .auto;

    if (oauth_logout) {
        try oauth.deleteTokenCache(alloc, cfg.url, resource);
        std.debug.print("mcp-bridge: deleted cached tokens for {s}\n", .{cfg.url});
        return;
    }

    if (oauth_flag or (file_sc != null and file_sc.?.oauth)) {
        cfg.oauth = .{
            .client_id = oauth_client_id orelse if (file_sc) |sc| sc.client_id else null,
            .client_secret = oauth_client_secret orelse if (file_sc) |sc| sc.client_secret else null,
            .scope = oauth_scope orelse if (file_sc) |sc| sc.scope else null,
            .resource = resource,
            .grant = grant,
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
        .out = stdoutOut(),
    };
    defer bridge.deinit();

    // Transport strategy: sse-first probes the event stream up front;
    // sse-only commits; http-first defers probing to the first POST's
    // status; http-only never probes.
    switch (cfg.transport) {
        .http_only, .http_first => {},
        .sse_only => {
            bridge.mode = .legacy;
            bridge.probed = true;
        },
        .sse_first => {
            bridge.startLegacy() catch |err| {
                if (err == error.NoSseEndpoint) {
                    if (cfg.verbose) std.debug.print("mcp-bridge: [sse] no event stream, using Streamable HTTP\n", .{});
                    bridge.mode = .streamable;
                    bridge.probed = true;
                } else {
                    return err;
                }
            };
            if (bridge.leg != null and bridge.leg.?.ready) {
                bridge.mode = .legacy;
                bridge.probed = true;
            }
        },
    }

    // Preload a cached token so the first request doesn't eat a 401
    // (skipped when the user passed an explicit Authorization header).
    var has_auth_header = false;
    for (cfg.headers.items) |h| {
        if (std.ascii.startsWithIgnoreCase(h, "authorization:")) has_auth_header = true;
    }
    if (!has_auth_header and cfg.target.secure) {
        bridge.tokens = oauth.loadTokenCache(alloc, cfg.url, bridge.cacheResource()) catch null;
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

        var maybe_resp = bridge.dispatchLine(line) catch |err| {
            // Synthesize a JSON-RPC error so the client isn't left hanging.
            var ebuf: [512]u8 = undefined;
            const emsg = mcp.formatTransportError(&ebuf, mcp.getRequestId(line), @errorName(err));
            bridge.out.writeLine(emsg);
            continue;
        };
        // Legacy transport: responses arrive on the event stream.
        const resp = &(maybe_resp orelse continue);
        defer resp.deinit(alloc);

        // Error status without a JSON-RPC body (e.g. a bare 401 page):
        // synthesize a proper JSON-RPC error instead of forwarding junk.
        if (resp.status >= 400 and std.mem.indexOf(u8, resp.body, "\"jsonrpc\"") == null) {
            var ebuf: [512]u8 = undefined;
            var msg_buf: [64]u8 = undefined;
            const msg = std.fmt.bufPrint(&msg_buf, "HTTP {d}", .{resp.status}) catch "HTTP error";
            const emsg = mcp.formatTransportError(&ebuf, mcp.getRequestId(line), msg);
            bridge.out.writeLine(emsg);
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
            bridge.out.writeLine(resp.body);
        } else if (cfg.verbose) {
            std.debug.print("mcp-bridge: << {d} (no body)\n", .{resp.status});
        }

        // With a session established, open the standalone GET stream for
        // server-initiated messages (no-op while healthy/unsupported).
        bridge.maybeStartPush();
    }

    if (cfg.verbose) std.debug.print("mcp-bridge: stdin closed, exiting\n", .{});
    bridge.terminateSession();
}
