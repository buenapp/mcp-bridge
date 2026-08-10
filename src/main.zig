// mcp-bridge: MCP stdio <-> HTTP(S) bridge (Windows, FreeBSD, Linux).
//
// EVENT-DRIVEN CORE (issue #7): a single dispatch loop over the platform
// event port (kqueue/epoll/IOCP). No blocking I/O on the data path, no
// I/O threads. stdin lines, upstream POSTs, SSE streams (both transports)
// and the standalone GET push stream are all connections on one loop;
// JSON-RPC correlation lives in the pending-id registry / per-conn
// expect_id. OAuth one-shot calls run on private event ports (syncreq) —
// synchronous from the loop's perspective, but never a blocking socket.
//
// Transports: Streamable HTTP (2025-03-26, POST to a single endpoint,
// plus the standalone GET stream for server-initiated messages) and the
// legacy HTTP+SSE transport (2024-11-05: GET event stream + per-session
// POST endpoint). TLS with DANE TLSA verification (DANE-TA/DANE-EE, no
// DNSSEC) and root-store PKI fallback when no TLSA is published. Platform
// backends: SChannel/crypt32 on Windows, OpenSSL on POSIX (platform.zig).
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
const builtin = @import("builtin");
const platform = @import("platform.zig");
const http = @import("http.zig");
const mcp = @import("mcp.zig");
const sse = @import("sse.zig");
const oauth = @import("oauth.zig");
const pkce = @import("pkce.zig");
const loopback = @import("oauth_loopback.zig");
const config_file = @import("config.zig");
const evport = @import("evport.zig");
const httpc = @import("httpc.zig");

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

/// The bridge's message sink (stdout in production via the write queue;
/// captured in tests). Single-threaded now — no mutex.
pub const Out = struct {
    ctx: *anyopaque,
    writeFn: *const fn (ctx: *anyopaque, bytes: []const u8) void,

    pub fn write(self: *const Out, bytes: []const u8) void {
        self.writeFn(self.ctx, bytes);
    }

    /// One JSON-RPC message per line.
    pub fn writeLine(self: *const Out, bytes: []const u8) void {
        self.writeFn(self.ctx, bytes);
        self.writeFn(self.ctx, "\n");
    }
};

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

/// Event udata sentinels for the stdio fds (conns carry *httpc.Conn).
var stdin_sentinel: u8 = 0;
var stdout_sentinel: u8 = 0;

/// Owns the event port, all upstream connections, the session id, the
/// pending-id registry, the stdio sources/sinks, and OAuth state.
pub const Bridge = struct {
    alloc: std.mem.Allocator,
    cfg: *const Config,
    verifier: ?*platform.Verifier,
    out: Out,
    evp: evport.EvPort,

    /// All live conns (including closing-marked ones until the reap).
    conns: std.ArrayList(*httpc.Conn) = .empty,
    /// Reusable keep-alive streamable POST conn (at most one).
    idle_conn: ?*httpc.Conn = null,

    // ---- stdin ----
    stdin_carry: std.ArrayList(u8) = .empty,
    stdin_active: bool = false, // fd 0 registered on the port
    stdin_eof: bool = false,

    // ---- stdout write queue (production; tests use a memory sink) ----
    stdout_q: std.ArrayList(u8) = .empty,
    stdout_armed: bool = false, // one-shot write interest staged/delivered-pending
    stdout_is_fd: bool = false,
    stdout_dead: bool = false, // EPIPE: the IDE is gone; drop queued output

    // ---- transport ----
    mode: TransportMode = .streamable,
    probed: bool = false,
    /// sse_first: a GET probe is resolving the transport; stdin lines queue.
    probe_via_get: bool = false,
    session_id: ?[]u8 = null,

    // ---- legacy HTTP+SSE transport ----
    leg_conn: ?*httpc.Conn = null, // the GET event stream conn
    leg_endpoint: ?Target = null, // slices point into leg_endpoint_url
    leg_endpoint_url: ?[]u8 = null,
    leg_last_event_id: ?[]u8 = null,
    leg_ready: bool = false, // endpoint event received
    leg_dead: bool = false, // stream dropped; reconnect on next send
    leg_ready_ever: bool = false,
    leg_reconnecting: bool = false, // one immediate reconnect under queue pressure
    leg_auth_retried: bool = false, // per-attempt 401 budget
    leg_pending: std.StringHashMapUnmanaged(void) = .empty, // request ids awaiting stream responses
    leg_queue: std.ArrayList([]u8) = .empty, // lines waiting for endpoint readiness (owned)

    // ---- Streamable standalone GET push stream ----
    push_conn: ?*httpc.Conn = null,
    push_dead: bool = false,
    push_unsupported: bool = false, // 404/405: never retry
    push_retried: bool = false, // one post-death restart allowed
    push_last_event_id: ?[]u8 = null,
    push_auth_retried: bool = false, // per-attempt 401 budget

    // ---- shutdown ----
    shutting_down: bool = false,
    delete_started: bool = false,
    delete_conn: ?*httpc.Conn = null,

    // ---- OAuth ----
    tokens: ?oauth.TokenSet = null,
    tokens_loaded: bool = false,
    discovered: ?oauth.Discovery = null,

    /// Fatal startup/probe error: shuts the loop down; main returns it.
    fatal: ?anyerror = null,

    pub fn init(alloc: std.mem.Allocator, cfg: *const Config, out: Out, verifier: ?*platform.Verifier) !Bridge {
        return .{
            .alloc = alloc,
            .cfg = cfg,
            .out = out,
            .verifier = verifier,
            .evp = try evport.EvPort.init(alloc),
        };
    }

    pub fn deinit(self: *Bridge) void {
        // Reap anything left (production exits with conns drained; tests
        // may leave streams open).
        for (self.conns.items) |conn| {
            conn.reapClose();
            conn.deinitMem();
        }
        self.conns.deinit(self.alloc);
        self.stdin_carry.deinit(self.alloc);
        self.stdout_q.deinit(self.alloc);
        if (self.session_id) |sid| self.alloc.free(sid);
        if (self.leg_endpoint_url) |u| self.alloc.free(u);
        if (self.leg_last_event_id) |i| self.alloc.free(i);
        var it = self.leg_pending.keyIterator();
        while (it.next()) |k| self.alloc.free(k.*);
        self.leg_pending.deinit(self.alloc);
        for (self.leg_queue.items) |l| self.alloc.free(l);
        self.leg_queue.deinit(self.alloc);
        if (self.push_last_event_id) |i| self.alloc.free(i);
        self.evp.deinit();
    }

    // ---------------------------------------------------------- stdio ----

    /// Production: stdin non-blocking + registered; stdout non-blocking +
    /// queued writes. (POSIX; the Windows overlapped path lands with the
    /// IOCP backend.)
    pub fn attachStdio(self: *Bridge) void {
        if (platform.is_windows) return;
        setNonBlocking(std.posix.STDIN_FILENO);
        setNonBlocking(std.posix.STDOUT_FILENO);
        self.evp.monitorRead(std.posix.STDIN_FILENO, @as(?*anyopaque, &stdin_sentinel));
        self.stdin_active = true;
        self.stdout_is_fd = true;
    }

    fn setNonBlocking(fd: std.posix.fd_t) void {
        const flags = std.posix.fcntl(fd, std.posix.F.GETFL, 0) catch return;
        var o: std.posix.O = @bitCast(@as(u32, @truncate(flags)));
        o.NONBLOCK = true;
        _ = std.posix.fcntl(fd, std.posix.F.SETFL, @as(usize, @as(u32, @bitCast(o)))) catch {};
    }

    fn queueStdout(self: *Bridge, bytes: []const u8) void {
        if (!self.stdout_is_fd or self.stdout_dead) return;
        self.stdout_q.appendSlice(self.alloc, bytes) catch {};
        if (!self.stdout_armed) {
            self.evp.monitorWrite(std.posix.STDOUT_FILENO, @as(?*anyopaque, &stdout_sentinel));
            self.stdout_armed = true;
        }
    }

    fn stdoutWriteFn(ctx: *anyopaque, bytes: []const u8) void {
        const self: *Bridge = @ptrCast(@alignCast(ctx));
        self.queueStdout(bytes);
    }

    /// The production Out sink: queued non-blocking stdout.
    pub fn queuedOut(self: *Bridge) Out {
        return .{ .ctx = self, .writeFn = stdoutWriteFn };
    }

    fn onStdoutWritable(self: *Bridge) void {
        self.stdout_armed = false; // one-shot consumed
        while (self.stdout_q.items.len > 0) {
            const n = std.posix.write(std.posix.STDOUT_FILENO, self.stdout_q.items) catch |err| switch (err) {
                error.WouldBlock => {
                    self.evp.monitorWrite(std.posix.STDOUT_FILENO, @as(?*anyopaque, &stdout_sentinel));
                    self.stdout_armed = true;
                    return;
                },
                else => {
                    // EPIPE etc: the client is gone — drop the queue.
                    self.stdout_dead = true;
                    self.stdout_q.clearRetainingCapacity();
                    return;
                },
            };
            const rest = self.stdout_q.items.len - n;
            std.mem.copyForwards(u8, self.stdout_q.items[0..rest], self.stdout_q.items[n..]);
            self.stdout_q.items.len = rest;
        }
    }

    /// Stdin readable: drain to EAGAIN, split complete lines, dispatch.
    fn onStdinReadable(self: *Bridge) void {
        var tmp: [16384]u8 = undefined;
        while (true) {
            const n = std.posix.read(std.posix.STDIN_FILENO, &tmp) catch |err| switch (err) {
                error.WouldBlock => break,
                else => {
                    self.onStdinEof();
                    return;
                },
            };
            if (n == 0) {
                self.onStdinEof();
                return;
            }
            self.stdin_carry.appendSlice(self.alloc, tmp[0..n]) catch {};
            while (std.mem.indexOfScalar(u8, self.stdin_carry.items, '\n')) |nl| {
                var line = self.stdin_carry.items[0..nl];
                if (line.len > 0 and line[line.len - 1] == '\r') line = line[0 .. line.len - 1];
                const owned = self.alloc.dupe(u8, line) catch null;
                const rest = self.stdin_carry.items.len - (nl + 1);
                std.mem.copyForwards(u8, self.stdin_carry.items[0..rest], self.stdin_carry.items[nl + 1 ..]);
                self.stdin_carry.items.len = rest;
                if (owned) |l| {
                    defer self.alloc.free(l);
                    if (l.len > 0) self.handleLine(l);
                }
                if (self.stdin_eof) return; // shutdown began mid-batch
            }
        }
    }

    /// stdin EOF: flush any unterminated remainder, then begin shutdown.
    fn onStdinEof(self: *Bridge) void {
        if (self.stdin_eof) return;
        self.stdin_eof = true;
        if (self.stdin_active) {
            self.evp.unmonitorRead(std.posix.STDIN_FILENO);
            self.stdin_active = false;
        }
        if (self.stdin_carry.items.len > 0) {
            var line = self.stdin_carry.items;
            if (line.len > 0 and line[line.len - 1] == '\r') line = line[0 .. line.len - 1];
            if (line.len > 0) self.handleLine(line);
            self.stdin_carry.clearRetainingCapacity();
        }
        self.beginShutdown();
    }

    /// Test hook: explicit EOF without a real stdin fd.
    pub fn stdinEof(self: *Bridge) void {
        self.onStdinEof();
    }

    /// Test hook: feed one stdin line.
    pub fn injectLine(self: *Bridge, line: []const u8) void {
        self.handleLine(line);
    }

    // ------------------------------------------------------ loop core ----

    /// One loop iteration: flush staged registrations + harvest events in
    /// ONE event-port call, dispatch, then reap closed conns.
    pub fn step(self: *Bridge, timeout_ms: ?i32) !void {
        var events: [32]evport.Event = undefined;
        const n = try self.evp.wait(&events, timeout_ms);
        for (events[0..n]) |ev| {
            if (ev.wake) continue;
            if (ev.udata == @as(?*anyopaque, &stdin_sentinel)) {
                self.onStdinReadable();
                continue;
            }
            if (ev.udata == @as(?*anyopaque, &stdout_sentinel)) {
                self.onStdoutWritable();
                continue;
            }
            if (ev.udata) |ud| {
                const conn: *httpc.Conn = @ptrCast(@alignCast(ud));
                if (!conn.closing) conn.onEvent(ev);
            }
        }
        self.reap();
    }

    /// Run until shutdown completes (stdin EOF + all conns drained +
    /// stdout queue flushed) or a fatal error.
    pub fn run(self: *Bridge) !void {
        while (!self.isDone()) try self.step(null);
    }

    fn isDone(self: *const Bridge) bool {
        if (!self.shutting_down) return false;
        if (self.conns.items.len != 0) return false;
        if (self.stdout_q.items.len != 0 and !self.stdout_dead) return false;
        return true;
    }

    /// End-of-batch reap: close + free every closing-marked conn.
    ///
    /// kqueue removes an fd's filters on close(2), so the only aliasing
    /// hazard is STAGED-but-unflushed changelist entries referencing an fd
    /// number that gets recycled — purgeFd drops those before the close.
    /// Event udata for the current batch was fully dispatched above, and
    /// fds recycle only after this reap, so no reference can dangle.
    fn reap(self: *Bridge) void {
        var i: usize = 0;
        while (i < self.conns.items.len) {
            const conn = self.conns.items[i];
            if (!conn.closing) {
                i += 1;
                continue;
            }
            self.evp.purgeFd(conn.fd());
            conn.reapClose(); // closeNotify + free TLS state + close fd
            if (self.idle_conn == conn) self.idle_conn = null;
            if (self.leg_conn == conn) self.leg_conn = null;
            if (self.push_conn == conn) self.push_conn = null;
            if (self.delete_conn == conn) self.delete_conn = null;
            conn.deinitMem();
            _ = self.conns.swapRemove(i);
        }
    }

    fn trackConn(self: *Bridge, conn: *httpc.Conn) void {
        self.conns.append(self.alloc, conn) catch {
            conn.close(); // OOM: mark closing; reaped next step
        };
    }

    /// stdin EOF (or fatal error): end the long-lived streams, fail the
    /// legacy pending set, drop the queue — but let in-flight POSTs run to
    /// completion (their responses still go to stdout; the serial core had
    /// the same between-requests EOF granularity). The session DELETE runs
    /// once the last POST drains.
    fn beginShutdown(self: *Bridge) void {
        if (self.shutting_down) return;
        self.shutting_down = true;
        if (self.leg_conn) |c| {
            c.close();
            self.leg_conn = null;
        }
        if (self.push_conn) |c| {
            c.close();
            self.push_conn = null;
        }
        if (self.idle_conn) |c| {
            c.close();
            self.idle_conn = null;
        }
        self.leg_ready = false;
        if (!self.leg_pendingEmpty()) self.failPending(error.ServerClosed);
        for (self.leg_queue.items) |l| self.alloc.free(l);
        self.leg_queue.clearRetainingCapacity();
        self.maybeStartDelete();
    }

    fn leg_pendingEmpty(self: *Bridge) bool {
        return self.leg_pending.count() == 0;
    }

    fn liveConns(self: *Bridge) usize {
        var n: usize = 0;
        for (self.conns.items) |c| {
            if (!c.closing) n += 1;
        }
        return n;
    }

    /// Start the session DELETE once the last in-flight POST drained.
    fn maybeStartDelete(self: *Bridge) void {
        if (!self.shutting_down or self.delete_started or self.fatal != null) return;
        if (self.liveConns() != 0) return;
        self.delete_started = true;
        if (self.session_id != null and self.mode == .streamable) self.startDelete();
    }

    // ------------------------------------------------------ dispatch ----

    /// Entry point for one stdin line. Never fails the client silently:
    /// errors are synthesized as JSON-RPC responses.
    fn handleLine(self: *Bridge, line: []const u8) void {
        if (self.fatal) |err| {
            self.writeTransportError(mcp.getRequestId(line), @errorName(err));
            return;
        }
        if (self.cfg.verbose) std.debug.print("mcp-bridge: >> {s}\n", .{line});
        if (self.probe_via_get and !self.probed) {
            // sse_first probe in flight: queue until the transport resolves.
            const owned = self.alloc.dupe(u8, line) catch return;
            self.leg_queue.append(self.alloc, owned) catch self.alloc.free(owned);
            return;
        }
        switch (self.mode) {
            .legacy => self.legacySendLine(line),
            .streamable => self.streamableSendLine(line, false, false),
        }
    }

    fn writeTransportError(self: *Bridge, rid: ?[]const u8, msg: []const u8) void {
        var ebuf: [512]u8 = undefined;
        self.out.writeLine(mcp.formatTransportError(&ebuf, rid, msg));
    }

    /// The one httpc.Handler surface for every conn; routing by identity.
    fn handler(self: *Bridge) httpc.Handler {
        return .{
            .ctx = self,
            .onResponse = onResponse,
            .onStreamHead = onStreamHead,
            .onEvent = onEvent,
            .onEnd = onEnd,
        };
    }

    fn onResponse(ctx: *anyopaque, conn: *httpc.Conn, resp: http.Response) void {
        const self: *Bridge = @ptrCast(@alignCast(ctx));
        self.handleResponse(conn, resp);
    }

    fn onStreamHead(ctx: *anyopaque, conn: *httpc.Conn, status: u16, is_sse: bool, session_id: ?[]const u8, www_authenticate: ?[]const u8) void {
        const self: *Bridge = @ptrCast(@alignCast(ctx));
        _ = session_id;
        if (conn == self.leg_conn) {
            self.onLegacyStreamHead(conn, status, is_sse, www_authenticate);
        } else if (conn == self.push_conn) {
            self.onPushStreamHead(conn, status, is_sse, www_authenticate);
        } else {
            conn.close(); // post conns never get here (role guard in httpc)
        }
    }

    fn onEvent(ctx: *anyopaque, conn: *httpc.Conn, ev: *const sse.Event) void {
        const self: *Bridge = @ptrCast(@alignCast(ctx));
        if (conn == self.leg_conn) {
            self.legacyDispatchEvent(conn, ev);
        } else if (conn == self.push_conn) {
            if (ev.id) |id| {
                if (self.push_last_event_id) |old| self.alloc.free(old);
                self.push_last_event_id = self.alloc.dupe(u8, id) catch null;
            }
            if (self.cfg.verbose) std.debug.print("mcp-bridge: [push] << {s}\n", .{ev.data});
            self.out.writeLine(ev.data);
        } else {
            // Non-matching event inside a POST's SSE response: a
            // server-pushed message (e.g. sampling request) — forward it.
            if (self.cfg.verbose) std.debug.print("mcp-bridge: [sse] << {s}\n", .{ev.data});
            self.out.writeLine(ev.data);
        }
    }

    fn onEnd(ctx: *anyopaque, conn: *httpc.Conn, err: ?anyerror) void {
        const self: *Bridge = @ptrCast(@alignCast(ctx));
        if (conn == self.leg_conn) {
            self.onLegacyStreamEnd(conn, err);
        } else if (conn == self.push_conn) {
            if (self.cfg.verbose and !self.stdin_eof) std.debug.print("mcp-bridge: [push] stream lost\n", .{});
            self.push_dead = true;
            conn.close();
        } else if (conn == self.delete_conn) {
            if (err == null and self.cfg.verbose) std.debug.print("mcp-bridge: session terminated via DELETE\n", .{});
            conn.close();
        } else if (conn == self.idle_conn) {
            // Idle keep-alive conn ended (server closed or protocol junk).
            self.idle_conn = null;
            conn.close();
            self.maybeStartDelete();
        } else {
            self.onPostEnd(conn, err);
        }
    }

    // ---------------------------------------------- streamable HTTP ----

    /// POST one JSON-RPC message in streamable mode. Reuses the idle
    /// keep-alive conn when available; a reused-conn transport failure
    /// retries once on a fresh conn; a 401 re-auths once and resends.
    fn streamableSendLine(self: *Bridge, line: []const u8, auth_retried: bool, retried: bool) void {
        const t = self.cfg.target;

        // Proactive: acquire/refresh a token when OAuth is configured.
        // (Synchronous sub-operation on a private event port.)
        if (self.cfg.oauth != null) {
            self.ensureAuth(null) catch |err| {
                self.writeTransportError(mcp.getRequestId(line), @errorName(err));
                return;
            };
        }

        var headers: std.ArrayList([]const u8) = .empty;
        defer headers.deinit(self.alloc);
        var session_hdr: ?[]const u8 = null;
        defer if (session_hdr) |h| self.alloc.free(h);
        var auth_hdr: ?[]const u8 = null;
        defer if (auth_hdr) |h| self.alloc.free(h);
        self.buildHeaders(&headers, &session_hdr, &auth_hdr) catch {
            self.writeTransportError(mcp.getRequestId(line), "OutOfMemory");
            return;
        };

        var req = httpc.buildRequest(self.alloc, "POST", t.path, t.host, "application/json, text/event-stream", "application/json", headers.items, line) catch {
            self.writeTransportError(mcp.getRequestId(line), "OutOfMemory");
            return;
        };
        errdefer req.deinit(self.alloc);

        if (self.idle_conn) |ic| {
            self.idle_conn = null;
            ic.reuseForPost(req, mcp.getRequestId(line), line) catch {
                ic.close();
                self.writeTransportError(mcp.getRequestId(line), "OutOfMemory");
                return;
            };
            ic.role.post.auth_retried = auth_retried;
            ic.role.post.retried = retried;
            return;
        }

        const conn = httpc.Conn.startPost(self.alloc, &self.evp, self.handler(), t, req, mcp.getRequestId(line), line, self.verifier) catch |err| {
            self.writeTransportError(mcp.getRequestId(line), @errorName(err));
            return;
        };
        conn.role.post.auth_retried = auth_retried;
        conn.role.post.retried = retried;
        self.trackConn(conn);
    }

    fn handleResponse(self: *Bridge, conn: *httpc.Conn, resp: http.Response) void {
        if (conn == self.delete_conn) {
            // Session DELETE: best-effort; nothing to do with the response.
            var r = resp;
            r.deinit(conn.alloc);
            conn.close();
            return;
        }
        if (conn.role.post.kind == .legacy) {
            self.handleLegacyPostResponse(conn, resp);
            return;
        }
        var r = resp;
        defer r.deinit(conn.alloc);

        // 401: re-auth once, resend on a fresh conn with a new token.
        if (r.status == 401 and !conn.role.post.auth_retried and
            (self.cfg.oauth != null or r.www_authenticate != null))
        {
            const wa = if (r.www_authenticate) |h| self.alloc.dupe(u8, h) catch null else null;
            defer if (wa) |h| self.alloc.free(h);
            const line = if (conn.role.post.line) |l| self.alloc.dupe(u8, l) catch null else null;
            defer if (line) |l| self.alloc.free(l);
            conn.close();
            if (line == null) return;
            if (self.cfg.verbose) std.debug.print("mcp-bridge: [oauth] 401 received, running OAuth\n", .{});
            if (self.tokens != null)
                self.reauthOn401(wa) catch |err| {
                    self.writeTransportError(mcp.getRequestId(line.?), @errorName(err));
                    return;
                }
            else
                self.ensureAuth(wa) catch |err| {
                    self.writeTransportError(mcp.getRequestId(line.?), @errorName(err));
                    return;
                };
            self.streamableSendLine(line.?, true, false);
            return;
        }

        // 404/405 on a streamable POST: the server doesn't speak
        // Streamable HTTP here. http-first probing switches to legacy SSE;
        // and ANY in-flight line caught mid-switch (including the probing
        // line itself) is resent once the endpoint event arrives.
        if (r.status == 404 or r.status == 405) {
            if (!self.probed and self.cfg.transport == .http_first) {
                if (self.cfg.verbose) std.debug.print("mcp-bridge: POST -> {d}, trying legacy SSE transport\n", .{r.status});
                self.mode = .legacy;
                self.probed = true;
                self.startLegacyTransport(false);
                if (self.cfg.verbose) std.debug.print("mcp-bridge: switched to legacy SSE transport\n", .{});
            }
            if (self.mode == .legacy) {
                const line = if (conn.role.post.line) |l| self.alloc.dupe(u8, l) catch null else null;
                conn.close();
                if (line) |l| {
                    self.leg_queue.append(self.alloc, l) catch self.alloc.free(l);
                }
                return;
            }
        }
        self.probed = true;

        // Error status without a JSON-RPC body (e.g. a bare 401 page):
        // synthesize a proper JSON-RPC error instead of forwarding junk.
        if (r.status >= 400 and std.mem.indexOf(u8, r.body, "\"jsonrpc\"") == null) {
            var msg_buf: [64]u8 = undefined;
            const msg = std.fmt.bufPrint(&msg_buf, "HTTP {d}", .{r.status}) catch "HTTP error";
            self.writeTransportError(mcp.getRequestId(if (conn.role.post.line) |l| l else ""), msg);
            if (self.cfg.verbose) std.debug.print("mcp-bridge: << {d} non-JSON-RPC body, synthesized error\n", .{r.status});
            conn.close();
            return;
        }

        // Capture session id from the initialize response.
        if (r.mcp_session_id) |sid| {
            const copy = self.alloc.dupe(u8, sid) catch null;
            if (copy) |c| {
                if (self.session_id) |old| self.alloc.free(old);
                self.session_id = c;
                if (self.cfg.verbose) std.debug.print("mcp-bridge: session {s}\n", .{sid});
            }
        }

        if (r.body.len > 0) {
            if (self.cfg.verbose) std.debug.print("mcp-bridge: << {d} {s}\n", .{ r.status, r.body });
            self.out.writeLine(r.body);
        } else if (self.cfg.verbose) {
            std.debug.print("mcp-bridge: << {d} (no body)\n", .{r.status});
        }

        // Keep-alive JSON conns return to the idle pool (never mid-
        // shutdown); SSE responses and Connection: close end their conn.
        if (!r.server_closed and self.idle_conn == null and !self.shutting_down) {
            conn.makeIdle();
            self.idle_conn = conn;
        } else {
            conn.close();
        }

        // With a session established, open the standalone GET stream for
        // server-initiated messages (no-op while healthy/unsupported).
        if (!self.shutting_down) self.maybeStartPush();
        self.maybeStartDelete();
    }

    fn onPostEnd(self: *Bridge, conn: *httpc.Conn, err: ?anyerror) void {
        const e = err orelse error.SocketError;
        if (conn.role.post.kind == .legacy) {
            // Legacy POST failed: drain its pending id + synthesize an error.
            if (conn.role.post.line) |line| {
                const rid = mcp.getRequestId(line);
                if (rid) |r| {
                    if (self.leg_pending.fetchRemove(r)) |kv| self.alloc.free(kv.key);
                }
                self.writeTransportError(rid, @errorName(e));
            }
            conn.close();
            self.maybeStartDelete();
            return;
        }
        // Stale keep-alive conn: retry once on a fresh connection.
        if (conn.role.post.reused and !conn.role.post.retried) {
            if (conn.role.post.line) |line| {
                const owned = self.alloc.dupe(u8, line) catch null;
                conn.close();
                if (owned) |l| {
                    defer self.alloc.free(l);
                    if (self.cfg.verbose) std.debug.print("mcp-bridge: stale connection ({s}), retrying once on fresh connection\n", .{@errorName(e)});
                    self.streamableSendLine(l, conn_auth_retried(conn), true);
                }
                return;
            }
        }
        const rid = if (conn.role.post.line) |l| mcp.getRequestId(l) else null;
        conn.close();
        self.writeTransportError(rid, @errorName(e));
        self.maybeStartDelete();
    }

    fn conn_auth_retried(conn: *httpc.Conn) bool {
        return switch (conn.role) {
            .post => |p| p.auth_retried,
            .sse_get => false,
        };
    }

    /// Best-effort session termination (DELETE) during shutdown.
    fn startDelete(self: *Bridge) void {
        const t = self.cfg.target;
        var headers: std.ArrayList([]const u8) = .empty;
        defer headers.deinit(self.alloc);
        var session_hdr: ?[]const u8 = null;
        defer if (session_hdr) |h| self.alloc.free(h);
        var auth_hdr: ?[]const u8 = null;
        defer if (auth_hdr) |h| self.alloc.free(h);
        self.buildHeaders(&headers, &session_hdr, &auth_hdr) catch return;

        var req = httpc.buildRequest(self.alloc, "DELETE", t.path, t.host, "application/json", null, headers.items, null) catch return;
        errdefer req.deinit(self.alloc);
        const conn = httpc.Conn.startPost(self.alloc, &self.evp, self.handler(), t, req, null, null, self.verifier) catch return;
        self.delete_conn = conn;
        self.trackConn(conn);
    }

    // -------------------------------------- streamable GET push stream ----

    /// Open the standalone GET SSE stream once initialize has produced a
    /// session id. Tolerates 404/405 (server has no GET stream). Cheap
    /// no-op while the stream is healthy. One restart after a dropped
    /// stream.
    pub fn maybeStartPush(self: *Bridge) void {
        if (self.mode != .streamable) return;
        if (self.session_id == null) return;
        if (self.push_unsupported) return;
        if (self.push_conn != null) return;
        if (self.push_dead) {
            if (self.push_retried) return;
            self.push_retried = true;
        }
        self.openPush(false);
    }

    fn openPush(self: *Bridge, auth_retried: bool) void {
        if (self.cfg.oauth != null) {
            self.ensureAuth(null) catch {
                self.push_dead = true;
                return;
            };
        }

        var headers: std.ArrayList([]const u8) = .empty;
        defer headers.deinit(self.alloc);
        var owned: std.ArrayList([]const u8) = .empty;
        defer {
            for (owned.items) |h| self.alloc.free(@constCast(h));
            owned.deinit(self.alloc);
        }
        self.streamHeaders(self.push_last_event_id, &headers, &owned) catch {
            self.push_dead = true;
            return;
        };
        const session_hdr = std.fmt.allocPrint(self.alloc, "MCP-Session-Id: {s}", .{self.session_id.?}) catch {
            self.push_dead = true;
            return;
        };
        defer self.alloc.free(session_hdr);
        headers.append(self.alloc, session_hdr) catch {};
        headers.append(self.alloc, "MCP-Protocol-Version: 2025-03-26") catch {};

        const req = httpc.buildRequest(self.alloc, "GET", self.cfg.target.path, self.cfg.target.host, "text/event-stream", null, headers.items, null) catch {
            self.push_dead = true;
            return;
        };
        const conn = httpc.Conn.startStreamGet(self.alloc, &self.evp, self.handler(), self.cfg.target, req, self.verifier) catch {
            self.push_dead = true;
            return;
        };
        self.push_conn = conn;
        self.push_dead = false;
        self.push_auth_retried = auth_retried;
        self.trackConn(conn);
        if (self.cfg.verbose) std.debug.print("mcp-bridge: [push] GET stream opening\n", .{});
    }

    fn onPushStreamHead(self: *Bridge, conn: *httpc.Conn, status: u16, is_sse: bool, www_authenticate: ?[]const u8) void {
        if (status == 404 or status == 405) {
            if (self.cfg.verbose) std.debug.print("mcp-bridge: [push] server has no GET stream ({d})\n", .{status});
            self.push_unsupported = true;
            conn.close();
            return;
        }
        if (status == 401 and !self.push_auth_retried and
            (self.cfg.oauth != null or self.tokens != null))
        {
            // Push is optional: only chase auth when OAuth is already in
            // play — never pop a surprise browser flow for it.
            const wa = if (www_authenticate) |h| self.alloc.dupe(u8, h) catch null else null;
            defer if (wa) |h| self.alloc.free(h);
            conn.close();
            if (self.tokens != null)
                self.reauthOn401(wa) catch {
                    self.push_dead = true;
                    return;
                }
            else
                self.ensureAuth(wa) catch {
                    self.push_dead = true;
                    return;
                };
            self.openPush(true);
            return;
        }
        if (status != 200 or !is_sse) {
            if (self.cfg.verbose) std.debug.print("mcp-bridge: [push] HTTP {d} (sse={})\n", .{ status, is_sse });
            self.push_dead = true;
            conn.close();
            return;
        }
        conn.proceedStream();
        if (self.cfg.verbose) std.debug.print("mcp-bridge: [push] GET stream open\n", .{});
    }

    // ------------------------------------------------- legacy SSE ----

    /// Open (or re-open) the legacy event stream. Asynchronous: the
    /// endpoint event resolves readiness; stdin lines queue meanwhile.
    /// (pub for the resume integration test, which must start the stream
    /// without an accompanying POST.)
    pub fn startLegacyTransport(self: *Bridge, auth_retried: bool) void {
        if (self.leg_conn != null and !self.leg_dead) return; // already connecting/open

        if (self.cfg.oauth != null) {
            self.ensureAuth(null) catch |err| {
                self.legacyFailed(err);
                return;
            };
        }

        var headers: std.ArrayList([]const u8) = .empty;
        defer headers.deinit(self.alloc);
        var owned: std.ArrayList([]const u8) = .empty;
        defer {
            for (owned.items) |h| self.alloc.free(@constCast(h));
            owned.deinit(self.alloc);
        }
        self.streamHeaders(self.leg_last_event_id, &headers, &owned) catch {
            self.leg_dead = true;
            return;
        };

        const req = httpc.buildRequest(self.alloc, "GET", self.cfg.target.path, self.cfg.target.host, "text/event-stream", null, headers.items, null) catch {
            self.leg_dead = true;
            return;
        };
        const conn = httpc.Conn.startStreamGet(self.alloc, &self.evp, self.handler(), self.cfg.target, req, self.verifier) catch {
            self.leg_dead = true;
            return;
        };
        self.leg_conn = conn;
        self.leg_dead = false;
        self.leg_ready = false;
        self.leg_auth_retried = auth_retried;
        self.trackConn(conn);
        if (self.cfg.verbose) std.debug.print("mcp-bridge: [sse] event stream connecting\n", .{});
    }

    fn onLegacyStreamHead(self: *Bridge, conn: *httpc.Conn, status: u16, is_sse: bool, www_authenticate: ?[]const u8) void {
        if (status == 404 or status == 405) {
            if (self.cfg.verbose) std.debug.print("mcp-bridge: [sse] GET {s} -> {d} (no event stream)\n", .{ self.cfg.target.path, status });
            conn.close();
            if (self.probe_via_get and !self.probed) {
                // sse_first: no event stream here — commit to Streamable HTTP.
                if (self.cfg.verbose) std.debug.print("mcp-bridge: [sse] no event stream, using Streamable HTTP\n", .{});
                self.probe_via_get = false;
                self.mode = .streamable;
                self.probed = true;
                self.flushQueueAsStreamable();
                return;
            }
            self.legacyFailed(error.NoSseEndpoint);
            return;
        }
        if (status == 401 and !self.leg_auth_retried) {
            const wa = if (www_authenticate) |h| self.alloc.dupe(u8, h) catch null else null;
            defer if (wa) |h| self.alloc.free(h);
            conn.close();
            self.leg_conn = null;
            if (self.cfg.verbose) std.debug.print("mcp-bridge: [sse] 401 on GET stream, running OAuth\n", .{});
            if (self.tokens != null)
                self.reauthOn401(wa) catch |err| {
                    self.legacyFailed(err);
                    return;
                }
            else
                self.ensureAuth(wa) catch |err| {
                    self.legacyFailed(err);
                    return;
                };
            self.leg_dead = true; // force a fresh conn
            self.startLegacyTransport(true);
            return;
        }
        if (status != 200 or !is_sse) {
            if (self.cfg.verbose) std.debug.print("mcp-bridge: [sse] GET stream -> HTTP {d} (sse={})\n", .{ status, is_sse });
            log.err("event stream endpoint returned HTTP {d}", .{status});
            conn.close();
            self.legacyFailed(error.SseEndpointUnavailable);
            return;
        }
        conn.proceedStream();
    }

    fn legacyDispatchEvent(self: *Bridge, conn: *httpc.Conn, ev: *const sse.Event) void {
        _ = conn;
        if (std.mem.eql(u8, ev.event, "endpoint")) {
            // POST endpoint URL for client->server messages.
            self.setLegacyEndpoint(ev.data);
            return;
        }
        if (ev.id) |id| {
            if (self.leg_last_event_id) |old| self.alloc.free(old);
            self.leg_last_event_id = self.alloc.dupe(u8, id) catch null;
        }
        // A response drains its pending id; everything (responses AND
        // server-pushed messages) goes to the client.
        if (mcp.getRequestId(ev.data)) |rid| {
            if (self.leg_pending.fetchRemove(rid)) |kv| self.alloc.free(kv.key);
        }
        if (self.cfg.verbose) std.debug.print("mcp-bridge: [sse] << {s}\n", .{ev.data});
        self.out.writeLine(ev.data);
        self.maybeCloseLegacyAtShutdown();
    }

    /// During shutdown the legacy stream is the response channel for
    /// queued/pending work; once both drain, the stream's job is done.
    /// (Created mid-shutdown by an in-flight 404/405 fallback.)
    fn maybeCloseLegacyAtShutdown(self: *Bridge) void {
        if (!self.shutting_down) return;
        if (self.leg_pending.count() != 0 or self.leg_queue.items.len != 0) return;
        if (self.leg_conn) |c| {
            c.close();
            self.leg_conn = null;
        }
    }

    fn setLegacyEndpoint(self: *Bridge, url_data: []const u8) void {
        // Resolve the endpoint event payload to an absolute URL. Per the
        // 2024-11-05 spec it's usually a relative reference against the
        // SSE endpoint's origin; absolute URLs are accepted as-is.
        var abs: []u8 = undefined;
        if (std.mem.startsWith(u8, url_data, "http://") or std.mem.startsWith(u8, url_data, "https://")) {
            abs = self.alloc.dupe(u8, url_data) catch {
                self.legacyFailed(error.OutOfMemory);
                return;
            };
        } else {
            const origin = self.cfg.target.origin(self.alloc) catch {
                self.legacyFailed(error.OutOfMemory);
                return;
            };
            defer self.alloc.free(origin);
            abs = (if (url_data.len > 0 and url_data[0] == '/')
                std.fmt.allocPrint(self.alloc, "{s}{s}", .{ origin, url_data })
            else
                std.fmt.allocPrint(self.alloc, "{s}/{s}", .{ origin, url_data })) catch {
                self.legacyFailed(error.OutOfMemory);
                return;
            };
        }
        const target = http.parseUrl(abs) catch {
            self.alloc.free(abs);
            if (self.cfg.verbose) std.debug.print("mcp-bridge: [sse] bad endpoint URL '{s}'\n", .{url_data});
            // Without an endpoint the transport is unusable.
            self.legacyFailed(error.SseEndpointUnavailable);
            return;
        };
        if (self.leg_endpoint_url) |old| self.alloc.free(old);
        self.leg_endpoint_url = abs;
        self.leg_endpoint = target;
        self.leg_ready = true;
        self.leg_ready_ever = true;
        self.leg_reconnecting = false;
        self.leg_auth_retried = false;
        if (self.probe_via_get and !self.probed) {
            self.probe_via_get = false;
            self.mode = .legacy;
            self.probed = true;
        }
        if (self.cfg.verbose) std.debug.print("mcp-bridge: [sse] endpoint: {s}\n", .{abs});
        self.flushQueueAsLegacy();
    }

    /// The legacy transport cannot serve (start failure, bad head, bad
    /// endpoint): fail queued lines + pending requests.
    fn legacyFailed(self: *Bridge, err: anyerror) void {
        const was_probe = self.probe_via_get and !self.probed;
        self.probe_via_get = false;
        self.leg_dead = true;
        self.leg_ready = false;
        if (self.leg_conn) |conn| {
            conn.close();
            self.leg_conn = null;
        }
        self.failPending(err);
        self.failQueue(err);
        if (was_probe and self.cfg.transport == .sse_first and !self.leg_ready_ever) {
            // Startup probe failure is fatal (matches the serial core).
            self.fatal = err;
            self.beginShutdown();
        }
    }

    /// Stream dropped: fail every pending request so the client never
    /// hangs; queued lines survive for the reconnect.
    fn onLegacyStreamEnd(self: *Bridge, conn: *httpc.Conn, err: ?anyerror) void {
        conn.close();
        const e = err orelse error.SseEndpointUnavailable;
        if (self.cfg.verbose) std.debug.print("mcp-bridge: [sse] event stream lost\n", .{});
        self.leg_dead = true;
        self.leg_ready = false;
        self.failPending(e);
        // Queued lines need the stream: one immediate reconnect attempt;
        // if it dies too, the queue fails on the next onEnd.
        if (self.leg_queue.items.len > 0 and !self.leg_reconnecting) {
            self.leg_reconnecting = true;
            self.leg_dead = true;
            self.startLegacyTransport(false);
        } else if (self.leg_queue.items.len > 0) {
            self.leg_reconnecting = false;
            self.failQueue(e);
        }
    }

    fn failPending(self: *Bridge, err: anyerror) void {
        var it = self.leg_pending.iterator();
        while (it.next()) |entry| {
            self.writeTransportError(entry.key_ptr.*, @errorName(err));
            self.alloc.free(entry.key_ptr.*);
        }
        self.leg_pending.clearRetainingCapacity();
    }

    fn failQueue(self: *Bridge, err: anyerror) void {
        for (self.leg_queue.items) |line| {
            const is_request = std.mem.indexOf(u8, line, "\"method\"") != null;
            if (is_request) self.writeTransportError(mcp.getRequestId(line), @errorName(err));
            self.alloc.free(line);
        }
        self.leg_queue.clearRetainingCapacity();
    }

    fn flushQueueAsLegacy(self: *Bridge) void {
        const queued = self.leg_queue.toOwnedSlice(self.alloc) catch return;
        defer self.alloc.free(queued);
        for (queued) |line| {
            defer self.alloc.free(line);
            self.legacySendLine(line);
        }
    }

    fn flushQueueAsStreamable(self: *Bridge) void {
        const queued = self.leg_queue.toOwnedSlice(self.alloc) catch return;
        defer self.alloc.free(queued);
        for (queued) |line| {
            defer self.alloc.free(line);
            self.streamableSendLine(line, false, false);
        }
    }

    /// Entry point for one stdin line in legacy mode: send now when the
    /// endpoint is ready, else (re)start the stream and queue.
    fn legacySendLine(self: *Bridge, line: []const u8) void {
        if (self.leg_conn == null or self.leg_dead) {
            self.leg_reconnecting = false;
            self.startLegacyTransport(false);
        }
        if (!self.leg_ready) {
            const owned = self.alloc.dupe(u8, line) catch return;
            self.leg_queue.append(self.alloc, owned) catch self.alloc.free(owned);
            return;
        }
        self.legacyPostNow(line);
    }

    /// POST one JSON-RPC message to the legacy session endpoint. The
    /// server answers 2xx (202 Accepted, no body); the JSON-RPC response
    /// arrives on the event stream.
    fn legacyPostNow(self: *Bridge, line: []const u8) void {
        const rid: ?[]const u8 = mcp.getRequestId(line);
        const is_request = std.mem.indexOf(u8, line, "\"method\"") != null;

        const ep = self.leg_endpoint orelse {
            if (rid != null and is_request) self.writeTransportError(rid, "SseEndpointUnavailable");
            return;
        };

        // Register the id before POSTing so a fast response can't race
        // ahead of the pending insert.
        if (rid != null and is_request) {
            const key = self.alloc.dupe(u8, rid.?) catch return;
            self.leg_pending.put(self.alloc, key, {}) catch {
                self.alloc.free(key);
                return;
            };
        }

        var headers: std.ArrayList([]const u8) = .empty;
        defer headers.deinit(self.alloc);
        var auth_hdr: ?[]const u8 = null;
        defer if (auth_hdr) |h| self.alloc.free(h);
        self.commonHeaders(&headers, &auth_hdr) catch {
            if (rid != null and is_request) {
                if (self.leg_pending.fetchRemove(rid.?)) |kv| self.alloc.free(kv.key);
                self.writeTransportError(rid, "OutOfMemory");
            }
            return;
        };

        var req = httpc.buildRequest(self.alloc, "POST", ep.path, ep.host, "application/json, text/event-stream", "application/json", headers.items, line) catch {
            if (rid != null and is_request) {
                if (self.leg_pending.fetchRemove(rid.?)) |kv| self.alloc.free(kv.key);
                self.writeTransportError(rid, "OutOfMemory");
            }
            return;
        };
        errdefer req.deinit(self.alloc);

        const conn = httpc.Conn.startPost(self.alloc, &self.evp, self.handler(), ep, req, null, line, null) catch |err| {
            if (rid != null and is_request) {
                if (self.leg_pending.fetchRemove(rid.?)) |kv| self.alloc.free(kv.key);
                self.writeTransportError(rid, @errorName(err));
            }
            return;
        };
        conn.role.post.kind = .legacy;
        // Cross-origin endpoints get their own verifier.
        if (ep.secure) {
            self.setupConnVerifier(conn, ep) catch |err| {
                if (self.cfg.verbose) std.debug.print("mcp-bridge: [sse] verifier init failed: {s}\n", .{@errorName(err)});
                conn.close();
                if (rid != null and is_request) {
                    if (self.leg_pending.fetchRemove(rid.?)) |kv| self.alloc.free(kv.key);
                    self.writeTransportError(rid, "VerifierFailed");
                }
                return;
            };
        }
        self.trackConn(conn);
    }

    /// Assign the verifier for a conn's target: the session verifier when
    /// the origin matches, else a fresh per-conn one (conn-owned; the TLS
    /// verify hook runs asynchronously after the handshake now).
    fn setupConnVerifier(self: *Bridge, conn: *httpc.Conn, t: Target) !void {
        if (self.verifier) |v| {
            if (std.mem.eql(u8, v.host, t.host) and v.port == t.port) {
                conn.verifier = v;
                return;
            }
        }
        conn.owned_verifier = try platform.Verifier.init(self.alloc, t.host, t.port, self.cfg.verbose);
    }

    /// The legacy POST's HTTP response: 2xx = accepted (the JSON-RPC
    /// response arrives on the event stream); 401 re-auths once and
    /// resends; anything else synthesizes an error for the request id.
    fn handleLegacyPostResponse(self: *Bridge, conn: *httpc.Conn, resp: http.Response) void {
        defer self.maybeStartDelete();
        var r = resp;
        defer r.deinit(conn.alloc);

        if (r.status == 401 and !conn.role.post.auth_retried) {
            const wa = if (r.www_authenticate) |h| self.alloc.dupe(u8, h) catch null else null;
            defer if (wa) |h| self.alloc.free(h);
            const line = if (conn.role.post.line) |l| self.alloc.dupe(u8, l) catch null else null;
            defer if (line) |l| self.alloc.free(l);
            conn.close();
            if (line == null) return;
            if (self.tokens != null)
                self.reauthOn401(wa) catch |err| {
                    self.legacyPostFailed(line.?, @errorName(err));
                    return;
                }
            else
                self.ensureAuth(wa) catch |err| {
                    self.legacyPostFailed(line.?, @errorName(err));
                    return;
                };
            self.legacyPostResend(line.?);
            return;
        }

        if (r.status >= 200 and r.status < 300) {
            conn.close();
            return; // accepted; the response arrives on the event stream
        }

        if (self.cfg.verbose) std.debug.print("mcp-bridge: [sse] POST rejected: HTTP {d}\n", .{r.status});
        const line = conn.role.post.line;
        self.legacyPostFailed(if (line) |l| l else "", "SsePostRejected");
        conn.close();
    }

    fn legacyPostResend(self: *Bridge, line: []const u8) void {
        // Fresh conn to the same endpoint, auth_retried carried.
        const ep = self.leg_endpoint orelse {
            self.legacyPostFailed(line, "SseEndpointUnavailable");
            return;
        };
        var headers: std.ArrayList([]const u8) = .empty;
        defer headers.deinit(self.alloc);
        var auth_hdr: ?[]const u8 = null;
        defer if (auth_hdr) |h| self.alloc.free(h);
        self.commonHeaders(&headers, &auth_hdr) catch {
            self.legacyPostFailed(line, "OutOfMemory");
            return;
        };
        var req = httpc.buildRequest(self.alloc, "POST", ep.path, ep.host, "application/json, text/event-stream", "application/json", headers.items, line) catch {
            self.legacyPostFailed(line, "OutOfMemory");
            return;
        };
        errdefer req.deinit(self.alloc);
        const conn = httpc.Conn.startPost(self.alloc, &self.evp, self.handler(), ep, req, null, line, null) catch |err| {
            self.legacyPostFailed(line, @errorName(err));
            return;
        };
        conn.role.post.kind = .legacy;
        conn.role.post.auth_retried = true;
        if (ep.secure) {
            self.setupConnVerifier(conn, ep) catch {
                conn.close();
                self.legacyPostFailed(line, "VerifierFailed");
                return;
            };
        }
        self.trackConn(conn);
    }

    fn legacyPostFailed(self: *Bridge, line: []const u8, msg: []const u8) void {
        const rid = mcp.getRequestId(line);
        if (rid) |r| {
            if (self.leg_pending.fetchRemove(r)) |kv| self.alloc.free(kv.key);
        }
        self.writeTransportError(rid, msg);
    }

    // ----------------------------------------------------- shared bits ----

    /// Extra headers every upstream request carries: configured custom
    /// headers + bearer token snapshot. The auth header backing is
    /// caller-owned (auth_hdr out-param).
    fn commonHeaders(self: *Bridge, headers: *std.ArrayList([]const u8), auth_hdr: *?[]const u8) !void {
        try headers.appendSlice(self.alloc, self.cfg.headers.items);
        if (try self.authHeader(auth_hdr)) |h| try headers.append(self.alloc, h);
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

    var bridge = try Bridge.init(alloc, &cfg, undefined, if (verifier != null) &verifier.? else null);
    bridge.out = bridge.queuedOut();
    defer bridge.deinit();
    bridge.attachStdio();

    // Transport strategy: sse-first probes the event stream up front;
    // sse-only commits; http-first defers probing to the first POST's
    // status; http-only never probes.
    switch (cfg.transport) {
        .http_only => bridge.probed = true,
        .http_first => {},
        .sse_only => {
            bridge.mode = .legacy;
            bridge.probed = true;
        },
        .sse_first => {
            bridge.probe_via_get = true;
            bridge.startLegacyTransport(false);
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

    if (cfg.verbose) std.debug.print("mcp-bridge: event loop starting\n", .{});
    try bridge.run();

    if (bridge.fatal) |err| return err;
    if (cfg.verbose) std.debug.print("mcp-bridge: stdin closed, exiting\n", .{});
}
