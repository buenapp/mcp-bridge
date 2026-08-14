// OAuth loopback redirect listener + browser launch.
//
// HTTP listener on 127.0.0.1:<ephemeral> for the authorization code
// redirect, with an accept timeout so a stalled browser flow cannot hang
// the bridge forever. Multi-instance coordination (issue #3): while the
// holder waits for the redirect, second instances long-poll it with
// GET /wait-for-auth; those conns are held open and answered once the
// code lands (or dropped on failure — EOF is their retry signal).
//
// Browser launch mirrors the proven MailMCP order ($BROWSER FIRST — the
// remote-SSH seamless path; see plan "Remote SSH sessions"):
//   1. $BROWSER (VS Code/Windsurf Remote helper: opens locally + forwards
//      the loopback port back to the remote host)
//   2. Windows: ShellExecuteA
//   3. POSIX with VSCODE_IPC_HOOK_CLI/WINDSURF_IPC_HOOK_CLI: code/windsurf --open-url
//   4. POSIX with DISPLAY/WAYLAND_DISPLAY: xdg-open
//   5. Caller prints the URL on stderr as the manual fallback.

const std = @import("std");
const builtin = @import("builtin");

const is_windows = builtin.os.tag == .windows;
const win = if (is_windows) @import("win.zig") else struct {};

const log = std.log.scoped(.oauth);

const ConnFd = if (is_windows) win.SOCKET else std.posix.fd_t;

pub const LoopbackError = error{
    ListenFailed,
    AcceptFailed,
    Timeout,
    BadRequest,
    StateMismatch,
    NoCode,
    OutOfMemory,
};

pub const Listener = struct {
    sock: ConnFd,
    port: u16,
    timeout_ms: u32,
    /// Hostname used in the redirect URI (--host; default "localhost").
    /// The bind address is the host's first IPv4 resolution.
    display_host: []const u8 = "localhost",
    /// Per-conn read cap so an idle conn cannot stall the flow (tests
    /// shrink this).
    conn_timeout_ms: u32 = 10_000,
    /// Held /wait-for-auth pollers (issue #3). waitForCode only COLLECTS
    /// them; the caller answers (completeWaiters) once the tokens are
    /// actually cached, or drops them (dropWaiters) on any failure —
    /// a 200 must mean "tokens are on disk NOW".
    held: [8]ConnFd = undefined,
    held_count: usize = 0,

    /// Answer all held pollers (200) and close them. Call AFTER the token
    /// cache is written.
    pub fn completeWaiters(self: *Listener) void {
        for (self.held[0..self.held_count]) |w| {
            self.respond(w, 200, "Authorization complete") catch {};
            sockClose(w);
        }
        self.held_count = 0;
    }

    /// Drop held pollers without an answer (EOF = retry signal). No-op
    /// after completeWaiters.
    pub fn dropWaiters(self: *Listener) void {
        for (self.held[0..self.held_count]) |w| sockClose(w);
        self.held_count = 0;
    }

    /// Bind 127.0.0.1:0 (OS-assigned port) with an accept timeout.
    pub fn init(timeout_ms: u32) LoopbackError!Listener {
        if (is_windows) return initWin(defaultBindAddr(), timeout_ms);
        return initPosix(defaultBindAddr(), timeout_ms);
    }

    /// --host variant: the redirect URI uses `host` and the listener binds
    /// the host's first IPv4 resolution (loopback aliases included — that
    /// is the intended case: authorization servers that reject a bare
    /// "localhost" redirect).
    pub fn initHost(alloc: std.mem.Allocator, timeout_ms: u32, host: []const u8) LoopbackError!Listener {
        const addr = resolveV4(alloc, host, 0) catch return LoopbackError.ListenFailed;
        var l = if (is_windows) try initWin(addr, timeout_ms) else try initPosix(addr, timeout_ms);
        l.display_host = host;
        return l;
    }

    fn defaultBindAddr() std.net.Address {
        return std.net.Address.parseIp4("127.0.0.1", 0) catch unreachable;
    }

    /// First IPv4 address `host` resolves to (literal IPs included).
    pub fn resolveV4(alloc: std.mem.Allocator, host: []const u8, port: u16) !std.net.Address {
        const list = std.net.getAddressList(alloc, host, port) catch return error.ResolveFailed;
        defer list.deinit();
        for (list.addrs) |a| {
            if (a.any.family == std.posix.AF.INET) return a;
        }
        return error.ResolveFailed;
    }

    pub fn deinit(self: *Listener) void {
        sockClose(self.sock);
    }

    /// Redirect URI to register/send: http://<display_host>:<port>/callback
    /// ("localhost" is what the IDE's port forwarding terminates).
    pub fn redirectUri(self: *const Listener, alloc: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(alloc, "http://{s}:{d}/callback", .{ self.display_host, self.port });
    }

    /// Accept connections until the authorization redirect arrives (or the
    /// overall timeout): /callback gets the one-shot parse + state
    /// validation; /wait-for-auth conns (second instances, issue #3) are
    /// HELD open and answered 200 once the code lands. Stray, broken, or
    /// unrelated conns are dropped — they must not fail the flow.
    pub fn waitForCode(self: *Listener, alloc: std.mem.Allocator, expected_state: []const u8) LoopbackError![]u8 {
        var arena = std.heap.ArenaAllocator.init(alloc);
        defer arena.deinit();
        const a = arena.allocator();

        var timer = std.time.Timer.start() catch unreachable;
        while (true) {
            const elapsed_ms: u32 = @intCast(timer.read() / std.time.ns_per_ms);
            if (elapsed_ms >= self.timeout_ms) return LoopbackError.Timeout;
            setSockTimeout(self.sock, self.timeout_ms - elapsed_ms);

            const conn = self.acceptOne() catch |err| switch (err) {
                LoopbackError.Timeout => return LoopbackError.Timeout,
                else => continue, // aborted/stray accept: keep waiting
            };
            // An idle conn must not stall the flow for everyone else.
            setSockTimeout(conn, self.conn_timeout_ms);

            const req = self.readRequest(a, conn) orelse {
                sockClose(conn);
                continue;
            };
            if (std.mem.eql(u8, req.path, "/wait-for-auth")) {
                if (self.held_count < self.held.len) {
                    self.held[self.held_count] = conn;
                    self.held_count += 1;
                } else {
                    self.respond(conn, 503, "Too many waiting instances") catch {};
                    sockClose(conn);
                }
                continue;
            }
            if (!std.mem.eql(u8, req.path, "/callback")) {
                self.respond(conn, 404, "Not found") catch {};
                sockClose(conn);
                continue;
            }

            var code: ?[]const u8 = null;
            var state: ?[]const u8 = null;
            var oauth_err: ?[]const u8 = null;
            var it = std.mem.splitScalar(u8, req.query, '&');
            while (it.next()) |pair| {
                const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
                const k = pair[0..eq];
                const v = try urlDecode(a, pair[eq + 1 ..]);
                if (std.mem.eql(u8, k, "code")) {
                    code = v;
                } else if (std.mem.eql(u8, k, "state")) {
                    state = v;
                } else if (std.mem.eql(u8, k, "error")) {
                    oauth_err = v;
                }
            }

            if (oauth_err) |e| {
                const msg = try std.fmt.allocPrint(a, "Authorization failed: {s}", .{e});
                self.respond(conn, 400, msg) catch {};
                sockClose(conn);
                return LoopbackError.BadRequest;
            }
            if (state == null or !std.mem.eql(u8, state.?, expected_state)) {
                self.respond(conn, 400, "State mismatch — possible CSRF, authorization rejected") catch {};
                sockClose(conn);
                return LoopbackError.StateMismatch;
            }
            const c = code orelse {
                self.respond(conn, 400, "Missing authorization code") catch {};
                sockClose(conn);
                return LoopbackError.NoCode;
            };
            self.respond(conn, 200, "Authorization complete — you can close this tab and return to your IDE.") catch {};
            sockClose(conn);
            // Held pollers are answered by the caller (completeWaiters)
            // once the tokens are cached — not before.

            return try alloc.dupe(u8, c);
        }
    }

    const Request = struct {
        path: []const u8, // arena-owned
        query: []const u8, // arena-owned
    };

    /// Read one request head and split path/query; null on any I/O or
    /// shape failure (caller drops the conn and keeps waiting).
    fn readRequest(self: *Listener, a: std.mem.Allocator, conn: ConnFd) ?Request {
        _ = self;
        // Headers are plenty: the request line carries the code.
        var buf: [16384]u8 = undefined;
        var len: usize = 0;
        while (std.mem.indexOf(u8, buf[0..len], "\r\n\r\n") == null and len < buf.len) {
            const n = sockRead(conn, buf[len..]) catch return null;
            if (n == 0) break;
            len += n;
        }
        if (len == 0) return null;

        const line_end = std.mem.indexOf(u8, buf[0..len], "\r\n") orelse return null;
        const request_line = buf[0..line_end];
        // "GET /callback?code=...&state=... HTTP/1.1"
        if (!std.mem.startsWith(u8, request_line, "GET ")) return null;
        const target_end = std.mem.lastIndexOfScalar(u8, request_line, ' ') orelse return null;
        const target = request_line[4..target_end];
        const q = std.mem.indexOfScalar(u8, target, '?');
        return .{
            .path = a.dupe(u8, if (q) |i| target[0..i] else target) catch return null,
            .query = a.dupe(u8, if (q) |i| target[i + 1 ..] else "") catch return null,
        };
    }

    // ------------------------------------------------------- platform io --

    fn initPosix(addr: std.net.Address, timeout_ms: u32) LoopbackError!Listener {
        const s = std.posix.socket(std.posix.AF.INET, std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC, 0) catch
            return LoopbackError.ListenFailed;
        errdefer std.posix.close(s);
        std.posix.setsockopt(s, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1))) catch {};
        std.posix.bind(s, &addr.any, addr.getOsSockLen()) catch return LoopbackError.ListenFailed;
        std.posix.listen(s, 8) catch return LoopbackError.ListenFailed;
        setSockTimeout(s, timeout_ms);

        var bound = defaultBindAddr();
        var blen: std.posix.socklen_t = bound.getOsSockLen();
        std.posix.getsockname(s, &bound.any, &blen) catch return LoopbackError.ListenFailed;
        return .{ .sock = s, .port = bound.getPort(), .timeout_ms = timeout_ms };
    }

    fn initWin(addr: std.net.Address, timeout_ms: u32) LoopbackError!Listener {
        var wsa: win.ws2.WSADATA = undefined;
        if (win.ws2.WSAStartup(0x0202, &wsa) != 0) return LoopbackError.ListenFailed;

        const s = win.ws2.socket(addr.any.family, win.ws2.SOCK.STREAM, 0);
        if (s == win.INVALID_SOCKET) return LoopbackError.ListenFailed;
        errdefer _ = win.ws2.closesocket(s);

        const one: i32 = 1;
        _ = win.ws2.setsockopt(s, win.SOL_SOCKET, win.ws2.SO.REUSEADDR, std.mem.asBytes(&one), @sizeOf(i32));
        if (win.ws2.bind(s, &addr.any, @intCast(addr.getOsSockLen())) != 0) return LoopbackError.ListenFailed;
        if (win.ws2.listen(s, 8) != 0) return LoopbackError.ListenFailed;
        setSockTimeout(s, timeout_ms);

        var bound = defaultBindAddr();
        var blen: i32 = @intCast(bound.getOsSockLen());
        if (win.ws2.getsockname(s, &bound.any, &blen) != 0) return LoopbackError.ListenFailed;
        return .{ .sock = s, .port = bound.getPort(), .timeout_ms = timeout_ms };
    }

    fn acceptOne(self: *Listener) LoopbackError!ConnFd {
        if (is_windows) {
            const c = win.ws2.accept(self.sock, null, null);
            if (c == win.INVALID_SOCKET) {
                if (@intFromEnum(win.ws2.WSAGetLastError()) == win.WSAETIMEDOUT) return LoopbackError.Timeout;
                return LoopbackError.AcceptFailed;
            }
            return c;
        }
        return std.posix.accept(self.sock, null, null, std.posix.SOCK.CLOEXEC) catch |err| switch (err) {
            error.WouldBlock => LoopbackError.Timeout,
            else => LoopbackError.AcceptFailed,
        };
    }

    fn respond(self: *Listener, conn: ConnFd, status: u16, message: []const u8) !void {
        _ = self;
        const status_text = switch (status) {
            200 => "OK",
            400 => "Bad Request",
            404 => "Not Found",
            503 => "Service Unavailable",
            else => "Error",
        };
        var buf: [2048]u8 = undefined;
        const body = std.fmt.bufPrint(&buf, "<!DOCTYPE html><html><head><title>MCP Bridge</title>" ++
            "<style>body{{font-family:system-ui,sans-serif;display:flex;justify-content:center;" ++
            "align-items:center;min-height:100vh;margin:0;background:#f5f5f5}}" ++
            ".card{{background:white;padding:2rem;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,.1);" ++
            "max-width:400px;text-align:center}}</style></head>" ++
            "<body><div class=\"card\"><p>{s}</p></div></body></html>", .{message}) catch return;

        var hbuf: [256]u8 = undefined;
        const head = std.fmt.bufPrint(&hbuf, "HTTP/1.1 {d} {s}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{ status, status_text, body.len }) catch return;

        _ = sockWriteAll(conn, head);
        _ = sockWriteAll(conn, body);
    }
};

pub const WaitResult = enum { done, failed };

/// Long-poll a peer instance's loopback listener (issue #3): block until
/// its interactive flow completes (200) or the connection drops / times
/// out. The peer's accept timeout bounds its flow, so timeout_ms should
/// match it. `host` is the callback host the peer bound (default loopback;
/// a --host alias both instances share).
pub fn waitForAuth(alloc: std.mem.Allocator, port: u16, timeout_ms: u32, host: []const u8) WaitResult {
    const addr = Listener.resolveV4(alloc, host, port) catch return .failed;

    var conn: ConnFd = undefined;
    if (is_windows) {
        var wsa: win.ws2.WSADATA = undefined;
        if (win.ws2.WSAStartup(0x0202, &wsa) != 0) return .failed;
        conn = win.ws2.socket(addr.any.family, win.ws2.SOCK.STREAM, 0);
        if (conn == win.INVALID_SOCKET) return .failed;
        if (win.ws2.connect(conn, &addr.any, @intCast(addr.getOsSockLen())) != 0) {
            sockClose(conn);
            return .failed;
        }
    } else {
        conn = std.posix.socket(std.posix.AF.INET, std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC, 0) catch return .failed;
        std.posix.connect(conn, &addr.any, addr.getOsSockLen()) catch {
            sockClose(conn);
            return .failed;
        };
    }
    defer sockClose(conn);
    setSockTimeout(conn, timeout_ms);

    if (!sockWriteAll(conn, "GET /wait-for-auth HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"))
        return .failed;

    // The status line decides; it always fits in the first segments.
    var buf: [512]u8 = undefined;
    var len: usize = 0;
    while (std.mem.indexOf(u8, buf[0..len], "\r\n") == null and len < buf.len) {
        const n = sockRead(conn, buf[len..]) catch return .failed;
        if (n == 0) return .failed; // dropped without an answer
        len += n;
    }
    return if (std.mem.startsWith(u8, buf[0..len], "HTTP/1.1 200")) .done else .failed;
}

// -------------------------------------------------------- socket helpers --

fn sockClose(conn: ConnFd) void {
    if (is_windows) {
        _ = win.ws2.closesocket(conn);
    } else {
        std.posix.close(conn);
    }
}

fn sockRead(conn: ConnFd, out: []u8) !usize {
    if (is_windows) {
        const n = win.ws2.recv(conn, out.ptr, @intCast(out.len), 0);
        if (n == win.ws2.SOCKET_ERROR) return error.ReadFailed;
        return @intCast(n);
    }
    return std.posix.read(conn, out);
}

fn sockWriteAll(conn: ConnFd, data: []const u8) bool {
    var off: usize = 0;
    while (off < data.len) {
        if (is_windows) {
            const n = win.ws2.send(conn, data.ptr + off, @intCast(data.len - off), 0);
            if (n == win.ws2.SOCKET_ERROR) return false;
            off += @intCast(n);
        } else {
            off += std.posix.write(conn, data[off..]) catch return false;
        }
    }
    return true;
}

fn setSockTimeout(conn: ConnFd, ms: u32) void {
    if (is_windows) {
        const t: i32 = @intCast(ms);
        _ = win.ws2.setsockopt(conn, win.SOL_SOCKET, win.SO_RCVTIMEO, std.mem.asBytes(&t), @sizeOf(i32));
    } else {
        const tv: std.posix.timeval = .{
            .sec = @intCast(ms / 1000),
            .usec = @intCast((ms % 1000) * 1000),
        };
        std.posix.setsockopt(conn, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch {};
    }
}

fn urlDecode(alloc: std.mem.Allocator, s: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        if (s[i] == '%' and i + 3 <= s.len) {
            const hi = std.fmt.charToDigit(s[i + 1], 16) catch {
                try out.append(alloc, s[i]);
                continue;
            };
            const lo = std.fmt.charToDigit(s[i + 2], 16) catch {
                try out.append(alloc, s[i]);
                continue;
            };
            try out.append(alloc, (hi << 4) | lo);
            i += 2;
            continue;
        }
        try out.append(alloc, if (s[i] == '+') ' ' else s[i]);
    }
    return out.toOwnedSlice(alloc);
}

// ------------------------------------------------------------ browser ----

/// Attempt to open a URL in the user's browser. Returns true if a launch
/// command was executed. $BROWSER goes FIRST: on Remote SSH sessions the
/// IDE's helper opens the URL on the local machine and auto-forwards the
/// loopback port — that is what makes the flow seamless.
pub fn openUrl(alloc: std.mem.Allocator, url: []const u8) bool {
    // 1. $BROWSER (VS Code / Windsurf Remote SSH helper, or user choice)
    if (std.process.getEnvVarOwned(alloc, "BROWSER")) |browser| {
        defer alloc.free(browser);
        if (browser.len > 0) {
            if (spawnShell(alloc, browser, url)) return true;
        }
    } else |_| {}

    if (is_windows) return shellExecute(url);

    // 2. IDE CLI via IPC hook env vars (works over Remote SSH)
    if (std.posix.getenv("VSCODE_IPC_HOOK_CLI") != null) {
        if (spawnArgv(alloc, &.{ "code", "--open-url", url })) return true;
    }
    if (std.posix.getenv("WINDSURF_IPC_HOOK_CLI") != null) {
        if (spawnArgv(alloc, &.{ "windsurf", "--open-url", url })) return true;
    }

    // 3. Desktop session only: xdg-open
    if (std.posix.getenv("DISPLAY") != null or std.posix.getenv("WAYLAND_DISPLAY") != null) {
        if (spawnArgv(alloc, &.{ "xdg-open", url })) return true;
    }

    return false;
}

fn spawnShell(alloc: std.mem.Allocator, cmd_prefix: []const u8, url: []const u8) bool {
    // Via sh so "$BROWSER" may itself contain arguments (e.g. "code --open-url").
    const script = std.fmt.allocPrint(alloc, "{s} \"$1\"", .{cmd_prefix}) catch return false;
    defer alloc.free(script);
    var child = std.process.Child.init(&.{ "/bin/sh", "-c", script, "sh", url }, alloc);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Ignore;
    child.spawn() catch return false;
    // Fire-and-forget: browser helpers return immediately; don't block on exit.
    return true;
}

fn spawnArgv(alloc: std.mem.Allocator, argv: []const []const u8) bool {
    var child = std.process.Child.init(argv, alloc);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Ignore;
    child.spawn() catch return false;
    return true;
}

fn shellExecute(url: []const u8) bool {
    if (!is_windows) return false;
    const S = struct {
        pub extern "shell32" fn ShellExecuteA(
            hwnd: ?*anyopaque,
            lpOperation: ?[*:0]const u8,
            lpFile: [*:0]const u8,
            lpParameters: ?[*:0]const u8,
            lpDirectory: ?[*:0]const u8,
            nShowCmd: i32,
        ) isize;
    };
    var buf: [2083]u8 = undefined; // INTERNET_MAX_URL_LENGTH
    if (url.len >= buf.len) return false;
    @memcpy(buf[0..url.len], url);
    buf[url.len] = 0;
    const rc = S.ShellExecuteA(null, "open", @ptrCast(&buf), null, null, 1); // SW_SHOWNORMAL
    return rc > 32;
}

// ------------------------------------------------------------------ tests --

test "urlDecode: percent, plus, malformed" {
    const alloc = std.testing.allocator;
    const d1 = try urlDecode(alloc, "a%20b%2Bc%2Fd%3De");
    defer alloc.free(d1);
    try std.testing.expectEqualStrings("a b+c/d=e", d1);
    const d2 = try urlDecode(alloc, "plain");
    defer alloc.free(d2);
    try std.testing.expectEqualStrings("plain", d2);
    const d3 = try urlDecode(alloc, "100%25");
    defer alloc.free(d3);
    try std.testing.expectEqualStrings("100%", d3);
}

/// Connect a client socket to the listener and send a full request head.
fn testClient(port: u16, request: []const u8) !std.posix.fd_t {
    const addr = std.net.Address.parseIp4("127.0.0.1", port) catch unreachable;
    const c = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC, 0);
    errdefer std.posix.close(c);
    try std.posix.connect(c, &addr.any, addr.getOsSockLen());
    if (!sockWriteAll(c, request)) return error.WriteFailed;
    return c;
}

fn testReadAll(c: std.posix.fd_t, buf: []u8) usize {
    var len: usize = 0;
    while (len < buf.len) {
        const n = std.posix.read(c, buf[len..]) catch break;
        if (n == 0) break;
        len += n;
    }
    return len;
}

test "waitForCode: wait-for-auth pollers are held and answered on callback" {
    if (comptime is_windows) return error.SkipZigTest;
    const alloc = std.testing.allocator;

    var listener = try Listener.init(30_000);
    defer listener.deinit();
    defer listener.dropWaiters();

    // Both requests land in the accept backlog before waitForCode runs, so
    // the holder processes them in order: waiter first (held), callback
    // second (completes the flow). The caller then answers the waiter via
    // completeWaiters once the tokens are cached.
    const w = try testClient(listener.port, "GET /wait-for-auth HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
    defer std.posix.close(w);
    const cb = try testClient(listener.port, "GET /callback?code=abc123&state=st HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
    defer std.posix.close(cb);

    const code = try listener.waitForCode(alloc, "st");
    defer alloc.free(code);
    try std.testing.expectEqualStrings("abc123", code);
    try std.testing.expectEqual(@as(usize, 1), listener.held_count);
    listener.completeWaiters();

    var buf: [2048]u8 = undefined;
    const wn = testReadAll(w, &buf);
    try std.testing.expect(std.mem.startsWith(u8, buf[0..wn], "HTTP/1.1 200"));
    const cn = testReadAll(cb, &buf);
    try std.testing.expect(std.mem.startsWith(u8, buf[0..cn], "HTTP/1.1 200"));
}

test "waitForCode: state mismatch fails the flow and drops waiters" {
    if (comptime is_windows) return error.SkipZigTest;
    const alloc = std.testing.allocator;

    var listener = try Listener.init(30_000);
    defer listener.deinit();
    defer listener.dropWaiters();

    const w = try testClient(listener.port, "GET /wait-for-auth HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
    defer std.posix.close(w);
    const cb = try testClient(listener.port, "GET /callback?code=abc&state=WRONG HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
    defer std.posix.close(cb);

    try std.testing.expectError(LoopbackError.StateMismatch, listener.waitForCode(alloc, "st"));
    try std.testing.expectEqual(@as(usize, 1), listener.held_count);
    listener.dropWaiters(); // the caller's failure path (defer in main.zig)

    // The waiter got EOF (dropped without an answer) — its retry signal.
    var buf: [2048]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 0), testReadAll(w, &buf));
    const cn = testReadAll(cb, &buf);
    try std.testing.expect(std.mem.startsWith(u8, buf[0..cn], "HTTP/1.1 400"));
}

test "waitForCode: stray conns are dropped without failing the flow" {
    if (comptime is_windows) return error.SkipZigTest;
    const alloc = std.testing.allocator;

    var listener = try Listener.init(30_000);
    defer listener.deinit();
    listener.conn_timeout_ms = 100; // keep the idle-conn probe fast

    // Garbage request, an unrelated path, and a conn that never sends —
    // none may abort the flow; the real callback still succeeds.
    const junk = try testClient(listener.port, "this is not http\r\n\r\n");
    defer std.posix.close(junk);
    const favicon = try testClient(listener.port, "GET /favicon.ico HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
    defer std.posix.close(favicon);
    const silent = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC, 0);
    defer std.posix.close(silent);
    {
        const addr = std.net.Address.parseIp4("127.0.0.1", listener.port) catch unreachable;
        try std.posix.connect(silent, &addr.any, addr.getOsSockLen());
    }
    const cb = try testClient(listener.port, "GET /callback?code=ok&state=st HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
    defer std.posix.close(cb);

    const code = try listener.waitForCode(alloc, "st");
    defer alloc.free(code);
    try std.testing.expectEqualStrings("ok", code);

    var buf: [2048]u8 = undefined;
    const fav_len = testReadAll(favicon, &buf);
    try std.testing.expect(std.mem.startsWith(u8, buf[0..fav_len], "HTTP/1.1 404"));
}

test "initHost: display host in redirect URI, loopback alias binds" {
    if (comptime is_windows) return error.SkipZigTest;
    const alloc = std.testing.allocator;

    var l = try Listener.initHost(alloc, 5_000, "127.0.0.1");
    defer l.deinit();
    const uri = try l.redirectUri(alloc);
    defer alloc.free(uri);
    try std.testing.expectEqualStrings("http://127.0.0.1:", uri[0.."http://127.0.0.1:".len]);

    // "localhost" resolves to a loopback bind.
    var l2 = try Listener.initHost(alloc, 5_000, "localhost");
    defer l2.deinit();
    try std.testing.expect(l2.port != 0);
    const uri2 = try l2.redirectUri(alloc);
    defer alloc.free(uri2);
    try std.testing.expect(std.mem.startsWith(u8, uri2, "http://localhost:"));

    // Unresolvable host fails cleanly.
    try std.testing.expectError(LoopbackError.ListenFailed, Listener.initHost(alloc, 5_000, "no-such-host.invalid"));
}

test "waitForAuth: done on 200, failed on drop, failed on refused" {
    if (comptime is_windows) return error.SkipZigTest;
    const alloc = std.testing.allocator;

    // Mini server thread: answer 200 once.
    const Srv = struct {
        fn answer200(l: *Listener) void {
            const conn = l.acceptOne() catch return;
            defer sockClose(conn);
            var buf: [512]u8 = undefined;
            _ = sockRead(conn, &buf) catch return;
            l.respond(conn, 200, "done") catch {};
        }
        fn drop(l: *Listener) void {
            const conn = l.acceptOne() catch return;
            sockClose(conn);
        }
    };

    var l1 = try Listener.init(10_000);
    defer l1.deinit();
    const t1 = try std.Thread.spawn(.{}, Srv.answer200, .{&l1});
    try std.testing.expectEqual(WaitResult.done, waitForAuth(alloc, l1.port, 5_000, "127.0.0.1"));
    t1.join();

    var l2 = try Listener.init(10_000);
    defer l2.deinit();
    const t2 = try std.Thread.spawn(.{}, Srv.drop, .{&l2});
    try std.testing.expectEqual(WaitResult.failed, waitForAuth(alloc, l2.port, 5_000, "127.0.0.1"));
    t2.join();

    // Nothing listening → connect refused → failed.
    var l3 = try Listener.init(10_000);
    const refused_port = l3.port;
    l3.deinit();
    try std.testing.expectEqual(WaitResult.failed, waitForAuth(alloc, refused_port, 1_000, "127.0.0.1"));
}
