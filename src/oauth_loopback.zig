// OAuth loopback redirect listener + browser launch.
//
// One-shot HTTP listener on 127.0.0.1:<ephemeral> for the authorization
// code redirect. Cross-platform (Winsock / POSIX sockets), accept timeout
// so a stalled browser flow cannot hang the bridge forever.
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
    sock: if (is_windows) win.SOCKET else std.posix.fd_t,
    port: u16,

    /// Bind 127.0.0.1:0 (OS-assigned port) with an accept timeout.
    pub fn init(timeout_ms: u32) LoopbackError!Listener {
        if (is_windows) return initWin(timeout_ms);
        return initPosix(timeout_ms);
    }

    pub fn deinit(self: *Listener) void {
        if (is_windows) {
            _ = win.ws2.closesocket(self.sock);
        } else {
            std.posix.close(self.sock);
        }
    }

    /// Redirect URI to register/send: http://localhost:<port>/callback
    /// ("localhost" is what the IDE's port forwarding terminates).
    pub fn redirectUri(self: *const Listener, alloc: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(alloc, "http://localhost:{d}/callback", .{self.port});
    }

    /// Accept exactly one connection (subject to the timeout), parse the
    /// authorization redirect, validate state, answer the browser, and
    /// return an owned copy of the authorization code.
    pub fn waitForCode(self: *Listener, alloc: std.mem.Allocator, expected_state: []const u8) LoopbackError![]u8 {
        var arena = std.heap.ArenaAllocator.init(alloc);
        defer arena.deinit();
        const a = arena.allocator();

        const conn = self.acceptOne() catch |err| return err;
        defer self.closeConn(conn);

        // Read the request (headers are plenty: request line carries the code)
        var buf: [16384]u8 = undefined;
        var len: usize = 0;
        while (std.mem.indexOf(u8, buf[0..len], "\r\n\r\n") == null and len < buf.len) {
            const n = self.readConn(conn, buf[len..]) catch return LoopbackError.AcceptFailed;
            if (n == 0) break;
            len += n;
        }
        if (len == 0) return LoopbackError.BadRequest;

        const line_end = std.mem.indexOf(u8, buf[0..len], "\r\n") orelse return LoopbackError.BadRequest;
        const request_line = buf[0..line_end];
        // "GET /callback?code=...&state=... HTTP/1.1"
        if (!std.mem.startsWith(u8, request_line, "GET ")) return LoopbackError.BadRequest;
        const target_end = std.mem.lastIndexOfScalar(u8, request_line, ' ') orelse return LoopbackError.BadRequest;
        const target = request_line[4..target_end];

        const query = if (std.mem.indexOfScalar(u8, target, '?')) |q| target[q + 1 ..] else "";
        const path = if (std.mem.indexOfScalar(u8, target, '?')) |q| target[0..q] else target;
        if (!std.mem.eql(u8, path, "/callback")) {
            self.respond(conn, 404, "Not found") catch {};
            return LoopbackError.BadRequest;
        }

        var code: ?[]const u8 = null;
        var state: ?[]const u8 = null;
        var oauth_err: ?[]const u8 = null;
        var it = std.mem.splitScalar(u8, query, '&');
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
            return LoopbackError.BadRequest;
        }
        if (state == null or !std.mem.eql(u8, state.?, expected_state)) {
            self.respond(conn, 400, "State mismatch — possible CSRF, authorization rejected") catch {};
            return LoopbackError.StateMismatch;
        }
        const c = code orelse {
            self.respond(conn, 400, "Missing authorization code") catch {};
            return LoopbackError.NoCode;
        };
        self.respond(conn, 200, "Authorization complete — you can close this tab and return to your IDE.") catch {};

        return try alloc.dupe(u8, c);
    }

    // ------------------------------------------------------- platform io --

    fn initPosix(timeout_ms: u32) LoopbackError!Listener {
        const addr = std.net.Address.parseIp4("127.0.0.1", 0) catch unreachable;
        const s = std.posix.socket(std.posix.AF.INET, std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC, 0) catch
            return LoopbackError.ListenFailed;
        errdefer std.posix.close(s);
        std.posix.setsockopt(s, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1))) catch {};
        std.posix.bind(s, &addr.any, addr.getOsSockLen()) catch return LoopbackError.ListenFailed;
        std.posix.listen(s, 1) catch return LoopbackError.ListenFailed;

        const tv: std.posix.timeval = .{
            .sec = @intCast(timeout_ms / 1000),
            .usec = @intCast((timeout_ms % 1000) * 1000),
        };
        std.posix.setsockopt(s, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch {};

        var bound = std.net.Address.parseIp4("127.0.0.1", 0) catch unreachable;
        var blen: std.posix.socklen_t = bound.getOsSockLen();
        std.posix.getsockname(s, &bound.any, &blen) catch return LoopbackError.ListenFailed;
        return .{ .sock = s, .port = bound.getPort() };
    }

    fn initWin(timeout_ms: u32) LoopbackError!Listener {
        var wsa: win.ws2.WSADATA = undefined;
        if (win.ws2.WSAStartup(0x0202, &wsa) != 0) return LoopbackError.ListenFailed;

        const addr = std.net.Address.parseIp4("127.0.0.1", 0) catch unreachable;
        const s = win.ws2.socket(addr.any.family, win.ws2.SOCK.STREAM, 0);
        if (s == win.INVALID_SOCKET) return LoopbackError.ListenFailed;
        errdefer _ = win.ws2.closesocket(s);

        const one: i32 = 1;
        _ = win.ws2.setsockopt(s, win.SOL_SOCKET, win.ws2.SO.REUSEADDR, std.mem.asBytes(&one), @sizeOf(i32));
        if (win.ws2.bind(s, &addr.any, @intCast(addr.getOsSockLen())) != 0) return LoopbackError.ListenFailed;
        if (win.ws2.listen(s, 1) != 0) return LoopbackError.ListenFailed;

        const t: i32 = @intCast(timeout_ms);
        _ = win.ws2.setsockopt(s, win.SOL_SOCKET, win.SO_RCVTIMEO, std.mem.asBytes(&t), @sizeOf(i32));

        var bound = std.net.Address.parseIp4("127.0.0.1", 0) catch unreachable;
        var blen: i32 = @intCast(bound.getOsSockLen());
        if (win.ws2.getsockname(s, &bound.any, &blen) != 0) return LoopbackError.ListenFailed;
        return .{ .sock = s, .port = bound.getPort() };
    }

    fn acceptOne(self: *Listener) LoopbackError!@TypeOf(@as(Listener, undefined).sock) {
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

    fn closeConn(self: *Listener, conn: anytype) void {
        if (is_windows) {
            _ = win.ws2.closesocket(conn);
        } else {
            std.posix.close(conn);
        }
        _ = self;
    }

    fn readConn(self: *Listener, conn: anytype, out: []u8) !usize {
        _ = self;
        if (is_windows) {
            const n = win.ws2.recv(conn, out.ptr, @intCast(out.len), 0);
            if (n == win.ws2.SOCKET_ERROR) return error.ReadFailed;
            return @intCast(n);
        }
        return std.posix.read(conn, out);
    }

    fn respond(self: *Listener, conn: anytype, status: u16, message: []const u8) !void {
        _ = self;
        const status_text = switch (status) {
            200 => "OK",
            400 => "Bad Request",
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

        if (is_windows) {
            _ = win.ws2.send(conn, head.ptr, @intCast(head.len), 0);
            _ = win.ws2.send(conn, body.ptr, @intCast(body.len), 0);
        } else {
            _ = std.posix.write(conn, head) catch {};
            _ = std.posix.write(conn, body) catch {};
        }
    }
};

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

test "urlDecode: percent, plus, malformed" {
    const alloc = std.testing.allocator;
    try std.testing.expectEqualStrings("a b+c/d=e", try urlDecode(alloc, "a%20b%2Bc%2Fd%3De"));
    try std.testing.expectEqualStrings("plain", try urlDecode(alloc, "plain"));
    try std.testing.expectEqualStrings("100%", try urlDecode(alloc, "100%25"));
}
