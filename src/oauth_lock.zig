// Multi-instance OAuth lockfile coordination (POSIX only, issue #3).
//
// mcp-remote parity: while an interactive authorization-code flow is in
// progress, the instance holds <tokens_dir>/<hash>_lock.json containing
// {"pid":N,"port":P} (P = its loopback listener port). A second instance
// started for the same server finds the lock, long-polls the first
// instance's listener (GET /wait-for-auth, see oauth_loopback.zig), then
// reads the tokens the first instance cached — no second browser tab.
// Stale locks (dead pid, or nothing accepting on the recorded port — e.g.
// a recycled pid) are deleted and taken over.
//
// Windows skips this entirely (mcp-remote skips it too): callers gate on
// is_supported and run the plain single-instance flow. All POSIX-only
// function bodies below are analyzed lazily — never call them on Windows.

const std = @import("std");
const builtin = @import("builtin");
const oauth = @import("oauth.zig");

pub const is_supported = builtin.os.tag != .windows;

pub const LockError = error{
    /// The lock stayed contested through repeated stale takeovers.
    Contention,
    OutOfMemory,
    /// The cache dir / lock file could not be written.
    WriteFailed,
};

/// Outcome of acquire(): either we hold the lock (MUST release() when the
/// flow ends, success or failure), or a live peer holds it — wait on its
/// loopback port, then re-read the token cache.
pub const AcquireResult = union(enum) {
    acquired: Lock,
    held_by_other: u16,
};

pub const Lock = struct {
    path: []u8, // owned by the caller's allocator

    pub fn release(self: *Lock, alloc: std.mem.Allocator) void {
        std.fs.cwd().deleteFile(self.path) catch {};
        alloc.free(self.path);
        self.path = &.{};
    }
};

pub const LockInfo = struct {
    pid: i32,
    port: u16,
};

/// Try to become the coordinating instance for this server's interactive
/// flow. `port` is OUR loopback listener (already bound and accepting, so
/// a waiter that sees the lock can connect immediately). POSIX only.
pub fn acquire(alloc: std.mem.Allocator, server_url: []const u8, resource: ?[]const u8, port: u16) LockError!AcquireResult {
    const dir = oauth.tokensDir(alloc) catch return LockError.WriteFailed;
    defer alloc.free(dir);
    return acquireIn(alloc, dir, server_url, resource, port);
}

/// Dir-injectable core of acquire() (hermetic tests).
pub fn acquireIn(alloc: std.mem.Allocator, dir: []const u8, server_url: []const u8, resource: ?[]const u8, port: u16) LockError!AcquireResult {
    const path = oauth.lockPathIn(alloc, dir, server_url, resource) catch return LockError.OutOfMemory;
    std.fs.cwd().makePath(dir) catch {};

    var takeovers: u8 = 0;
    while (true) {
        const f = std.fs.cwd().createFile(path, .{ .exclusive = true, .mode = 0o600 }) catch |err| switch (err) {
            error.PathAlreadyExists => {
                if (readLock(alloc, path)) |info| {
                    if (pidAlive(info.pid) and portAccepts(info.port)) {
                        alloc.free(path);
                        return .{ .held_by_other = info.port };
                    }
                    // Stale: dead pid, recycled pid, or dead listener.
                } else {
                    // Released between our create and read — just retry.
                    std.fs.cwd().access(path, .{}) catch |aerr| switch (aerr) {
                        error.FileNotFound => continue,
                        else => {},
                    };
                    // Unparseable: the creator is in its create-then-write
                    // window. Re-read a few times before calling it corrupt.
                    var retries: u8 = 0;
                    var info: ?LockInfo = null;
                    while (retries < 3) : (retries += 1) {
                        std.Thread.sleep(10 * std.time.ns_per_ms);
                        if (readLock(alloc, path)) |i| {
                            info = i;
                            break;
                        }
                    }
                    if (info) |i| {
                        if (pidAlive(i.pid) and portAccepts(i.port)) {
                            alloc.free(path);
                            return .{ .held_by_other = i.port };
                        }
                    }
                    // Genuinely corrupt → stale.
                }
                if (takeovers >= 4) {
                    alloc.free(path);
                    return LockError.Contention;
                }
                takeovers += 1;
                std.fs.cwd().deleteFile(path) catch {};
                continue;
            },
            else => {
                alloc.free(path);
                return LockError.WriteFailed;
            },
        };
        // We hold the lock: record pid + port for waiters.
        var body_buf: [64]u8 = undefined;
        const body = std.fmt.bufPrint(&body_buf, "{{\"pid\":{d},\"port\":{d}}}", .{ std.c.getpid(), port }) catch unreachable;
        f.writeAll(body) catch {};
        f.close();
        return .{ .acquired = .{ .path = path } };
    }
}

/// Parse a lock file; null when absent or unparseable.
pub fn readLock(alloc: std.mem.Allocator, path: []const u8) ?LockInfo {
    const text = std.fs.cwd().readFileAlloc(alloc, path, 4096) catch return null;
    defer alloc.free(text);
    const parsed = std.json.parseFromSlice(std.json.Value, alloc, text, .{}) catch return null;
    defer parsed.deinit();
    const obj = switch (parsed.value) {
        .object => |o| o,
        else => return null,
    };
    const pid: i32 = switch (obj.get("pid") orelse return null) {
        .integer => |i| if (i > 0 and i <= std.math.maxInt(i32)) @intCast(i) else return null,
        else => return null,
    };
    const port: u16 = switch (obj.get("port") orelse return null) {
        .integer => |i| if (i > 0 and i <= std.math.maxInt(u16)) @intCast(i) else return null,
        else => return null,
    };
    return .{ .pid = pid, .port = port };
}

/// kill(pid, 0) liveness. EPERM still means alive (owned by someone else).
pub fn pidAlive(pid: i32) bool {
    std.posix.kill(pid, 0) catch |err| switch (err) {
        error.ProcessNotFound => return false,
        else => return true,
    };
    return true;
}

/// A live lock's listener must accept connections: it is bound BEFORE the
/// lock file is written. A refused connect therefore means the recorded
/// pid was recycled by an unrelated process — the lock is stale.
fn portAccepts(port: u16) bool {
    const addr = std.net.Address.parseIp4("127.0.0.1", port) catch unreachable;
    const s = std.posix.socket(std.posix.AF.INET, std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC, 0) catch return false;
    defer std.posix.close(s);
    std.posix.connect(s, &addr.any, addr.getOsSockLen()) catch return false;
    return true;
}

// ------------------------------------------------------------------ tests --

test "lockPath shares the token cache key" {
    const alloc = std.testing.allocator;
    const dir = "/tmp/mcp-bridge-test";
    const tok = try oauth.pathInDir(alloc, dir, "https://a.example/mcp", null, ".json");
    defer alloc.free(tok);
    const lock = try oauth.lockPathIn(alloc, dir, "https://a.example/mcp", null);
    defer alloc.free(lock);
    // Same <dir>/<hex> stem, different suffix.
    try std.testing.expect(std.mem.endsWith(u8, tok, ".json"));
    try std.testing.expect(std.mem.endsWith(u8, lock, "_lock.json"));
    try std.testing.expectEqualStrings(tok[0 .. tok.len - ".json".len], lock[0 .. lock.len - "_lock.json".len]);

    // Resource namespacing applies to the lock key too.
    const lock_r = try oauth.lockPathIn(alloc, dir, "https://a.example/mcp", "https://a.example");
    defer alloc.free(lock_r);
    try std.testing.expect(!std.mem.eql(u8, lock, lock_r));
}

/// Bind a throwaway loopback listener; returns its port. The socket stays
/// open (bound+listening) until the caller closes `sock`.
fn testListener(sock: *std.posix.fd_t) !u16 {
    const addr = std.net.Address.parseIp4("127.0.0.1", 0) catch unreachable;
    sock.* = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC, 0);
    try std.posix.bind(sock.*, &addr.any, addr.getOsSockLen());
    try std.posix.listen(sock.*, 4);
    var bound = std.net.Address.parseIp4("127.0.0.1", 0) catch unreachable;
    var blen: std.posix.socklen_t = bound.getOsSockLen();
    try std.posix.getsockname(sock.*, &bound.any, &blen);
    return bound.getPort();
}

test "lockfile: acquire free, contention with live pid, release" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realpathAlloc(alloc, ".");
    defer alloc.free(dir);

    // Free → acquired.
    var sock: std.posix.fd_t = undefined;
    const port = try testListener(&sock);
    defer std.posix.close(sock);
    var l1 = switch (try acquireIn(alloc, dir, "https://a.example/mcp", null, port)) {
        .acquired => |l| l,
        .held_by_other => return error.TestUnexpectedResult,
    };

    // Held by a live pid (ours) with an accepting port → held_by_other.
    switch (try acquireIn(alloc, dir, "https://a.example/mcp", null, port)) {
        .acquired => return error.TestUnexpectedResult,
        .held_by_other => |p| try std.testing.expectEqual(port, p),
    }

    // After release the lock is gone and re-acquirable.
    l1.release(alloc);
    const lock_path = try oauth.lockPathIn(alloc, dir, "https://a.example/mcp", null);
    defer alloc.free(lock_path);
    try std.testing.expectError(error.FileNotFound, std.fs.cwd().access(lock_path, .{}));
    var l2 = switch (try acquireIn(alloc, dir, "https://a.example/mcp", null, port)) {
        .acquired => |l| l,
        .held_by_other => return error.TestUnexpectedResult,
    };
    l2.release(alloc);
}

test "lockfile: stale lock (dead pid) is taken over" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realpathAlloc(alloc, ".");
    defer alloc.free(dir);

    // Dead pid (above every platform's maxpid) + a closed port.
    const lock_path = try oauth.lockPathIn(alloc, dir, "https://a.example/mcp", null);
    defer alloc.free(lock_path);
    {
        const f = try std.fs.cwd().createFile(lock_path, .{});
        defer f.close();
        try f.writeAll("{\"pid\":16777217,\"port\":1}");
    }

    var sock2: std.posix.fd_t = undefined;
    const port = try testListener(&sock2);
    defer std.posix.close(sock2);
    var l = switch (try acquireIn(alloc, dir, "https://a.example/mcp", null, port)) {
        .acquired => |l| l,
        .held_by_other => return error.TestUnexpectedResult,
    };
    defer l.release(alloc);
    // The lock now records US.
    const info = readLock(alloc, lock_path).?;
    try std.testing.expectEqual(std.c.getpid(), info.pid);
    try std.testing.expectEqual(port, info.port);
}

test "lockfile: corrupt lock is taken over" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realpathAlloc(alloc, ".");
    defer alloc.free(dir);

    const lock_path = try oauth.lockPathIn(alloc, dir, "https://a.example/mcp", null);
    defer alloc.free(lock_path);
    {
        const f = try std.fs.cwd().createFile(lock_path, .{});
        defer f.close();
        try f.writeAll("not json at all");
    }
    var sock: std.posix.fd_t = undefined;
    const port = try testListener(&sock);
    defer std.posix.close(sock);
    var l = switch (try acquireIn(alloc, dir, "https://a.example/mcp", null, port)) {
        .acquired => |l| l,
        .held_by_other => return error.TestUnexpectedResult,
    };
    l.release(alloc);
}

test "pidAlive: self and dead pid" {
    try std.testing.expect(pidAlive(std.c.getpid()));
    try std.testing.expect(!pidAlive(16777217)); // above Linux/FreeBSD maxpid → ESRCH
}

test "readLock: valid and invalid content" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realpathAlloc(alloc, ".");
    defer alloc.free(dir);
    const path = try std.fs.path.join(alloc, &.{ dir, "x_lock.json" });
    defer alloc.free(path);

    try std.testing.expect(readLock(alloc, path) == null); // absent
    {
        const f = try std.fs.cwd().createFile(path, .{});
        defer f.close();
        try f.writeAll("{\"pid\":1234,\"port\":5678}");
    }
    const info = readLock(alloc, path).?;
    try std.testing.expectEqual(@as(i32, 1234), info.pid);
    try std.testing.expectEqual(@as(u16, 5678), info.port);

    for ([_][]const u8{ "", "{}", "{\"pid\":-1,\"port\":80}", "{\"pid\":1,\"port\":70000}", "[1,2]" }) |bad| {
        const f = try std.fs.cwd().createFile(path, .{ .truncate = true });
        try f.writeAll(bad);
        f.close();
        try std.testing.expect(readLock(alloc, path) == null);
    }
}
