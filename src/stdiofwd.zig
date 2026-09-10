// Remote stdio targets (issue #15): bridge an IDE's local stdio to a
// stdio MCP server on another host, over raw TCP (socat/nc style) or
// SSH via the system client.
//
//   stdio+tcp://HOST:PORT
//       Plain TCP to a `socat tcp-listen:PORT,fork exec:<server>`-style
//       listener. Line-framed JSON-RPC both ways. POSIX only (v1).
//
//   stdio+ssh://[USER@]HOST[:PORT]/remote/path
//       Spawns the system ssh client with its stdin/stdout piped:
//       ssh -T -o BatchMode=yes -o ConnectTimeout=10 [-p PORT] USER@HOST
//       '/remote/path' ['arg'...] — the operator's ~/.ssh config/agent
//       carries auth; nothing crypto lives here.

const std = @import("std");
const builtin = @import("builtin");

pub const Error = error{ BadTarget, OutOfMemory };

pub const Tcp = struct { host: []const u8, port: u16 };

pub const Target = union(enum) {
    tcp: Tcp,
    ssh: Ssh,
};

/// Which local SSH client drives the connection.
///
/// They are not interchangeable on Windows, and the difference reaches all
/// the way into how the child's stdout must be created (issue #23):
/// OpenSSH's ssh.exe wedges forever on a pipe and needs an OVERLAPPED
/// loopback socket, while plink does a plain synchronous WriteFile and
/// rejects an overlapped handle outright with ERROR_INVALID_PARAMETER, so
/// it needs an ordinary pipe. See fwdStartSsh.
pub const Client = enum { openssh, plink };

pub const Ssh = struct {
    user: ?[]const u8 = null,
    host: []const u8,
    port: ?u16 = null,
    /// Remote executable path (percent-decoded), e.g. "/opt/bin/vnc-mcp".
    path: []const u8,
    /// Extra remote arguments (trailing positional CLI args).
    args: []const []const u8 = &.{},
    /// --ssh-client: which local client binary to drive.
    client: Client = .openssh,
    /// --ssh-identity: private key file. OpenSSH takes any format it
    /// supports; plink requires a PuTTY .ppk (it cannot read OpenSSH keys).
    identity: ?[]const u8 = null,
    /// --ssh-hostkey: expected host key fingerprint, plink only. plink
    /// -batch aborts on a host key that is not already cached in the
    /// registry, and has no accept-new equivalent, so an unattended run on
    /// a fresh host needs this.
    hostkey: ?[]const u8 = null,

    /// Full child argv for the local ssh client. The remote command is
    /// ONE sh-quoted string: path + args joined by spaces.
    pub fn sshArgv(self: *const Ssh, alloc: std.mem.Allocator) Error![][]const u8 {
        if (self.client == .plink) return self.plinkArgv(alloc);
        var argv: std.ArrayList([]const u8) = .empty;
        argv.append(alloc, "ssh") catch return Error.OutOfMemory;
        // -T: no pty (a pty would echo/mangle the line protocol).
        // BatchMode + ConnectTimeout: never hang an IDE on a prompt.
        argv.append(alloc, "-T") catch return Error.OutOfMemory;
        argv.append(alloc, "-o") catch return Error.OutOfMemory;
        argv.append(alloc, "BatchMode=yes") catch return Error.OutOfMemory;
        argv.append(alloc, "-o") catch return Error.OutOfMemory;
        argv.append(alloc, "ConnectTimeout=10") catch return Error.OutOfMemory;
        if (self.port) |p| {
            argv.append(alloc, "-p") catch return Error.OutOfMemory;
            argv.append(alloc, std.fmt.allocPrint(alloc, "{d}", .{p}) catch return Error.OutOfMemory) catch return Error.OutOfMemory;
        }
        if (self.identity) |k| {
            argv.append(alloc, "-i") catch return Error.OutOfMemory;
            argv.append(alloc, k) catch return Error.OutOfMemory;
        }
        argv.append(alloc, try self.hostArg(alloc)) catch return Error.OutOfMemory;
        argv.append(alloc, try self.remoteCommand(alloc)) catch return Error.OutOfMemory;
        return argv.toOwnedSlice(alloc) catch return Error.OutOfMemory;
    }

    /// PuTTY plink argv. Deliberately mirrors the OpenSSH form: -T for no
    /// pty, -batch so an IDE never hangs on a prompt.
    ///
    /// plink ignores ~/.ssh/config entirely, so any Host alias, ProxyJump
    /// or IdentityFile the user relies on there does NOT apply here.
    fn plinkArgv(self: *const Ssh, alloc: std.mem.Allocator) Error![][]const u8 {
        var argv: std.ArrayList([]const u8) = .empty;
        argv.append(alloc, "plink") catch return Error.OutOfMemory;
        argv.append(alloc, "-batch") catch return Error.OutOfMemory;
        argv.append(alloc, "-ssh") catch return Error.OutOfMemory;
        argv.append(alloc, "-T") catch return Error.OutOfMemory;
        if (self.port) |p| {
            // plink spells it -P, unlike ssh's -p.
            argv.append(alloc, "-P") catch return Error.OutOfMemory;
            argv.append(alloc, std.fmt.allocPrint(alloc, "{d}", .{p}) catch return Error.OutOfMemory) catch return Error.OutOfMemory;
        }
        if (self.identity) |k| {
            argv.append(alloc, "-i") catch return Error.OutOfMemory;
            argv.append(alloc, k) catch return Error.OutOfMemory;
        }
        if (self.hostkey) |h| {
            argv.append(alloc, "-hostkey") catch return Error.OutOfMemory;
            argv.append(alloc, h) catch return Error.OutOfMemory;
        }
        argv.append(alloc, try self.hostArg(alloc)) catch return Error.OutOfMemory;
        argv.append(alloc, try self.remoteCommand(alloc)) catch return Error.OutOfMemory;
        return argv.toOwnedSlice(alloc) catch return Error.OutOfMemory;
    }

    fn hostArg(self: *const Ssh, alloc: std.mem.Allocator) Error![]const u8 {
        if (self.user) |u| return std.fmt.allocPrint(alloc, "{s}@{s}", .{ u, self.host }) catch Error.OutOfMemory;
        return self.host;
    }

    fn remoteCommand(self: *const Ssh, alloc: std.mem.Allocator) ![]const u8 {
        var cmd: std.ArrayList(u8) = .empty;
        cmd.appendSlice(alloc, try shQuote(alloc, self.path)) catch return Error.OutOfMemory;
        for (self.args) |a| {
            cmd.append(alloc, ' ') catch return Error.OutOfMemory;
            cmd.appendSlice(alloc, try shQuote(alloc, a)) catch return Error.OutOfMemory;
        }
        return cmd.toOwnedSlice(alloc) catch return Error.OutOfMemory;
    }
};

/// POSIX-sh single-quote escape: safe embedding into a remote shell
/// command line no matter what the bytes are (' becomes '"'"').
pub fn shQuote(alloc: std.mem.Allocator, s: []const u8) Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    out.append(alloc, '\'') catch return Error.OutOfMemory;
    for (s) |c| {
        if (c == '\'') {
            out.appendSlice(alloc, "'\"'\"'") catch return Error.OutOfMemory;
        } else {
            out.append(alloc, c) catch return Error.OutOfMemory;
        }
    }
    out.append(alloc, '\'') catch return Error.OutOfMemory;
    return out.toOwnedSlice(alloc) catch return Error.OutOfMemory;
}

/// Parse url_str as a stdio target. Returns null (not an error) when the
/// scheme is not stdio+tcp / stdio+ssh — the caller continues with the
/// HTTP path. extra are trailing positional CLI args appended to the ssh
/// remote command.
pub fn parse(alloc: std.mem.Allocator, url_str: []const u8, extra: []const []const u8) Error!?Target {
    if (std.mem.startsWith(u8, url_str, "stdio+tcp://"))
        return .{ .tcp = try parseTcp(url_str["stdio+tcp://".len..]) };
    if (std.mem.startsWith(u8, url_str, "stdio+ssh://"))
        return .{ .ssh = try parseSsh(alloc, url_str["stdio+ssh://".len..], extra) };
    return null;
}

/// HOST:PORT — the port is mandatory; there is no conventional default.
fn parseTcp(rest: []const u8) Error!Tcp {
    if (builtin.os.tag == .windows) {
        // No plain-socket IOCP path exists yet; ssh covers the deploy case.
        ulogErr("stdio+tcp is not supported on Windows in this build; use stdio+ssh://");
        return Error.BadTarget;
    }
    const colon = std.mem.lastIndexOfScalar(u8, rest, ':') orelse return Error.BadTarget;
    const host = if (rest[0] == '[') blk: { // [::1]:6600
        const close = std.mem.indexOfScalar(u8, rest, ']') orelse return Error.BadTarget;
        if (close + 1 != colon) return Error.BadTarget;
        break :blk rest[1..close];
    } else rest[0..colon];
    if (host.len == 0 or std.mem.indexOfAny(u8, host, "/?#") != null) return Error.BadTarget;
    const port = std.fmt.parseInt(u16, rest[colon + 1 ..], 10) catch return Error.BadTarget;
    if (port == 0) return Error.BadTarget;
    return .{ .host = host, .port = port };
}

fn parseSsh(alloc: std.mem.Allocator, rest: []const u8, extra: []const []const u8) Error!Ssh {
    var user: ?[]const u8 = null;
    var auth = rest;
    if (std.mem.indexOfScalar(u8, rest, '@')) |at| {
        user = percentDecode(alloc, rest[0..at]) catch return Error.OutOfMemory;
        if (user.?.len == 0) return Error.BadTarget;
        auth = rest[at + 1 ..];
    }
    const slash = std.mem.indexOfScalar(u8, auth, '/') orelse return Error.BadTarget;
    var hostport = auth[0..slash];
    var port: ?u16 = null;
    if (std.mem.lastIndexOfScalar(u8, hostport, ':')) |colon| {
        port = std.fmt.parseInt(u16, hostport[colon + 1 ..], 10) catch return Error.BadTarget;
        hostport = hostport[0..colon];
    }
    const host = percentDecode(alloc, hostport) catch return Error.OutOfMemory;
    if (host.len == 0 or std.mem.indexOfAny(u8, host, " \t?#") != null) return Error.BadTarget;
    const raw_path = auth[slash..];
    if (std.mem.indexOfAny(u8, raw_path, "?#") != null) return Error.BadTarget; // no query/fragment semantics
    const path = percentDecode(alloc, raw_path) catch return Error.OutOfMemory;
    if (path.len < 2 or path[0] != '/') return Error.BadTarget; // must be an absolute remote path
    return .{ .user = user, .host = host, .port = port, .path = path, .args = extra };
}

fn percentDecode(alloc: std.mem.Allocator, s: []const u8) Error![]const u8 {
    if (std.mem.indexOfScalar(u8, s, '%') == null) return s;
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < s.len) {
        if (s[i] == '%') {
            if (i + 2 >= s.len) return Error.BadTarget;
            const hi = std.fmt.charToDigit(s[i + 1], 16) catch return Error.BadTarget;
            const lo = std.fmt.charToDigit(s[i + 2], 16) catch return Error.BadTarget;
            out.append(alloc, hi * 16 + lo) catch return Error.OutOfMemory;
            i += 3;
        } else {
            out.append(alloc, s[i]) catch return Error.OutOfMemory;
            i += 1;
        }
    }
    return out.toOwnedSlice(alloc) catch return Error.OutOfMemory;
}

fn ulogErr(msg: []const u8) void {
    std.debug.print("mcp-bridge: {s}\n", .{msg});
}

// --------------------------------------------------------------- tests ----

test "parse: not a stdio scheme returns null" {
    const alloc = std.testing.allocator;
    try std.testing.expect(try parse(alloc, "https://example.com/mcp", &.{}) == null);
    try std.testing.expect(try parse(alloc, "http://127.0.0.1:3000/", &.{}) == null);
}

test "parse: tcp host:port" {
    if (builtin.os.tag == .windows) return; // v1 rejects tcp on windows
    const alloc = std.testing.allocator;
    const t = (try parse(alloc, "stdio+tcp://192.168.1.233:6600", &.{})).?;
    switch (t) {
        .tcp => |tcp| {
            try std.testing.expectEqualStrings("192.168.1.233", tcp.host);
            try std.testing.expectEqual(@as(u16, 6600), tcp.port);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "parse: tcp requires a port and rejects paths" {
    if (builtin.os.tag == .windows) return;
    const alloc = std.testing.allocator;
    try std.testing.expectError(Error.BadTarget, parse(alloc, "stdio+tcp://example.com", &.{}));
    try std.testing.expectError(Error.BadTarget, parse(alloc, "stdio+tcp://example.com:0", &.{}));
    try std.testing.expectError(Error.BadTarget, parse(alloc, "stdio+tcp://example.com:notaport", &.{}));
    try std.testing.expectError(Error.BadTarget, parse(alloc, "stdio+tcp://example.com:6600/x", &.{}));
    const v6 = (try parse(alloc, "stdio+tcp://[::1]:6600", &.{})).?;
    try std.testing.expectEqualStrings("::1", v6.tcp.host);
    try std.testing.expectEqual(@as(u16, 6600), v6.tcp.port);
}

test "parse: ssh full form" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const t = (try parse(alloc, "stdio+ssh://admin%40corp@freebsd-dev1:2222/opt/bin/vnc-mcp%20server", &.{"--fast"})).?;
    const ssh = t.ssh;
    try std.testing.expectEqualStrings("admin@corp", ssh.user.?);
    try std.testing.expectEqualStrings("freebsd-dev1", ssh.host);
    try std.testing.expectEqual(@as(u16, 2222), ssh.port.?);
    try std.testing.expectEqualStrings("/opt/bin/vnc-mcp server", ssh.path);
    try std.testing.expectEqualStrings("--fast", ssh.args[0]);
}

test "parse: ssh rejects garbage" {
    const alloc = std.testing.allocator;
    try std.testing.expectError(Error.BadTarget, parse(alloc, "stdio+ssh://host", &.{})); // no path
    try std.testing.expectError(Error.BadTarget, parse(alloc, "stdio+ssh://host/", &.{})); // empty path
    try std.testing.expectError(Error.BadTarget, parse(alloc, "stdio+ssh://host/path?x=1", &.{})); // no query
    try std.testing.expectError(Error.BadTarget, parse(alloc, "stdio+ssh://@host/x", &.{})); // empty user
    try std.testing.expectError(Error.BadTarget, parse(alloc, "stdio+ssh://host:x/path", &.{})); // bad port
}

test "sshArgv: flags, port, quoting" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    var ssh = Ssh{ .user = "daniel", .host = "freebsd-dev1", .port = 2222, .path = "/opt/bin/vnc-mcp server", .args = &.{"a's b"} };
    const argv = try ssh.sshArgv(alloc);
    try std.testing.expectEqualStrings("ssh", argv[0]);
    try std.testing.expectEqualStrings("-T", argv[1]);
    try std.testing.expectEqualStrings("BatchMode=yes", argv[3]);
    try std.testing.expectEqualStrings("-p", argv[6]);
    try std.testing.expectEqualStrings("2222", argv[7]);
    try std.testing.expectEqualStrings("daniel@freebsd-dev1", argv[8]);
    try std.testing.expectEqualStrings("'/opt/bin/vnc-mcp server' 'a'\"'\"'s b'", argv[9]);

    var plain = Ssh{ .host = "h", .path = "/x" };
    const argv2 = try plain.sshArgv(alloc);
    try std.testing.expectEqualStrings("h", argv2[6]);
    try std.testing.expectEqualStrings("'/x'", argv2[7]);
}

test "sshArgv: openssh identity" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    var ssh = Ssh{ .host = "h", .path = "/x", .identity = "/k/id_ed25519" };
    const argv = try ssh.sshArgv(alloc);
    try std.testing.expectEqualStrings("-i", argv[6]);
    try std.testing.expectEqualStrings("/k/id_ed25519", argv[7]);
    try std.testing.expectEqualStrings("h", argv[8]);
}

test "plinkArgv: batch flags, -P port, -i, -hostkey, quoting" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    var ssh = Ssh{
        .user = "daniel",
        .host = "freebsd-dev1",
        .port = 2222,
        .path = "/opt/bin/vnc-mcp server",
        .args = &.{"a's b"},
        .client = .plink,
        .identity = "C:\\keys\\id.ppk",
        .hostkey = "SHA256:abc+def/ghi",
    };
    const argv = try ssh.sshArgv(alloc);
    try std.testing.expectEqualStrings("plink", argv[0]);
    try std.testing.expectEqualStrings("-batch", argv[1]);
    try std.testing.expectEqualStrings("-ssh", argv[2]);
    try std.testing.expectEqualStrings("-T", argv[3]);
    // plink spells the port -P, not -p.
    try std.testing.expectEqualStrings("-P", argv[4]);
    try std.testing.expectEqualStrings("2222", argv[5]);
    try std.testing.expectEqualStrings("-i", argv[6]);
    try std.testing.expectEqualStrings("C:\\keys\\id.ppk", argv[7]);
    try std.testing.expectEqualStrings("-hostkey", argv[8]);
    try std.testing.expectEqualStrings("SHA256:abc+def/ghi", argv[9]);
    try std.testing.expectEqualStrings("daniel@freebsd-dev1", argv[10]);
    // The remote command is sh-quoted exactly as for OpenSSH.
    try std.testing.expectEqualStrings("'/opt/bin/vnc-mcp server' 'a'\"'\"'s b'", argv[11]);
}

test "plinkArgv: minimal form omits optional flags" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    var ssh = Ssh{ .host = "h", .path = "/x", .client = .plink };
    const argv = try ssh.sshArgv(alloc);
    try std.testing.expectEqual(@as(usize, 6), argv.len);
    try std.testing.expectEqualStrings("plink", argv[0]);
    try std.testing.expectEqualStrings("h", argv[4]);
    try std.testing.expectEqualStrings("'/x'", argv[5]);
}

test "shQuote round trips odd bytes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    try std.testing.expectEqualStrings("'plain'", try shQuote(alloc, "plain"));
    try std.testing.expectEqualStrings("''", try shQuote(alloc, ""));
    try std.testing.expectEqualStrings("'a'\"'\"'b'", try shQuote(alloc, "a'b"));
}
