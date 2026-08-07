// mcp-bridge: MCP stdio <-> HTTP(S) bridge for Windows.
//
// Reads newline-delimited JSON-RPC from stdin, POSTs each message to a
// remote MCP server (Streamable HTTP transport), writes each JSON response
// to stdout. TLS via SChannel with DANE TLSA verification (DANE-TA/DANE-EE,
// no DNSSEC) and Windows root-store PKI fallback when no TLSA is published.
//
// Usage:
//   mcp-bridge.exe <url> [--header "Name: Value"]... [--verbose]
//
// Example (mcp_config.json):
//   "memory": { "command": "C:\\tools\\mcp-bridge.exe",
//               "args": ["https://memory.morante.com/mcp"] }

const std = @import("std");
const win = @import("win.zig");
const schannel = @import("schannel.zig");
const plain = @import("plain.zig");
const http = @import("http.zig");
const mcp = @import("mcp.zig");
const dane = @import("dane.zig");
const dns = @import("dns.zig");

const log = std.log.scoped(.bridge);

const Target = struct {
    secure: bool,
    host: []const u8,
    port: u16,
    path: []const u8,
};

const Config = struct {
    target: Target,
    headers: std.ArrayList([]const u8) = .empty,
    verbose: bool = false,
};

fn usage() noreturn {
    std.debug.print(
        \\usage: mcp-bridge.exe <url> [--header "Name: Value"]... [--verbose]
        \\
        \\  url       http(s)://host[:port]/path of the MCP server
        \\  --header  extra request header (repeatable), e.g. auth tokens
        \\  --verbose diagnostics on stderr
        \\
    , .{});
    std.process.exit(2);
}

fn parseUrl(url: []const u8) !Target {
    var rest = url;
    var secure = true;
    if (std.mem.startsWith(u8, rest, "https://")) {
        rest = rest["https://".len..];
    } else if (std.mem.startsWith(u8, rest, "http://")) {
        rest = rest["http://".len..];
        secure = false;
    } else return error.BadScheme;

    const slash = std.mem.indexOf(u8, rest, "/") orelse rest.len;
    const authority = rest[0..slash];
    const path = if (slash < rest.len) rest[slash..] else "/";

    var host = authority;
    var port: u16 = if (secure) 443 else 80;
    if (std.mem.indexOfScalar(u8, authority, ':')) |colon| {
        host = authority[0..colon];
        port = std.fmt.parseInt(u16, authority[colon + 1 ..], 10) catch return error.BadPort;
    }
    if (host.len == 0) return error.BadHost;
    return .{ .secure = secure, .host = host, .port = port, .path = path };
}

/// Certificate verification: DANE TLSA first (cached lookup), then Windows
/// root-store PKI fallback when no TLSA records are published.
const Verifier = struct {
    alloc: std.mem.Allocator,
    host: []const u8,
    host_w: [:0]const u16,
    port: u16,
    verbose: bool,
    tlsa: ?[]dane.TlsaRecord = null,

    fn verifyOpaque(ctx_ptr: *anyopaque, leaf: *win.CERT_CONTEXT) bool {
        const self: *Verifier = @ptrCast(@alignCast(ctx_ptr));
        return self.verify(leaf) catch |err| {
            log.err("certificate verification error: {s}", .{@errorName(err)});
            return false;
        };
    }

    fn verify(self: *Verifier, leaf: *win.CERT_CONTEXT) !bool {
        if (self.tlsa == null) {
            self.tlsa = dns.lookupTlsa(self.alloc, self.host, self.port) catch |err| {
                // DNS lookup ERROR (not "no records") → fail closed.
                log.err("TLSA lookup failed for {s}: {s}", .{ self.host, @errorName(err) });
                if (self.verbose) std.debug.print("mcp-bridge: TLSA lookup error, refusing connection\n", .{});
                return err;
            };
            if (self.verbose) {
                std.debug.print("mcp-bridge: {d} TLSA record(s) for _{d}._tcp.{s}\n", .{ self.tlsa.?.len, self.port, self.host });
            }
        }
        const records = self.tlsa.?;

        const built = try dane.buildChain(leaf);
        defer dane.freeChain(built.chain, built.certs);

        if (records.len > 0) {
            const result = dane.verifyChainDane(self.alloc, records, built.certs);
            if (self.verbose) {
                std.debug.print("mcp-bridge: DANE result: {s}\n", .{@tagName(result)});
            }
            return result == .success;
        }

        // No TLSA published → normal PKI against Windows root store.
        if (self.verbose) std.debug.print("mcp-bridge: no TLSA, PKI fallback via Windows root store\n", .{});
        return dane.verifyChainPki(built.chain, self.host_w);
    }
};

fn readLineFromStdin(alloc: std.mem.Allocator, stdin_h: win.HANDLE, carry: *std.ArrayList(u8)) !?[]u8 {
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
        var nread: win.DWORD = 0;
        const ok = win.ReadFile(stdin_h, &tmp, tmp.len, &nread, null);
        if (ok == 0 or nread == 0) {
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

fn writeStdout(bytes: []const u8) !void {
    const stdout_h = win.GetStdHandle(win.STD_OUTPUT_HANDLE) orelse return error.NoStdout;
    var off: usize = 0;
    while (off < bytes.len) {
        var written: win.DWORD = 0;
        if (win.WriteFile(stdout_h, bytes.ptr + off, @intCast(bytes.len - off), &written, null) == 0)
            return error.WriteFailed;
        off += written;
    }
}

fn serveRequest(
    alloc: std.mem.Allocator,
    cfg: *const Config,
    verifier: ?*Verifier,
    session_id: *?[]const u8,
    line: []const u8,
) !http.Response {
    const t = cfg.target;

    // Assemble headers: user headers + session/protocol headers
    var headers: std.ArrayList([]const u8) = .empty;
    defer headers.deinit(alloc);
    try headers.appendSlice(alloc, cfg.headers.items);
    if (session_id.*) |sid| {
        const h = try std.fmt.allocPrint(alloc, "MCP-Session-Id: {s}", .{sid});
        try headers.append(alloc, h);
    }
    try headers.append(alloc, "MCP-Protocol-Version: 2025-03-26");
    defer for (headers.items[cfg.headers.items.len..]) |h| {
        if (!std.mem.eql(u8, h, "MCP-Protocol-Version: 2025-03-26")) alloc.free(@constCast(h));
    };

    if (t.secure) {
        var tls = try schannel.connect(alloc, t.host, t.port, @ptrCast(verifier.?), Verifier.verifyOpaque);
        defer tls.deinit();
        return try http.post(alloc, &tls, t.host, t.path, line, headers.items);
    } else {
        var ps = try plain.PlainStream.connect(alloc, t.host, t.port);
        defer ps.deinit();
        return try http.post(alloc, &ps, t.host, t.path, line, headers.items);
    }
}

pub fn main() !void {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{}){};
    const alloc = gpa_state.allocator();

    const args = try std.process.argsAlloc(alloc);

    var cfg = Config{ .target = undefined };
    var url: ?[]const u8 = null;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--verbose") or std.mem.eql(u8, a, "-v")) {
            cfg.verbose = true;
        } else if (std.mem.eql(u8, a, "--header") or std.mem.eql(u8, a, "-H")) {
            i += 1;
            if (i >= args.len) usage();
            try cfg.headers.append(alloc, args[i]);
        } else if (url == null) {
            url = a;
        } else {
            usage();
        }
    }
    cfg.target = parseUrl(url orelse usage()) catch usage();
    schannel.verbose = cfg.verbose;

    if (cfg.verbose) {
        std.debug.print("mcp-bridge: {s}://{s}:{d}{s}\n", .{
            if (cfg.target.secure) "https" else "http",
            cfg.target.host,
            cfg.target.port,
            cfg.target.path,
        });
    }

    // Verifier (TLS only)
    var verifier: ?Verifier = null;
    if (cfg.target.secure) {
        const host_w = win.utf16Z(alloc, cfg.target.host) catch return error.Utf16;
        verifier = .{
            .alloc = alloc,
            .host = cfg.target.host,
            .host_w = host_w,
            .port = cfg.target.port,
            .verbose = cfg.verbose,
        };
    }

    const stdin_h = win.GetStdHandle(win.STD_INPUT_HANDLE) orelse return error.NoStdin;

    var carry: std.ArrayList(u8) = .empty;
    defer carry.deinit(alloc);

    var session_id: ?[]const u8 = null;

    while (true) {
        const maybe_line = readLineFromStdin(alloc, stdin_h, &carry) catch null;
        const line = maybe_line orelse break;
        defer alloc.free(line);
        if (line.len == 0) continue;

        if (cfg.verbose) std.debug.print("mcp-bridge: >> {s}\n", .{line});

        var resp = serveRequest(alloc, &cfg, if (verifier != null) &verifier.? else null, &session_id, line) catch |err| {
            // Synthesize a JSON-RPC error so the client isn't left hanging.
            var ebuf: [512]u8 = undefined;
            const emsg = mcp.formatTransportError(&ebuf, mcp.getRequestId(line), @errorName(err));
            try writeStdout(emsg);
            try writeStdout("\n");
            continue;
        };
        defer resp.deinit(alloc);

        // Capture session id from initialize response
        if (resp.mcp_session_id) |sid| {
            const copy = try alloc.dupe(u8, sid);
            if (session_id) |old| alloc.free(@constCast(old));
            session_id = copy;
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

    // Clean session shutdown (DELETE) — best effort
    if (session_id != null and cfg.verbose) {
        std.debug.print("mcp-bridge: stdin closed, exiting\n", .{});
    }
}
