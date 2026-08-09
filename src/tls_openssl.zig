// TLS client over OpenSSL 3.x (POSIX) with manual certificate validation
// hook — same surface and policy as schannel.zig: DANE first, system
// trust-store PKI fallback (both live in the Verifier, invoked via the
// verify_fn hook after the handshake).
//
// Blocking sockets with SO_RCVTIMEO/SNDTIMEO (30s/15s parity with the
// Windows build). Patterns adapted from xmppd lib/tls/ssl.zig.

const std = @import("std");
const posix = @import("posix.zig");
const openssl = @import("openssl.zig");

const c = openssl.c;
const log = std.log.scoped(.tls_openssl);

pub var verbose: bool = false;

fn vprint(comptime fmt: []const u8, args: anytype) void {
    if (verbose) std.debug.print(fmt, args);
}

pub const TlsError = error{
    ConnectFailed,
    SslInitFailed,
    HandshakeFailed,
    NoRemoteCert,
    PkiValidationFailed,
    TlsClosed,
    TlsError,
    Timeout,
    OutOfMemory,
};

/// Certificate verification hook: invoked with the connected SSL object
/// after the handshake; must return true to proceed.
pub const VerifyFn = *const fn (ctx: *anyopaque, ssl: *c.SSL) bool;

pub const TlsStream = struct {
    sock: std.posix.fd_t = -1,
    ctx: ?*c.SSL_CTX = null,
    ssl: ?*c.SSL = null,
    alloc: std.mem.Allocator,

    pub fn deinit(self: *TlsStream) void {
        if (self.ssl) |s| c.SSL_free(s);
        if (self.ctx) |x| c.SSL_CTX_free(x);
        if (self.sock >= 0) std.posix.close(self.sock);
        self.ssl = null;
        self.ctx = null;
        self.sock = -1;
    }

    /// Read decrypted application data. Returns 0 on clean close.
    pub fn read(self: *TlsStream, out: []u8) TlsError!usize {
        const ret = c.SSL_read(self.ssl.?, out.ptr, @intCast(out.len));
        if (ret > 0) return @intCast(ret);

        const err = c.SSL_get_error(self.ssl.?, ret);
        switch (err) {
            c.SSL_ERROR_ZERO_RETURN => return 0, // close_notify
            c.SSL_ERROR_WANT_READ, c.SSL_ERROR_WANT_WRITE => return TlsError.TlsError, // blocking fd: unreachable
            c.SSL_ERROR_SYSCALL => {
                // SO_RCVTIMEO expiry surfaces as EAGAIN/EWOULDBLOCK.
                if (cErrno() == @intFromEnum(std.posix.E.AGAIN)) return TlsError.Timeout;
                if (ret == 0) return 0; // unexpected TCP EOF; treat as close
                return TlsError.TlsError;
            },
            else => {
                logSslErrors("read", err);
                return TlsError.TlsError;
            },
        }
    }

    /// Write plaintext.
    pub fn writeAll(self: *TlsStream, data: []const u8) TlsError!void {
        var off: usize = 0;
        while (off < data.len) {
            const ret = c.SSL_write(self.ssl.?, data.ptr + off, @intCast(data.len - off));
            if (ret > 0) {
                off += @intCast(ret);
                continue;
            }
            const err = c.SSL_get_error(self.ssl.?, ret);
            if (err == c.SSL_ERROR_SYSCALL and cErrno() == @intFromEnum(std.posix.E.AGAIN)) return TlsError.Timeout;
            logSslErrors("write", err);
            return TlsError.TlsError;
        }
    }

    /// Best-effort close_notify.
    pub fn closeNotify(self: *TlsStream) void {
        if (self.ssl) |s| _ = c.SSL_shutdown(s);
    }

    /// Abruptly unblock an SSL_read blocked in ANOTHER thread (pump
    /// teardown). Shuts down the underlying socket directly — no
    /// close_notify, no OpenSSL state touched (not thread-safe).
    pub fn forceShutdown(self: *TlsStream) void {
        if (self.sock >= 0) std.posix.shutdown(self.sock, .both) catch {};
    }
};

/// Thread-local C errno (set by the underlying socket syscalls OpenSSL made).
fn cErrno() c_int {
    return std.c._errno().*;
}

fn logSslErrors(what: []const u8, ssl_err: c_int) void {
    var err_buf: [256]u8 = undefined;
    while (true) {
        const e = c.ERR_get_error();
        if (e == 0) break;
        c.ERR_error_string_n(e, &err_buf, err_buf.len);
        log.err("TLS {s} error: SSL_get_error={d} detail={s}", .{ what, ssl_err, @as([*:0]const u8, @ptrCast(&err_buf)) });
    }
}

/// Connect TCP + TLS handshake with manual cert validation.
pub fn connect(
    alloc: std.mem.Allocator,
    host: []const u8,
    port: u16,
    verify_ctx: *anyopaque,
    verify_fn: VerifyFn,
) TlsError!TlsStream {
    var stream = TlsStream{ .alloc = alloc };
    errdefer stream.deinit();

    vprint("mcp-bridge: [tls] resolving {s}:{d}\n", .{ host, port });
    stream.sock = posix.tcpConnect(alloc, host, port) catch return TlsError.ConnectFailed;
    vprint("mcp-bridge: [tls] tcp connected\n", .{});

    // Manual validation — DANE/PKI policy lives in the verify hook.
    const method = c.TLS_client_method() orelse return TlsError.SslInitFailed;
    const ctx = c.SSL_CTX_new(method) orelse return TlsError.SslInitFailed;
    stream.ctx = ctx;
    c.SSL_CTX_set_verify(ctx, c.SSL_VERIFY_NONE, null);
    // TLS 1.2+ only (SChannel build negotiates 1.2/1.3).
    if (c.SSL_CTX_set_min_proto_version(ctx, c.TLS1_2_VERSION) != 1) return TlsError.SslInitFailed;
    // Enable FreeBSD KTLS where available; silently ignored otherwise.
    // SSL_OP_ENABLE_KTLS = SSL_OP_BIT(3) = 0x8
    _ = c.SSL_CTX_set_options(ctx, 0x8);

    const ssl = c.SSL_new(ctx) orelse return TlsError.SslInitFailed;
    stream.ssl = ssl;
    if (c.SSL_set_fd(ssl, @intCast(stream.sock)) != 1) return TlsError.SslInitFailed;
    c.SSL_set_connect_state(ssl);

    // SNI
    var host_z: [256]u8 = undefined;
    if (host.len >= host_z.len) return TlsError.SslInitFailed;
    @memcpy(host_z[0..host.len], host);
    host_z[host.len] = 0;
    _ = c.SSL_ctrl(ssl, c.SSL_CTRL_SET_TLSEXT_HOSTNAME, c.TLSEXT_NAMETYPE_host_name, @ptrCast(&host_z));

    vprint("mcp-bridge: [tls] handshaking\n", .{});
    // Blocking fd: SSL_connect completes or fails (WANT_* cannot occur).
    const hret = c.SSL_connect(ssl);
    if (hret != 1) {
        logSslErrors("handshake", c.SSL_get_error(ssl, hret));
        return TlsError.HandshakeFailed;
    }
    vprint("mcp-bridge: [tls] handshake complete\n", .{});

    // Certificate verification hook
    if (c.SSL_get0_peer_certificate(ssl) == null) {
        log.err("no remote certificate", .{});
        return TlsError.NoRemoteCert;
    }
    vprint("mcp-bridge: [tls] verifying certificate\n", .{});
    if (!verify_fn(verify_ctx, ssl)) return TlsError.PkiValidationFailed;
    vprint("mcp-bridge: [tls] certificate accepted\n", .{});

    return stream;
}
