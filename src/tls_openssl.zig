// TLS client over OpenSSL 3.x (POSIX) with manual certificate validation
// hook — same surface and policy as schannel.zig: DANE first, system
// trust-store PKI fallback (both live in the Verifier, invoked via the
// verify_fn hook after the handshake).
//
// The upper half (TlsStream) is the legacy blocking path (SO_RCVTIMEO),
// retiring with the event-core rework. The lower half (TlsNb) is the
// event-core non-blocking layer: the handshake and I/O are driven by
// WANT_READ/WANT_WRITE re-registration on the platform event port.

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

// --------------------------------------------------- non-blocking TLS ----

/// Direction a non-blocking operation needs before it can make progress.
pub const Drive = union(enum) {
    done,
    want_read,
    want_write,
};

/// Non-blocking TLS client stream for the event core. All operations are
/// driven by SSL_WANT_READ/SSL_WANT_WRITE re-registration; nothing blocks.
/// The certificate verify hook runs once after handshakeDrive() returns
/// .done (Verifier.verifyOpaque, same DANE/PKI policy as the legacy path).
pub const TlsNb = struct {
    sock: std.posix.fd_t = -1,
    ctx: ?*c.SSL_CTX = null,
    ssl: ?*c.SSL = null,

    /// Wrap an already-connected non-blocking socket (see posix.PlainNb).
    /// SNI = host. Does NOT take ownership on failure (caller closes sock).
    pub fn initOnSocket(sock: std.posix.fd_t, host: []const u8) TlsError!TlsNb {
        const method = c.TLS_client_method() orelse return TlsError.SslInitFailed;
        const ctx = c.SSL_CTX_new(method) orelse return TlsError.SslInitFailed;
        errdefer c.SSL_CTX_free(ctx);
        c.SSL_CTX_set_verify(ctx, c.SSL_VERIFY_NONE, null);
        // TLS 1.2+ only (SChannel build negotiates 1.2/1.3).
        if (c.SSL_CTX_set_min_proto_version(ctx, c.TLS1_2_VERSION) != 1) return TlsError.SslInitFailed;
        // Enable FreeBSD KTLS where available; silently ignored otherwise.
        // SSL_OP_ENABLE_KTLS = SSL_OP_BIT(3) = 0x8
        _ = c.SSL_CTX_set_options(ctx, 0x8);
        // Partial writes keep the connection's write queue honest about
        // progress (SSL_write may consume less than requested).
        _ = c.SSL_CTX_set_mode(ctx, c.SSL_MODE_ENABLE_PARTIAL_WRITE);

        const ssl = c.SSL_new(ctx) orelse return TlsError.SslInitFailed;
        errdefer c.SSL_free(ssl);
        if (c.SSL_set_fd(ssl, @intCast(sock)) != 1) return TlsError.SslInitFailed;
        c.SSL_set_connect_state(ssl);

        // SNI
        var host_z: [256]u8 = undefined;
        if (host.len >= host_z.len) return TlsError.SslInitFailed;
        @memcpy(host_z[0..host.len], host);
        host_z[host.len] = 0;
        _ = c.SSL_ctrl(ssl, c.SSL_CTRL_SET_TLSEXT_HOSTNAME, c.TLSEXT_NAMETYPE_host_name, @ptrCast(&host_z));

        return .{ .sock = sock, .ctx = ctx, .ssl = ssl };
    }

    /// Drive the TLS handshake one step. Re-register for the returned
    /// direction and call again on the event.
    pub fn handshakeDrive(self: *TlsNb) TlsError!Drive {
        const ret = c.SSL_connect(self.ssl.?);
        if (ret == 1) return .done;
        const err = c.SSL_get_error(self.ssl.?, ret);
        switch (err) {
            c.SSL_ERROR_WANT_READ => return .want_read,
            c.SSL_ERROR_WANT_WRITE => return .want_write,
            else => {
                logSslErrors("handshake", err);
                return TlsError.HandshakeFailed;
            },
        }
    }

    /// Read decrypted application data. Draining to .want_read implies the
    /// underlying socket hit EAGAIN (OpenSSL's record layer always reads
    /// the socket dry first), which is what EV_CLEAR requires.
    pub fn readNb(self: *TlsNb, out: []u8) TlsError!posix.NbRead {
        const ret = c.SSL_read(self.ssl.?, out.ptr, @intCast(out.len));
        if (ret > 0) return .{ .data = @intCast(ret) };

        const err = c.SSL_get_error(self.ssl.?, ret);
        switch (err) {
            c.SSL_ERROR_ZERO_RETURN => return .eof, // close_notify
            c.SSL_ERROR_WANT_READ => return .want_read,
            c.SSL_ERROR_WANT_WRITE => return .want_write,
            c.SSL_ERROR_SYSCALL => {
                if (ret == 0) return .eof; // unexpected TCP EOF; treat as close
                logSslErrors("read", err);
                return TlsError.TlsError;
            },
            else => {
                logSslErrors("read", err);
                return TlsError.TlsError;
            },
        }
    }

    /// Write plaintext; may consume fewer bytes than given (partial-write
    /// mode). .want_read can occur on post-handshake control messages.
    pub fn writeNb(self: *TlsNb, data: []const u8) TlsError!posix.NbWrite {
        if (data.len == 0) return .{ .done = 0 };
        const ret = c.SSL_write(self.ssl.?, data.ptr, @intCast(data.len));
        if (ret > 0) return .{ .done = @intCast(ret) };

        const err = c.SSL_get_error(self.ssl.?, ret);
        switch (err) {
            c.SSL_ERROR_WANT_READ => return .want_read,
            c.SSL_ERROR_WANT_WRITE => return .want_write,
            else => {
                logSslErrors("write", err);
                return TlsError.TlsError;
            },
        }
    }

    /// Best-effort close_notify.
    pub fn closeNotify(self: *TlsNb) void {
        if (self.ssl) |s| _ = c.SSL_shutdown(s);
    }

    pub fn deinit(self: *TlsNb) void {
        if (self.ssl) |s| c.SSL_free(s);
        if (self.ctx) |x| c.SSL_CTX_free(x);
        if (self.sock >= 0) std.posix.close(self.sock);
        self.ssl = null;
        self.ctx = null;
        self.sock = -1;
    }
};

// --------------------------------------------------------------- tests ----

// Throwaway test-only self-signed cert (CN=localhost, EC prime256v1,
// generated 2026-08-09, expires 2036). Never used outside this test.
const test_cert_pem =
    \\-----BEGIN CERTIFICATE-----
    \\MIIBfTCCASOgAwIBAgIUUY11E6+WhJQ0XL6QoRSb3neZUGUwCgYIKoZIzj0EAwIw
    \\FDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDgwOTIzNTQzM1oXDTM2MDgwNjIz
    \\NTQzM1owFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0D
    \\AQcDQgAEEkzYGSQ9B5br1QvgjqLG4rQtlMb8XWgISMrtlizNstg8A/IoJlwPLpYG
    \\10l19kYpXAm4s3YpdZ8bXnjhv/CaGKNTMFEwHQYDVR0OBBYEFKq2gGln6b2/bFBY
    \\h5DmNT40iuJ3MB8GA1UdIwQYMBaAFKq2gGln6b2/bFBYh5DmNT40iuJ3MA8GA1Ud
    \\EwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhANfTgUCxghaH29aFg5wrQ1Yb
    \\3XI2ZZGfi56+NNJCHjURAiB7sx/6uyLsBk8tUkkeAC2vOyepiFRVOzdKJYgJvXda
    \\WQ==
    \\-----END CERTIFICATE-----
    \\
;
const test_key_pem =
    \\-----BEGIN TEST FIXTURE-----
    \\REDACTED-TEST-ONLY
    \\REDACTED-TEST-ONLY
    \\REDACTED-TEST-ONLY
    \\-----END TEST FIXTURE-----
    \\
;

/// Minimal non-blocking TLS server endpoint for the interlock test.
const TestServer = struct {
    ctx: ?*c.SSL_CTX = null,
    ssl: ?*c.SSL = null,

    fn init(sock: std.posix.fd_t) TlsError!TestServer {
        const method = c.TLS_server_method() orelse return TlsError.SslInitFailed;
        const ctx = c.SSL_CTX_new(method) orelse return TlsError.SslInitFailed;
        errdefer c.SSL_CTX_free(ctx);
        if (c.SSL_CTX_set_min_proto_version(ctx, c.TLS1_2_VERSION) != 1) return TlsError.SslInitFailed;

        const cbio = c.BIO_new_mem_buf(test_cert_pem.ptr, @intCast(test_cert_pem.len)) orelse return TlsError.SslInitFailed;
        defer _ = c.BIO_free(cbio);
        const cert = c.PEM_read_bio_X509(cbio, null, null, null) orelse return TlsError.SslInitFailed;
        defer c.X509_free(cert);
        if (c.SSL_CTX_use_certificate(ctx, cert) != 1) return TlsError.SslInitFailed;

        const kbio = c.BIO_new_mem_buf(test_key_pem.ptr, @intCast(test_key_pem.len)) orelse return TlsError.SslInitFailed;
        defer _ = c.BIO_free(kbio);
        const pkey = c.PEM_read_bio_PrivateKey(kbio, null, null, null) orelse return TlsError.SslInitFailed;
        defer c.EVP_PKEY_free(pkey);
        if (c.SSL_CTX_use_PrivateKey(ctx, pkey) != 1) return TlsError.SslInitFailed;

        const ssl = c.SSL_new(ctx) orelse return TlsError.SslInitFailed;
        errdefer c.SSL_free(ssl);
        if (c.SSL_set_fd(ssl, @intCast(sock)) != 1) return TlsError.SslInitFailed;
        c.SSL_set_accept_state(ssl);
        return .{ .ctx = ctx, .ssl = ssl };
    }

    fn drive(self: *TestServer) TlsError!Drive {
        const ret = c.SSL_accept(self.ssl.?);
        if (ret == 1) return .done;
        const err = c.SSL_get_error(self.ssl.?, ret);
        switch (err) {
            c.SSL_ERROR_WANT_READ => return .want_read,
            c.SSL_ERROR_WANT_WRITE => return .want_write,
            else => {
                logSslErrors("accept", err);
                return TlsError.HandshakeFailed;
            },
        }
    }

    fn readNb(self: *TestServer, out: []u8) TlsError!posix.NbRead {
        const ret = c.SSL_read(self.ssl.?, out.ptr, @intCast(out.len));
        if (ret > 0) return .{ .data = @intCast(ret) };
        const err = c.SSL_get_error(self.ssl.?, ret);
        return switch (err) {
            c.SSL_ERROR_ZERO_RETURN => .eof,
            c.SSL_ERROR_WANT_READ => .want_read,
            c.SSL_ERROR_WANT_WRITE => .want_write,
            else => TlsError.TlsError,
        };
    }

    fn writeNb(self: *TestServer, data: []const u8) TlsError!posix.NbWrite {
        const ret = c.SSL_write(self.ssl.?, data.ptr, @intCast(data.len));
        if (ret > 0) return .{ .done = @intCast(ret) };
        const err = c.SSL_get_error(self.ssl.?, ret);
        return switch (err) {
            c.SSL_ERROR_WANT_READ => .want_read,
            c.SSL_ERROR_WANT_WRITE => .want_write,
            else => TlsError.TlsError,
        };
    }

    fn deinit(self: *TestServer) void {
        if (self.ssl) |s| c.SSL_free(s);
        if (self.ctx) |x| c.SSL_CTX_free(x);
        // fd closed by the test
    }
};

test "TlsNb: non-blocking handshake interlock + encrypted echo" {
    var fds: [2]c_int = undefined;
    try std.testing.expectEqual(@as(c_int, 0), std.c.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM | std.posix.SOCK.NONBLOCK | std.posix.SOCK.CLOEXEC, 0, &fds));
    defer _ = std.c.close(fds[0]); // server end (TestServer borrows)
    // client end owned/closed by TlsNb.deinit

    var server = try TestServer.init(fds[0]);
    defer server.deinit();
    var client = try TlsNb.initOnSocket(fds[1], "localhost");
    defer client.deinit();

    // Drive both ends alternately: each WANT_* is satisfied by the other
    // side making progress. Bounded iteration guards against livelock.
    var server_done = false;
    var client_done = false;
    var guard: usize = 0;
    while ((!server_done or !client_done) and guard < 200) : (guard += 1) {
        if (!server_done) switch (try server.drive()) {
            .done => server_done = true,
            else => {},
        };
        if (!client_done) switch (try client.handshakeDrive()) {
            .done => client_done = true,
            else => {},
        };
    }
    try std.testing.expect(server_done and client_done);

    // A peer certificate is presented (the conn verify hook's precondition).
    try std.testing.expect(c.SSL_get0_peer_certificate(client.ssl.?) != null);

    var buf: [64]u8 = undefined;

    // Nothing sent yet: read must report want_read (never blocks).
    switch (try server.readNb(&buf)) {
        .want_read => {},
        else => return error.TestUnexpectedResult,
    }

    switch (try client.writeNb("ping")) {
        .done => |n| try std.testing.expectEqual(@as(usize, 4), n),
        else => return error.TestUnexpectedResult,
    }
    switch (try server.readNb(&buf)) {
        .data => |n| try std.testing.expectEqualStrings("ping", buf[0..n]),
        else => return error.TestUnexpectedResult,
    }
    switch (try server.writeNb("pong")) {
        .done => |n| try std.testing.expectEqual(@as(usize, 4), n),
        else => return error.TestUnexpectedResult,
    }
    switch (try client.readNb(&buf)) {
        .data => |n| try std.testing.expectEqualStrings("pong", buf[0..n]),
        else => return error.TestUnexpectedResult,
    }
    // Drained: want_read again (the EV_CLEAR precondition).
    switch (try client.readNb(&buf)) {
        .want_read => {},
        else => return error.TestUnexpectedResult,
    }
}
