// TLS client over OpenSSL 3.x (POSIX) with manual certificate validation
// hook — same policy as schannel.zig: DANE first, system trust-store PKI
// fallback (both live in the Verifier, invoked after the handshake).
//
// Event-core non-blocking layer (issue #7): the handshake and I/O are
// driven by WANT_READ/WANT_WRITE re-registration on the platform event
// port. The legacy blocking TlsStream retired with the serial core.

const std = @import("std");
const posix = @import("posix.zig");
const openssl = @import("openssl.zig");

const c = openssl.c;
const log = std.log.scoped(.tls_openssl);
const ulog = @import("ulog.zig");

fn vprint(comptime fmt: []const u8, args: anytype) void {
    ulog.vprint(fmt, args);
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

fn logSslErrors(what: []const u8, ssl_err: c_int) void {
    var err_buf: [256]u8 = undefined;
    while (true) {
        const e = c.ERR_get_error();
        if (e == 0) break;
        c.ERR_error_string_n(e, &err_buf, err_buf.len);
        log.err("TLS {s} error: SSL_get_error={d} detail={s}", .{ what, ssl_err, @as([*:0]const u8, @ptrCast(&err_buf)) });
    }
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

        vprint("mcp-bridge: [tls] handshaking\n", .{});
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
        if (ret == 1) {
            vprint("mcp-bridge: [tls] handshake complete\n", .{});
            return .done;
        }
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

/// The interlock test's keypair is GENERATED at test time — no PEM
/// fixtures in the repo (secret scanners reject embedded keys, rightly).
const TestPki = struct {
    key: *c.EVP_PKEY,
    cert: *c.X509,
};

fn generateTestPki() ?TestPki {
    const kctx = c.EVP_PKEY_CTX_new_id(c.EVP_PKEY_EC, null) orelse return null;
    defer c.EVP_PKEY_CTX_free(kctx);
    if (c.EVP_PKEY_keygen_init(kctx) <= 0) return null;
    if (c.EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kctx, c.NID_X9_62_prime256v1) <= 0) return null;
    var pkey: ?*c.EVP_PKEY = null;
    if (c.EVP_PKEY_keygen(kctx, &pkey) <= 0) return null;
    const key = pkey orelse return null;
    errdefer c.EVP_PKEY_free(key);

    const x = c.X509_new() orelse return null;
    errdefer c.X509_free(x);
    if (c.X509_set_version(x, 2) != 1) return null;
    var serial: u64 = undefined;
    std.crypto.random.bytes(std.mem.asBytes(&serial));
    serial &= 0x7FFFFFFFFFFFFFFF; // positive
    if (c.ASN1_INTEGER_set_uint64(c.X509_get_serialNumber(x), serial) != 1) return null;
    if (c.X509_gmtime_adj(c.X509_getm_notBefore(x), 0) == null) return null;
    if (c.X509_gmtime_adj(c.X509_getm_notAfter(x), 365 * 24 * 3600) == null) return null;
    const name = c.X509_get_subject_name(x);
    if (name == null) return null;
    if (c.X509_NAME_add_entry_by_txt(name, "CN", c.MBSTRING_ASC, "localhost", -1, -1, 0) != 1) return null;
    if (c.X509_set_issuer_name(x, c.X509_get_subject_name(x)) != 1) return null; // self-signed
    if (c.X509_set_pubkey(x, key) != 1) return null;
    if (c.X509_sign(x, key, c.EVP_sha256()) <= 0) return null;
    return .{ .key = key, .cert = x };
}

/// Minimal non-blocking TLS server endpoint for the interlock test.
const TestServer = struct {
    ctx: ?*c.SSL_CTX = null,
    ssl: ?*c.SSL = null,

    fn init(sock: std.posix.fd_t) TlsError!TestServer {
        const method = c.TLS_server_method() orelse return TlsError.SslInitFailed;
        const ctx = c.SSL_CTX_new(method) orelse return TlsError.SslInitFailed;
        errdefer c.SSL_CTX_free(ctx);
        if (c.SSL_CTX_set_min_proto_version(ctx, c.TLS1_2_VERSION) != 1) return TlsError.SslInitFailed;

        const pki = generateTestPki() orelse return TlsError.SslInitFailed;
        defer {
            c.X509_free(pki.cert);
            c.EVP_PKEY_free(pki.key);
        }
        if (c.SSL_CTX_use_certificate(ctx, pki.cert) != 1) return TlsError.SslInitFailed;
        if (c.SSL_CTX_use_PrivateKey(ctx, pki.key) != 1) return TlsError.SslInitFailed;

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
