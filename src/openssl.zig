// Shared OpenSSL 3.x bindings for the POSIX TLS backend: cImport, DER chain
// extraction, SPKI extraction (DANE selector 1), and trust-store PKI
// verification with hostname checking (fallback when no TLSA is published).
//
// Patterns adapted from xmppd lib/tls/ssl.zig (getPeerCertDer,
// getPeerChainDer, OPENSSL_sk_* casts) — blocking-socket variant.

const std = @import("std");

pub const c = @cImport({
    @cInclude("openssl/ssl.h");
    @cInclude("openssl/err.h");
    @cInclude("openssl/x509.h");
    @cInclude("openssl/x509_vfy.h");
    @cInclude("openssl/x509v3.h");
});

pub const OsslError = error{
    OutOfMemory,
    ParseFailed,
    VerifyFailed,
};

/// DER-encode an X509. Caller owns the returned slice.
fn x509ToDer(alloc: std.mem.Allocator, x509: *c.X509) OsslError![]u8 {
    const der_len = c.i2d_X509(x509, null);
    if (der_len <= 0) return OsslError.ParseFailed;

    const buf = alloc.alloc(u8, @intCast(der_len)) catch return OsslError.OutOfMemory;
    errdefer alloc.free(buf);

    var ptr: [*c]u8 = buf.ptr;
    if (c.i2d_X509(x509, &ptr) != der_len) return OsslError.ParseFailed;
    return buf;
}

/// Extract the peer's full certificate chain (EE first) as DER slices.
/// Caller owns the slice and each element.
pub fn getPeerChainDer(alloc: std.mem.Allocator, ssl: *c.SSL) OsslError![][]u8 {
    const leaf = c.SSL_get0_peer_certificate(ssl) orelse return OsslError.ParseFailed;
    const leaf_der = try x509ToDer(alloc, leaf);
    errdefer alloc.free(leaf_der);

    var list: std.ArrayList([]u8) = .empty;
    errdefer {
        for (list.items) |d| alloc.free(d);
        list.deinit(alloc);
    }

    // Client side: SSL_get_peer_cert_chain includes the leaf at index 0.
    const chain = c.SSL_get_peer_cert_chain(ssl);
    if (chain != null) {
        const num: usize = @intCast(c.OPENSSL_sk_num(@ptrCast(chain)));
        for (0..num) |i| {
            const raw = c.OPENSSL_sk_value(@ptrCast(chain), @intCast(i)) orelse continue;
            const x509: *c.X509 = @ptrCast(@alignCast(raw));
            const der = try x509ToDer(alloc, x509);
            errdefer alloc.free(der);
            // Skip a duplicate of the leaf (we prepend it ourselves).
            if (std.mem.eql(u8, der, leaf_der)) {
                alloc.free(der);
                continue;
            }
            try list.append(alloc, der);
        }
    }

    const rest = try list.toOwnedSlice(alloc);
    const out = alloc.alloc([]u8, rest.len + 1) catch return OsslError.OutOfMemory;
    out[0] = leaf_der;
    @memcpy(out[1..], rest);
    alloc.free(rest);
    return out;
}

pub fn freeChainDer(alloc: std.mem.Allocator, chain: [][]u8) void {
    for (chain) |d| alloc.free(d);
    alloc.free(chain);
}

/// Extract SubjectPublicKeyInfo DER from a certificate's DER encoding.
/// This is the dane.zig `spki_fn` hook for selector 1 (SPKI) TLSA records.
pub fn spkiFromCertDer(alloc: std.mem.Allocator, cert_der: []const u8) OsslError![]u8 {
    var ptr: [*c]const u8 = cert_der.ptr;
    const x509 = c.d2i_X509(null, &ptr, @intCast(cert_der.len)) orelse return OsslError.ParseFailed;
    defer c.X509_free(x509);

    const pubkey = c.X509_get_X509_PUBKEY(x509) orelse return OsslError.ParseFailed;

    const der_len = c.i2d_X509_PUBKEY(pubkey, null);
    if (der_len <= 0) return OsslError.ParseFailed;

    const buf = alloc.alloc(u8, @intCast(der_len)) catch return OsslError.OutOfMemory;
    errdefer alloc.free(buf);

    var out_ptr: [*c]u8 = buf.ptr;
    if (c.i2d_X509_PUBKEY(pubkey, &out_ptr) != der_len) return OsslError.ParseFailed;
    return buf;
}

/// PKI fallback: verify the peer chain against the system trust store
/// (SSL_CTX_set_default_verify_paths equivalent — FreeBSD certctl
/// /etc/ssl/certs, Linux distro bundles) including hostname verification.
pub fn verifyPkiHost(alloc: std.mem.Allocator, host: []const u8, chain_der: []const []const u8) bool {
    if (chain_der.len == 0) return false;

    const store = c.X509_STORE_new() orelse return false;
    defer c.X509_STORE_free(store);
    if (c.X509_STORE_set_default_paths(store) != 1) return false;

    // Parse leaf
    var leaf_ptr: [*c]const u8 = chain_der[0].ptr;
    const leaf = c.d2i_X509(null, &leaf_ptr, @intCast(chain_der[0].len)) orelse return false;
    defer c.X509_free(leaf);

    // Parse intermediates into an untrusted stack
    const untrusted: ?*c.stack_st_X509 = @ptrCast(c.OPENSSL_sk_new_null());
    defer if (untrusted) |s| c.OPENSSL_sk_free(@ptrCast(s));
    var parsed: std.ArrayList(*c.X509) = .empty;
    defer {
        for (parsed.items) |x| c.X509_free(x);
        parsed.deinit(alloc);
    }
    for (chain_der[1..]) |der| {
        var p: [*c]const u8 = der.ptr;
        const x = c.d2i_X509(null, &p, @intCast(der.len)) orelse return false;
        parsed.append(alloc, x) catch {
            c.X509_free(x);
            return false;
        };
        if (untrusted != null) _ = c.OPENSSL_sk_push(@ptrCast(untrusted), x);
    }

    const store_ctx = c.X509_STORE_CTX_new() orelse return false;
    defer c.X509_STORE_CTX_free(store_ctx);
    if (c.X509_STORE_CTX_init(store_ctx, store, leaf, untrusted) != 1) return false;

    // Hostname verification (SAN, CN fallback)
    var host_buf: [256]u8 = undefined;
    if (host.len >= host_buf.len) return false;
    @memcpy(host_buf[0..host.len], host);
    host_buf[host.len] = 0;
    const param = c.X509_STORE_CTX_get0_param(store_ctx);
    if (param == null) return false;
    if (c.X509_VERIFY_PARAM_set1_host(param, @ptrCast(&host_buf), 0) != 1) return false;

    if (c.X509_verify_cert(store_ctx) == 1) return true;

    const verr = c.X509_STORE_CTX_get_error(store_ctx);
    const verr_str = c.X509_verify_cert_error_string(verr);
    std.log.scoped(.openssl).err("PKI verify failed for {s}: {s}", .{ host, verr_str });
    return false;
}
