// DANE TLSA verification (RFC 6698) — algorithm ported from Bloom's
// DANEVerifier.cpp (usage 2/3, selector CERT/SPKI, matching FULL/SHA-256/SHA-512,
// DANE-TA chain walk including single-cert chains).
//
// No DNSSEC validation, per project requirement.

const std = @import("std");
const win = @import("win.zig");

pub const TlsaRecord = struct {
    usage: u8, // 2 = DANE-TA, 3 = DANE-EE (0/1 = PKIX-* also matched like Bloom)
    selector: u8, // 0 = CERT, 1 = SPKI
    matching_type: u8, // 0 = FULL, 1 = SHA-256, 2 = SHA-512
    data: []const u8, // certificate association data
};

pub const DaneResult = enum {
    success,
    no_tlsa_records,
    validation_failed,
    dns_lookup_failed,
    invalid_tlsa_record,
};

/// Pure matcher: does `cert_der` satisfy `tlsa`?
/// `spki_fn` extracts SubjectPublicKeyInfo DER from a cert (platform hook).
pub fn matchCertToTlsa(
    cert_der: []const u8,
    tlsa: TlsaRecord,
    spki_fn: *const fn (alloc: std.mem.Allocator, cert_der: []const u8) anyerror![]u8,
    alloc: std.mem.Allocator,
) bool {
    var selected: []const u8 = undefined;
    var selected_owned: ?[]u8 = null;
    defer if (selected_owned) |b| alloc.free(b);

    switch (tlsa.selector) {
        0 => selected = cert_der,
        1 => {
            const spki = spki_fn(alloc, cert_der) catch return false;
            selected_owned = spki;
            selected = spki;
        },
        else => return false,
    }

    var processed_buf: [64]u8 = undefined;
    const processed: []const u8 = switch (tlsa.matching_type) {
        0 => selected,
        1 => blk: {
            std.crypto.hash.sha2.Sha256.hash(selected, processed_buf[0..32], .{});
            break :blk processed_buf[0..32];
        },
        2 => blk: {
            std.crypto.hash.sha2.Sha512.hash(selected, processed_buf[0..64], .{});
            break :blk processed_buf[0..64];
        },
        else => return false,
    };

    if (processed.len != tlsa.data.len) return false;
    return std.mem.eql(u8, processed, tlsa.data);
}

/// Verify a cert chain (DER list, EE first) against TLSA records.
/// Port of VerifyTLSARecords from DANEVerifier.cpp.
pub fn verifyTlsaRecords(
    tlsa_records: []const TlsaRecord,
    cert_chain_der: []const []const u8,
    spki_fn: *const fn (alloc: std.mem.Allocator, cert_der: []const u8) anyerror![]u8,
    alloc: std.mem.Allocator,
) DaneResult {
    if (tlsa_records.len == 0) return .no_tlsa_records;
    if (cert_chain_der.len == 0) return .validation_failed;

    for (tlsa_records) |tlsa| {
        // Validate parameters
        if (tlsa.usage > 3 or tlsa.selector > 1 or tlsa.matching_type > 2) continue;

        switch (tlsa.usage) {
            0, 3 => { // PKIX-EE, DANE-EE: EE cert is first in chain
                if (matchCertToTlsa(cert_chain_der[0], tlsa, spki_fn, alloc)) {
                    return .success;
                }
            },
            1, 2 => { // PKIX-TA, DANE-TA: walk chain for a matching anchor
                var i: usize = 1;
                while (i < cert_chain_der.len) : (i += 1) {
                    if (matchCertToTlsa(cert_chain_der[i], tlsa, spki_fn, alloc)) {
                        return .success;
                    }
                }
                // Single-cert chain: check the EE cert itself
                if (cert_chain_der.len == 1) {
                    if (matchCertToTlsa(cert_chain_der[0], tlsa, spki_fn, alloc)) {
                        return .success;
                    }
                }
            },
            else => unreachable,
        }
    }

    return .validation_failed;
}

// ------------------------------------------------------------ windows -----

/// Extract SPKI DER from a decoded CERT_CONTEXT (Windows).
pub fn extractSpkiFromContext(alloc: std.mem.Allocator, ctx: *const win.CERT_CONTEXT) ![]u8 {
    const info = ctx.pCertInfo orelse return error.NoCertInfo;
    const spki = &info.SubjectPublicKeyInfo;

    var size: win.DWORD = 0;
    if (win.CryptEncodeObjectEx(
        win.X509_ASN_ENCODING,
        win.X509_PUBLIC_KEY_INFO,
        spki,
        0,
        null,
        null,
        &size,
    ) == 0) {
        return error.EncodeSizeFailed;
    }

    const buf = try alloc.alloc(u8, size);
    errdefer alloc.free(buf);

    if (win.CryptEncodeObjectEx(
        win.X509_ASN_ENCODING,
        win.X509_PUBLIC_KEY_INFO,
        spki,
        0,
        null,
        buf.ptr,
        &size,
    ) == 0) {
        return error.EncodeFailed;
    }
    return buf[0..size];
}

pub const ChainCert = struct {
    der: []const u8,
    ctx: *win.CERT_CONTEXT,
};

/// Build the cert chain for the server leaf context via crypt32.
/// Caller must call freeChain().
pub fn buildChain(leaf: *win.CERT_CONTEXT) !struct { chain: *win.CERT_CHAIN_CONTEXT, certs: []ChainCert } {
    var chain_ctx: ?*win.CERT_CHAIN_CONTEXT = null;
    var para: win.CERT_CHAIN_PARA = std.mem.zeroes(win.CERT_CHAIN_PARA);
    para.cbSize = @sizeOf(win.CERT_CHAIN_PARA);
    para.RequestedUsage.dwType = win.USAGE_MATCH_TYPE_AND;

    if (win.CertGetCertificateChain(
        null,
        leaf,
        null,
        null,
        &para,
        0,
        null,
        &chain_ctx,
    ) == 0 or chain_ctx == null) {
        return error.ChainBuildFailed;
    }
    errdefer win.CertFreeCertificateChain(chain_ctx.?);

    const chain = chain_ctx.?;
    if (chain.cChain == 0 or chain.rgpChain == null) return error.EmptyChain;

    const simple = chain.rgpChain.?[0] orelse return error.EmptyChain;
    const n = simple.cElement;
    const elems = simple.rgpElement orelse return error.EmptyChain;

    const certs = try std.heap.page_allocator.alloc(ChainCert, n);
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const elem = elems[i] orelse return error.EmptyChain;
        const ctx = elem.pCertContext orelse return error.EmptyChain;
        certs[i] = .{
            .der = ctx.pbCertEncoded[0..ctx.cbCertEncoded],
            .ctx = ctx,
        };
    }

    return .{ .chain = chain, .certs = certs };
}

pub fn freeChain(chain: *win.CERT_CHAIN_CONTEXT, certs: []ChainCert) void {
    std.heap.page_allocator.free(certs);
    win.CertFreeCertificateChain(chain);
}

/// DANE verification entry: verify chain contexts against TLSA records.
pub fn verifyChainDane(
    alloc: std.mem.Allocator,
    tlsa_records: []const TlsaRecord,
    certs: []const ChainCert,
) DaneResult {
    if (tlsa_records.len == 0) return .no_tlsa_records;
    if (certs.len == 0) return .validation_failed;

    for (tlsa_records) |tlsa| {
        if (tlsa.usage > 3 or tlsa.selector > 1 or tlsa.matching_type > 2) continue;

        const tryMatch = struct {
            fn go(cc: []const ChainCert, t: TlsaRecord, idx: usize, a: std.mem.Allocator) bool {
                if (t.selector == 1) {
                    const spki = extractSpkiFromContext(a, cc[idx].ctx) catch return false;
                    defer a.free(spki);
                    return matchHashed(spki, t);
                }
                return matchHashed(cc[idx].der, t);
            }
        }.go;

        switch (tlsa.usage) {
            0, 3 => {
                if (tryMatch(certs, tlsa, 0, alloc)) return .success;
            },
            1, 2 => {
                var i: usize = 1;
                while (i < certs.len) : (i += 1) {
                    if (tryMatch(certs, tlsa, i, alloc)) return .success;
                }
                if (certs.len == 1) {
                    if (tryMatch(certs, tlsa, 0, alloc)) return .success;
                }
            },
            else => unreachable,
        }
    }
    return .validation_failed;
}

fn matchHashed(selected: []const u8, tlsa: TlsaRecord) bool {
    var buf: [64]u8 = undefined;
    const processed: []const u8 = switch (tlsa.matching_type) {
        0 => selected,
        1 => blk: {
            std.crypto.hash.sha2.Sha256.hash(selected, buf[0..32], .{});
            break :blk buf[0..32];
        },
        2 => blk: {
            std.crypto.hash.sha2.Sha512.hash(selected, buf[0..64], .{});
            break :blk buf[0..64];
        },
        else => return false,
    };
    return std.mem.eql(u8, processed, tlsa.data);
}

/// PKI fallback: standard server-auth chain policy against the Windows
/// root store, including hostname verification.
pub fn verifyChainPki(chain: *win.CERT_CHAIN_CONTEXT, hostname_w: [:0]const u16) bool {
    var ssl_para: win.SSL_EXTRA_CERT_CHAIN_POLICY_PARA = std.mem.zeroes(win.SSL_EXTRA_CERT_CHAIN_POLICY_PARA);
    ssl_para.cbSize = @sizeOf(win.SSL_EXTRA_CERT_CHAIN_POLICY_PARA);
    ssl_para.dwAuthType = win.AUTHTYPE_SERVER;
    ssl_para.pwszServerName = hostname_w.ptr;

    var policy_para: win.CERT_CHAIN_POLICY_PARA = std.mem.zeroes(win.CERT_CHAIN_POLICY_PARA);
    policy_para.cbSize = @sizeOf(win.CERT_CHAIN_POLICY_PARA);
    policy_para.pvExtraPolicyPara = &ssl_para;

    var status: win.CERT_CHAIN_POLICY_STATUS = std.mem.zeroes(win.CERT_CHAIN_POLICY_STATUS);
    status.cbSize = @sizeOf(win.CERT_CHAIN_POLICY_STATUS);

    const ok = win.CertVerifyCertificateChainPolicy(
        win.CERT_CHAIN_POLICY_SSL,
        chain,
        &policy_para,
        &status,
    );
    return ok != 0 and status.dwError == 0;
}
