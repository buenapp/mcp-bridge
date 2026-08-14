// DANE TLSA verification — Windows-specific chain building (crypt32) and
// PKI fallback against the Windows root store.
//
// Verbatim relocation of the Windows section of dane.zig (v0.1.0). The
// portable matcher core (TlsaRecord, DaneResult, matchCertToTlsa,
// verifyTlsaRecords) stays in dane.zig.

const std = @import("std");
const win = @import("win.zig");
const dane = @import("dane.zig");

const TlsaRecord = dane.TlsaRecord;
const DaneResult = dane.DaneResult;

const ulog = @import("ulog.zig");

fn vprint(comptime fmt: []const u8, args: anytype) void {
    ulog.vprint(fmt, args);
}

fn hexEncode(alloc: std.mem.Allocator, data: []const u8) []u8 {
    const out = alloc.alloc(u8, data.len * 2) catch return &.{};
    const chars = "0123456789abcdef";
    for (data, 0..) |b, i| {
        out[i * 2] = chars[b >> 4];
        out[i * 2 + 1] = chars[b & 0xf];
    }
    return out;
}

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
/// The leaf's own hCertStore (where SChannel puts the other handshake
/// certs) is passed as hAdditionalStore so intermediates are found.
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
        leaf.hCertStore, // SChannel keeps the peer's extra certs here
        &para,
        0,
        null,
        &chain_ctx,
    ) == 0 or chain_ctx == null) {
        return error.ChainBuildFailed;
    }
    errdefer win.CertFreeCertificateChain(chain_ctx.?);

    const chain = chain_ctx.?;
    vprint("mcp-bridge: [dane] CertGetCertificateChain: cChain={d} trustError=0x{x}\n", .{
        chain.cChain, chain.TrustStatus.dwErrorStatus,
    });
    if (chain.cChain == 0 or chain.rgpChain == null) return error.EmptyChain;

    const simple = chain.rgpChain.?[0] orelse return error.EmptyChain;
    const n = simple.cElement;
    vprint("mcp-bridge: [dane] simple chain cElement={d} trustError=0x{x}\n", .{ n, simple.TrustStatus.dwErrorStatus });
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

        vprint("mcp-bridge: [dane] chain has {d} cert(s); tlsa usage={d} sel={d} mt={d} data={s}\n", .{
            certs.len, tlsa.usage, tlsa.selector, tlsa.matching_type, hexEncode(alloc, tlsa.data),
        });

        const tryMatch = struct {
            fn go(cc: []const ChainCert, t: TlsaRecord, idx: usize, a: std.mem.Allocator) bool {
                if (t.selector == 1) {
                    const spki = extractSpkiFromContext(a, cc[idx].ctx) catch |err| {
                        vprint("mcp-bridge: [dane]   cert[{d}] SPKI extraction failed: {s}\n", .{ idx, @errorName(err) });
                        return false;
                    };
                    defer a.free(spki);
                    vprint("mcp-bridge: [dane]   cert[{d}] spki({d}b) -> {s}\n", .{ idx, spki.len, hexEncode(a, processed(spki, t.matching_type)) });
                    return matchHashed(spki, t);
                }
                vprint("mcp-bridge: [dane]   cert[{d}] cert({d}b) -> {s}\n", .{ idx, cc[idx].der.len, hexEncode(a, processed(cc[idx].der, t.matching_type)) });
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

fn processed(selected: []const u8, matching_type: u8) []const u8 {
    const S = struct {
        var buf: [64]u8 = undefined;
    };
    switch (matching_type) {
        0 => return selected,
        1 => {
            std.crypto.hash.sha2.Sha256.hash(selected, S.buf[0..32], .{});
            return S.buf[0..32];
        },
        2 => {
            std.crypto.hash.sha2.Sha512.hash(selected, S.buf[0..64], .{});
            return S.buf[0..64];
        },
        else => return &.{},
    }
}

fn matchHashed(selected: []const u8, tlsa: TlsaRecord) bool {
    const p = processed(selected, tlsa.matching_type);
    if (p.len != tlsa.data.len) return false;
    return std.mem.eql(u8, p, tlsa.data);
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
