// DANE TLSA verification (RFC 6698) — algorithm ported from Bloom's
// DANEVerifier.cpp (usage 2/3, selector CERT/SPKI, matching FULL/SHA-256/SHA-512,
// DANE-TA chain walk including single-cert chains).
//
// No DNSSEC validation, per project requirement.
//
// This file is portable: platform-specific chain building lives in
// dane_win.zig (crypt32) / verifier_posix.zig (OpenSSL).

const std = @import("std");

pub var verbose: bool = false;

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

    var hash_buf: [64]u8 = undefined;
    const hashed: []const u8 = switch (tlsa.matching_type) {
        0 => selected,
        1 => blk: {
            std.crypto.hash.sha2.Sha256.hash(selected, hash_buf[0..32], .{});
            break :blk hash_buf[0..32];
        },
        2 => blk: {
            std.crypto.hash.sha2.Sha512.hash(selected, hash_buf[0..64], .{});
            break :blk hash_buf[0..64];
        },
        else => return false,
    };

    if (hashed.len != tlsa.data.len) return false;
    return std.mem.eql(u8, hashed, tlsa.data);
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
