// PKCE (RFC 7636) primitives: S256 code verifier/challenge.
// Pure functions, no I/O — unit tested.

const std = @import("std");

/// base64url-no-pad of 32 random bytes is exactly 43 chars.
pub const VERIFIER_LEN = 43;
/// base64url-no-pad of a SHA-256 digest is exactly 43 chars.
pub const CHALLENGE_LEN = 43;

/// Generate a code verifier: 32 bytes of CSPRNG entropy, base64url encoded
/// (43 chars, within the RFC 7636 43–128 range).
pub fn generateVerifier() [VERIFIER_LEN]u8 {
    var rand: [32]u8 = undefined;
    std.crypto.random.bytes(&rand);
    var out: [VERIFIER_LEN]u8 = undefined;
    _ = std.base64.url_safe_no_pad.Encoder.encode(&out, &rand);
    return out;
}

/// S256 code challenge: base64url-no-pad(SHA-256(verifier)).
pub fn challengeS256(verifier: []const u8) [CHALLENGE_LEN]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(verifier, &digest, .{});
    var out: [CHALLENGE_LEN]u8 = undefined;
    _ = std.base64.url_safe_no_pad.Encoder.encode(&out, &digest);
    return out;
}

test "challengeS256: RFC 7636 Appendix B vector" {
    const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    try std.testing.expectEqualStrings(expected, &challengeS256(verifier));
}

test "generateVerifier: shape and uniqueness" {
    const a = generateVerifier();
    const b = generateVerifier();
    // 43 chars, all from the base64url alphabet
    for (a) |ch| {
        const ok = std.ascii.isAlphanumeric(ch) or ch == '-' or ch == '_';
        try std.testing.expect(ok);
    }
    try std.testing.expect(!std.mem.eql(u8, &a, &b));
    // Self-consistency: challenge of same verifier is stable
    try std.testing.expectEqual(challengeS256(&a), challengeS256(&a));
}
