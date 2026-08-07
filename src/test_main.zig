// Host-side unit tests for platform-independent modules.

const std = @import("std");
const dane = @import("dane.zig");
const mcp = @import("mcp.zig");

fn spkiStub(alloc: std.mem.Allocator, cert_der: []const u8) anyerror![]u8 {
    _ = alloc;
    _ = cert_der;
    return error.Unsupported;
}

test "getRequestId: numeric, string, absent" {
    try std.testing.expectEqualStrings("7", mcp.getRequestId("{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"ping\"}").?);
    try std.testing.expectEqualStrings("\"abc\"", mcp.getRequestId("{\"id\": \"abc\" , \"method\":\"x\"}").?);
    try std.testing.expect(mcp.getRequestId("{\"method\":\"notifications/initialized\"}") == null);
}

test "formatTransportError" {
    var buf: [512]u8 = undefined;
    const s = mcp.formatTransportError(&buf, "3", "ConnectFailed");
    try std.testing.expect(std.mem.indexOf(u8, s, "\"id\":3") != null);
    try std.testing.expect(std.mem.indexOf(u8, s, "ConnectFailed") != null);
}

test "dane: DANE-EE full cert match" {
    const cert = "fake-der-bytes";
    const recs = [_]dane.TlsaRecord{.{ .usage = 3, .selector = 0, .matching_type = 0, .data = cert }};
    const chain = [_][]const u8{cert};
    try std.testing.expectEqual(dane.DaneResult.success, dane.verifyTlsaRecords(&recs, &chain, spkiStub, std.testing.allocator));
}

test "dane: DANE-EE sha256 match" {
    const cert = "fake-der-bytes";
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(cert, &digest, .{});
    const recs = [_]dane.TlsaRecord{.{ .usage = 3, .selector = 0, .matching_type = 1, .data = &digest }};
    const chain = [_][]const u8{cert};
    try std.testing.expectEqual(dane.DaneResult.success, dane.verifyTlsaRecords(&recs, &chain, spkiStub, std.testing.allocator));
}

test "dane: DANE-EE mismatch fails" {
    const recs = [_]dane.TlsaRecord{.{ .usage = 3, .selector = 0, .matching_type = 0, .data = "other" }};
    const chain = [_][]const u8{"fake-der-bytes"};
    try std.testing.expectEqual(dane.DaneResult.validation_failed, dane.verifyTlsaRecords(&recs, &chain, spkiStub, std.testing.allocator));
}

test "dane: DANE-TA walks chain, skips EE" {
    const ee = "leaf-cert";
    const inter = "intermediate-ca";
    // TA record matches the intermediate
    const recs = [_]dane.TlsaRecord{.{ .usage = 2, .selector = 0, .matching_type = 0, .data = inter }};
    const chain = [_][]const u8{ ee, inter };
    try std.testing.expectEqual(dane.DaneResult.success, dane.verifyTlsaRecords(&recs, &chain, spkiStub, std.testing.allocator));

    // TA record matching only the EE must NOT pass with a 2-cert chain
    const recs_ee = [_]dane.TlsaRecord{.{ .usage = 2, .selector = 0, .matching_type = 0, .data = ee }};
    try std.testing.expectEqual(dane.DaneResult.validation_failed, dane.verifyTlsaRecords(&recs_ee, &chain, spkiStub, std.testing.allocator));

    // Single-cert chain: TA matches EE (Bloom single-cert case)
    const single = [_][]const u8{ee};
    try std.testing.expectEqual(dane.DaneResult.success, dane.verifyTlsaRecords(&recs_ee, &single, spkiStub, std.testing.allocator));
}

test "dane: no records / empty chain" {
    const recs = [_]dane.TlsaRecord{};
    const chain = [_][]const u8{"x"};
    try std.testing.expectEqual(dane.DaneResult.no_tlsa_records, dane.verifyTlsaRecords(&recs, &chain, spkiStub, std.testing.allocator));

    const recs2 = [_]dane.TlsaRecord{.{ .usage = 3, .selector = 0, .matching_type = 0, .data = "x" }};
    const empty_chain = [_][]const u8{};
    try std.testing.expectEqual(dane.DaneResult.validation_failed, dane.verifyTlsaRecords(&recs2, &empty_chain, spkiStub, std.testing.allocator));
}

test "dane: invalid params skipped" {
    const cert = "c";
    const recs = [_]dane.TlsaRecord{.{ .usage = 9, .selector = 0, .matching_type = 0, .data = cert }};
    const chain = [_][]const u8{cert};
    try std.testing.expectEqual(dane.DaneResult.validation_failed, dane.verifyTlsaRecords(&recs, &chain, spkiStub, std.testing.allocator));
}
