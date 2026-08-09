// TLSA record lookup via the system resolver (res_query) with a hand-rolled
// DNS answer parser. No DNSSEC validation, per project requirement.
//
// POSIX counterpart to dns.zig (Windows DnsQuery_A). Fail-closed semantics
// are identical: NXDOMAIN / NODATA → empty slice (PKI fallback allowed);
// any other lookup error (SERVFAIL/TRY_AGAIN etc.) → error.LookupFailed.
//
// res_query is in libc on both FreeBSD and glibc >= 2.34. The ns_* parser
// API is deliberately NOT used: on glibc it still lives in libresolv.so.2
// (not merged into libc), libresolv references GLIBC_PRIVATE symbols that
// LLD rejects with --no-allow-shlib-undefined, and zig silently drops
// -lresolv on Linux hosts assuming the fold-in. Parsing a DNS answer
// section by hand is small and we control the qname.

const std = @import("std");
const builtin = @import("builtin");
const dane = @import("dane.zig");

// res_query from libc (no resolv.h cImport needed).
extern "c" fn res_query(
    dname: [*:0]const u8,
    class: c_int,
    type_: c_int,
    answer: [*]u8,
    anslen: c_int,
) c_int;

// h_errno accessors: glibc exports __h_errno_location, BSDs export __h_errno.
extern "c" fn __h_errno_location() *c_int;
extern "c" fn __h_errno() *c_int;

fn hErrno() c_int {
    return if (builtin.os.tag == .linux) __h_errno_location().* else __h_errno().*;
}

const HOST_NOT_FOUND: c_int = 1;
const NO_DATA: c_int = 4;

const C_IN: c_int = 1;
const T_TLSA: c_int = 52;
const MAX_RESPONSE = 4096;

pub var verbose: bool = false;

fn vprint(comptime fmt: []const u8, args: anytype) void {
    if (verbose) std.debug.print(fmt, args);
}

pub const DnsError = error{
    LookupFailed,
    OutOfMemory,
};

/// Skip a (possibly compression-terminated) DNS name. Returns the offset
/// just past it, or null on malformed data. Compression pointers are only
/// FOLLOWED for length purposes when they terminate the name — we never
/// dereference them.
fn skipName(msg: []const u8, pos0: usize) ?usize {
    var pos = pos0;
    while (true) {
        if (pos >= msg.len) return null;
        const len = msg[pos];
        if (len == 0) return pos + 1;
        if (len & 0xc0 == 0xc0) return pos + 2; // compression pointer ends the name
        if (len & 0xc0 != 0) return null; // RFC 6891 EDNS extended labels: bail
        pos += 1 + len;
        if (pos > msg.len) return null;
    }
}

fn readU16(msg: []const u8, pos: usize) ?u16 {
    if (pos + 2 > msg.len) return null;
    return std.mem.readInt(u16, msg[pos..][0..2], .big);
}

/// Parse the answer section of a DNS response, collecting TLSA records.
fn collectTlsa(alloc: std.mem.Allocator, msg: []const u8, list: *std.ArrayList(dane.TlsaRecord)) !void {
    if (msg.len < 12) return DnsError.LookupFailed;
    const qdcount = readU16(msg, 4) orelse return DnsError.LookupFailed;
    const ancount = readU16(msg, 6) orelse return DnsError.LookupFailed;

    var pos: usize = 12;
    // Question section
    var q: usize = 0;
    while (q < qdcount) : (q += 1) {
        pos = skipName(msg, pos) orelse return DnsError.LookupFailed;
        if (pos + 4 > msg.len) return DnsError.LookupFailed;
        pos += 4; // qtype + qclass
    }

    // Answer section
    var a: usize = 0;
    while (a < ancount) : (a += 1) {
        pos = skipName(msg, pos) orelse return DnsError.LookupFailed;
        const rtype = readU16(msg, pos) orelse return DnsError.LookupFailed;
        const rdlen = readU16(msg, pos + 8) orelse return DnsError.LookupFailed;
        pos += 10; // type + class + ttl + rdlength
        if (pos + rdlen > msg.len) return DnsError.LookupFailed;
        defer pos += rdlen;

        if (rtype != T_TLSA) continue;
        // Wire format: usage(1) + selector(1) + matching_type(1) + data(...)
        if (rdlen < 4) continue;
        const rdata = msg[pos..][0..rdlen];
        const data_len = rdlen - 3;
        // Sanity bound: TLSA association data is a hash or cert; never huge.
        if (data_len > 8192) continue;

        vprint("mcp-bridge: [dns]   usage={d} selector={d} mtype={d} dataLen={d}\n", .{
            rdata[0], rdata[1], rdata[2], data_len,
        });

        const data_copy = alloc.dupe(u8, rdata[3..]) catch return DnsError.OutOfMemory;
        list.append(alloc, .{
            .usage = rdata[0],
            .selector = rdata[1],
            .matching_type = rdata[2],
            .data = data_copy,
        }) catch {
            alloc.free(data_copy);
            return DnsError.OutOfMemory;
        };
    }
}

/// Fetch TLSA records for `_<port>._tcp.<host>`.
/// Returns an empty slice when the name resolves but has no TLSA records
/// (caller distinguishes "no records" from LookupFailed error).
/// Caller owns the returned slice and each record's data buffer.
pub fn lookupTlsa(
    alloc: std.mem.Allocator,
    host: []const u8,
    port: u16,
) DnsError![]dane.TlsaRecord {
    var qname_buf: [260]u8 = undefined;
    const qname = std.fmt.bufPrintZ(&qname_buf, "_{d}._tcp.{s}", .{ port, host }) catch
        return DnsError.LookupFailed;
    vprint("mcp-bridge: [dns] query {s} TLSA\n", .{qname});

    var response: [MAX_RESPONSE]u8 = undefined;
    const resp_len = res_query(qname.ptr, C_IN, T_TLSA, &response, MAX_RESPONSE);

    if (resp_len < 0) {
        // NXDOMAIN / NODATA is NOT an error for DANE (no records published).
        const herr = hErrno();
        vprint("mcp-bridge: [dns] res_query failed, h_errno={d}\n", .{herr});
        switch (herr) {
            HOST_NOT_FOUND, NO_DATA => return alloc.alloc(dane.TlsaRecord, 0) catch DnsError.OutOfMemory,
            else => return DnsError.LookupFailed, // TRY_AGAIN/SERVFAIL etc. → fail closed
        }
    }

    var list: std.ArrayList(dane.TlsaRecord) = .empty;
    errdefer {
        for (list.items) |r| alloc.free(r.data);
        list.deinit(alloc);
    }

    try collectTlsa(alloc, response[0..@intCast(resp_len)], &list);
    vprint("mcp-bridge: [dns] {d} TLSA record(s)\n", .{list.items.len});
    return list.toOwnedSlice(alloc) catch DnsError.OutOfMemory;
}

pub fn freeTlsaRecords(alloc: std.mem.Allocator, records: []dane.TlsaRecord) void {
    for (records) |r| alloc.free(r.data);
    alloc.free(records);
}

test "skipName: plain, compressed, truncated" {
    // "\x03www\x07example\x03com\x00" then a byte; the offset returned is
    // just PAST the terminating zero (17), where the next field starts.
    const plain = "\x03www\x07example\x03com\x00Z";
    try std.testing.expectEqual(@as(?usize, 17), skipName(plain, 0));
    // compression pointer
    const comp = "\xc0\x0cZZ";
    try std.testing.expectEqual(@as(?usize, 2), skipName(comp, 0));
    // truncated
    try std.testing.expectEqual(@as(?usize, null), skipName("\x05ab", 0));
}

test "collectTlsa: synthetic response with one TLSA answer" {
    const alloc = std.testing.allocator;
    var msg: std.ArrayList(u8) = .empty;
    defer msg.deinit(alloc);
    const w = msg.writer(alloc);

    // header: id, flags, qd=1, an=1
    try w.writeAll(&.{ 0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0 });
    // question: _443._tcp.example.com TLSA IN
    const qname = "\x04_443\x04_tcp\x07example\x03com\x00";
    try w.writeAll(qname);
    try w.writeAll(&.{ 0, 52, 0, 1 });
    // answer: name = compression pointer to offset 12, type TLSA, class IN,
    // ttl 300, rdlen 6, rdata = 03 01 01 aa bb cc
    try w.writeAll(&.{ 0xc0, 0x0c, 0, 52, 0, 1, 0, 0, 1, 0x2c, 0, 6, 3, 1, 1, 0xaa, 0xbb, 0xcc });

    var list: std.ArrayList(dane.TlsaRecord) = .empty;
    defer {
        for (list.items) |r| alloc.free(r.data);
        list.deinit(alloc);
    }
    try collectTlsa(alloc, msg.items, &list);
    try std.testing.expectEqual(@as(usize, 1), list.items.len);
    try std.testing.expectEqual(@as(u8, 3), list.items[0].usage);
    try std.testing.expectEqual(@as(u8, 1), list.items[0].selector);
    try std.testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb, 0xcc }, list.items[0].data);
}
