// TLSA record lookup via the system resolver (res_query + ns_* parser).
// No DNSSEC validation, per project requirement.
//
// POSIX counterpart to dns.zig (Windows DnsQuery_A). Fail-closed semantics
// are identical: NXDOMAIN / NODATA → empty slice (PKI fallback allowed);
// any other lookup error (SERVFAIL/TRY_AGAIN etc.) → error.LookupFailed.
//
// res_query/ns_* live in libc on FreeBSD; Linux links libresolv (build.zig).

const std = @import("std");
const builtin = @import("builtin");
const dane = @import("dane.zig");

const c = @cImport({
    @cInclude("resolv.h");
    @cInclude("arpa/nameser.h");
});

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
    const resp_len = c.res_query(
        qname.ptr,
        C_IN,
        T_TLSA,
        &response,
        MAX_RESPONSE,
    );

    if (resp_len < 0) {
        // NXDOMAIN / NODATA is NOT an error for DANE (no records published).
        const herr = hErrno();
        vprint("mcp-bridge: [dns] res_query failed, h_errno={d}\n", .{herr});
        switch (herr) {
            HOST_NOT_FOUND, NO_DATA => return alloc.alloc(dane.TlsaRecord, 0) catch DnsError.OutOfMemory,
            else => return DnsError.LookupFailed, // TRY_AGAIN/SERVFAIL etc. → fail closed
        }
    }

    var msg: c.ns_msg = undefined;
    if (c.ns_initparse(&response, resp_len, &msg) < 0) return DnsError.LookupFailed;

    const answer_count: usize = @intCast(c.ns_msg_count(msg, c.ns_s_an));
    vprint("mcp-bridge: [dns] {d} answer(s)\n", .{answer_count});
    if (answer_count == 0) return alloc.alloc(dane.TlsaRecord, 0) catch DnsError.OutOfMemory;

    var list: std.ArrayList(dane.TlsaRecord) = .empty;
    errdefer {
        for (list.items) |r| alloc.free(r.data);
        list.deinit(alloc);
    }

    var i: c_int = 0;
    while (i < @as(c_int, @intCast(answer_count))) : (i += 1) {
        var rr: c.ns_rr = undefined;
        if (c.ns_parserr(&msg, c.ns_s_an, i, &rr) < 0) continue;
        if (c.ns_rr_type(rr) != T_TLSA) continue;

        const rdata: [*]const u8 = @ptrCast(c.ns_rr_rdata(rr));
        const rdlen: usize = @intCast(c.ns_rr_rdlen(rr));
        // Wire format: usage(1) + selector(1) + matching_type(1) + data(...)
        if (rdlen < 4) continue;
        const data_len = rdlen - 3;
        // Sanity bound: TLSA association data is a hash or cert; never huge.
        if (data_len > 8192) continue;

        vprint("mcp-bridge: [dns]   usage={d} selector={d} mtype={d} dataLen={d}\n", .{
            rdata[0], rdata[1], rdata[2], data_len,
        });

        const data_copy = alloc.dupe(u8, rdata[3..rdlen]) catch return DnsError.OutOfMemory;
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

    return list.toOwnedSlice(alloc) catch DnsError.OutOfMemory;
}

pub fn freeTlsaRecords(alloc: std.mem.Allocator, records: []dane.TlsaRecord) void {
    for (records) |r| alloc.free(r.data);
    alloc.free(records);
}
