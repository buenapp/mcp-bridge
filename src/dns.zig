// TLSA record lookup via Windows DnsQuery API (dnsapi.dll).
// No DNSSEC validation, per project requirement.

const std = @import("std");
const win = @import("win.zig");
const dane = @import("dane.zig");

const ulog = @import("ulog.zig");

fn vprint(comptime fmt: []const u8, args: anytype) void {
    ulog.vprint(fmt, args);
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

    var results: ?*win.DNS_RECORD = null;
    const status = win.DnsQuery_A(
        qname.ptr,
        win.DNS_TYPE_TLSA,
        win.DNS_QUERY_STANDARD,
        null,
        &results,
        null,
    );
    defer if (results != null) win.DnsRecordListFree(results, .FreeRecordList);

    vprint("mcp-bridge: [dns] status={d} results={*}\n", .{ status, results });

    // No records published (NXDOMAIN / NODATA) is NOT an error for DANE.
    if (status != 0 and results == null) {
        switch (status) {
            win.DNS_R_ERROR_NAME_DOES_NOT_EXIST,
            win.DNS_INFO_NO_RECORDS,
            => return alloc.alloc(dane.TlsaRecord, 0) catch DnsError.OutOfMemory,
            else => return DnsError.LookupFailed,
        }
    }

    var list: std.ArrayList(dane.TlsaRecord) = .empty;
    errdefer {
        for (list.items) |r| alloc.free(r.data);
        list.deinit(alloc);
    }

    var rec = results;
    while (rec) |r| : (rec = r.pNext) {
        vprint("mcp-bridge: [dns] record wType={d} wDataLength={d}\n", .{ r.wType, r.wDataLength });
        if (r.wType != win.DNS_TYPE_TLSA) continue;
        const tlsa = &r.Data.TLSA;
        const data_len: usize = tlsa.bCertificateAssociationDataLength;
        // Sanity bound: TLSA association data is a hash or cert; never huge.
        if (data_len == 0 or data_len > 8192) continue;
        // Data is stored INLINE after the 3-byte pad (no pointer field).
        const data_ptr: [*]const u8 = @ptrCast(&tlsa.bCertificateAssociationData);
        vprint("mcp-bridge: [dns]   usage={d} selector={d} mtype={d} dataLen={d}\n", .{
            tlsa.bCertUsage, tlsa.bSelector, tlsa.bMatchingType, data_len,
        });

        const data_copy = alloc.dupe(u8, data_ptr[0..data_len]) catch return DnsError.OutOfMemory;
        list.append(alloc, .{
            .usage = tlsa.bCertUsage,
            .selector = tlsa.bSelector,
            .matching_type = tlsa.bMatchingType,
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
