// Certificate verification policy (Windows): DANE TLSA first (cached
// lookup), then Windows root-store PKI fallback when no TLSA records are
// published.
//
// Verbatim relocation of the Verifier struct from main.zig (v0.1.0); the
// only additions are init/deinit helpers so main.zig stays portable.

const std = @import("std");
const win = @import("win.zig");
const dane = @import("dane.zig");
const dane_win = @import("dane_win.zig");
const dns = @import("dns.zig");

const log = std.log.scoped(.bridge);
const ulog = @import("ulog.zig");

pub const Verifier = struct {
    alloc: std.mem.Allocator,
    host: []const u8,
    host_w: [:0]const u16,
    port: u16,
    tlsa: ?[]dane.TlsaRecord = null,

    pub fn init(alloc: std.mem.Allocator, host: []const u8, port: u16) !Verifier {
        const host_w = win.utf16Z(alloc, host) catch return error.Utf16;
        return .{
            .alloc = alloc,
            .host = host,
            .host_w = host_w,
            .port = port,
        };
    }

    pub fn verifyOpaque(ctx_ptr: *anyopaque, leaf: *win.CERT_CONTEXT) bool {
        const self: *Verifier = @ptrCast(@alignCast(ctx_ptr));
        return self.verify(leaf) catch |err| {
            log.err("certificate verification error: {s}", .{@errorName(err)});
            return false;
        };
    }

    fn verify(self: *Verifier, leaf: *win.CERT_CONTEXT) !bool {
        if (self.tlsa == null) {
            self.tlsa = dns.lookupTlsa(self.alloc, self.host, self.port) catch |err| {
                // DNS lookup ERROR (not "no records") → fail closed.
                log.err("TLSA lookup failed for {s}: {s}", .{ self.host, @errorName(err) });
                ulog.vprint("mcp-bridge: TLSA lookup error, refusing connection\n", .{});
                return err;
            };
            ulog.vprint("mcp-bridge: {d} TLSA record(s) for _{d}._tcp.{s}\n", .{ self.tlsa.?.len, self.port, self.host });
        }
        const records = self.tlsa.?;

        const built = try dane_win.buildChain(leaf);
        defer dane_win.freeChain(built.chain, built.certs);

        if (records.len > 0) {
            const result = dane_win.verifyChainDane(self.alloc, records, built.certs);
            // CI smoke tests grep this line (see ci.yml) — keep the string.
            ulog.vprint("mcp-bridge: DANE result: {s}\n", .{@tagName(result)});
            return result == .success;
        }

        // No TLSA published → normal PKI against Windows root store.
        ulog.vprint("mcp-bridge: no TLSA, PKI fallback via Windows root store\n", .{});
        return dane_win.verifyChainPki(built.chain, self.host_w);
    }
};
