// Certificate verification policy (POSIX): DANE TLSA first (cached lookup),
// then system trust-store PKI fallback with hostname verification when no
// TLSA records are published.
//
// Same policy as verifier_win.zig; chain extraction and PKI primitives are
// OpenSSL (openssl.zig).

const std = @import("std");
const dane = @import("dane.zig");
const dns = @import("dns_posix.zig");
const openssl = @import("openssl.zig");

const log = std.log.scoped(.bridge);

pub const Verifier = struct {
    alloc: std.mem.Allocator,
    host: []const u8,
    port: u16,
    verbose: bool,
    tlsa: ?[]dane.TlsaRecord = null,

    pub fn init(alloc: std.mem.Allocator, host: []const u8, port: u16, verbose: bool) !Verifier {
        return .{
            .alloc = alloc,
            .host = host,
            .port = port,
            .verbose = verbose,
        };
    }

    pub fn verifyOpaque(ctx_ptr: *anyopaque, ssl: *openssl.c.SSL) bool {
        const self: *Verifier = @ptrCast(@alignCast(ctx_ptr));
        return self.verify(ssl) catch |err| {
            log.err("certificate verification error: {s}", .{@errorName(err)});
            return false;
        };
    }

    fn verify(self: *Verifier, ssl: *openssl.c.SSL) !bool {
        if (self.tlsa == null) {
            self.tlsa = dns.lookupTlsa(self.alloc, self.host, self.port) catch |err| {
                // DNS lookup ERROR (not "no records") → fail closed.
                log.err("TLSA lookup failed for {s}: {s}", .{ self.host, @errorName(err) });
                if (self.verbose) std.debug.print("mcp-bridge: TLSA lookup error, refusing connection\n", .{});
                return err;
            };
            if (self.verbose) {
                std.debug.print("mcp-bridge: {d} TLSA record(s) for _{d}._tcp.{s}\n", .{ self.tlsa.?.len, self.port, self.host });
            }
        }
        const records = self.tlsa.?;

        const chain_der = try openssl.getPeerChainDer(self.alloc, ssl);
        defer openssl.freeChainDer(self.alloc, chain_der);
        if (self.verbose) {
            std.debug.print("mcp-bridge: peer chain has {d} cert(s)\n", .{chain_der.len});
            for (chain_der, 0..) |der, idx| {
                std.debug.print("mcp-bridge:   cert[{d}] {d} bytes\n", .{ idx, der.len });
            }
        }

        if (records.len > 0) {
            const result = dane.verifyTlsaRecords(records, chain_der, openssl.spkiFromCertDer, self.alloc);
            if (self.verbose) {
                std.debug.print("mcp-bridge: DANE result: {s}\n", .{@tagName(result)});
            }
            return result == .success;
        }

        // No TLSA published → normal PKI against the system trust store.
        if (self.verbose) std.debug.print("mcp-bridge: no TLSA, PKI fallback via system trust store\n", .{});
        return openssl.verifyPkiHost(self.alloc, self.host, chain_der);
    }
};
