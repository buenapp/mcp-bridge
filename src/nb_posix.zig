// POSIX non-blocking stream union for the event core (issue #7): plain TCP
// and OpenSSL TLS over one fd, with a uniform surface for httpc.zig.
// TLS wraps the socket after the TCP connect completes (stream.swapToTls).
//
// Ownership: the Stream owns its fd; deinit closes it (TLS variant after
// freeing OpenSSL state). The event core calls deinit at the reap point.

const std = @import("std");
const posix = @import("posix.zig");
const tls_openssl = @import("tls_openssl.zig");
const platform = @import("platform.zig");
const openssl = @import("openssl.zig");
const ulog = @import("ulog.zig");

pub const PlainNb = posix.PlainNb;
pub const TlsNb = tls_openssl.TlsNb;
pub const NbRead = posix.NbRead;
pub const NbWrite = posix.NbWrite;
pub const Drive = tls_openssl.Drive;
pub const Fd = std.posix.fd_t;

pub const IoError = error{
    SocketError,
    TlsError,
};

pub const Stream = union(enum) {
    plain: PlainNb,
    tls: TlsNb,

    pub fn fd(self: *const Stream) std.posix.fd_t {
        return switch (self.*) {
            .plain => |*s| s.sock,
            .tls => |*s| s.sock,
        };
    }

    /// Start a non-blocking TCP connect (all conns begin as .plain),
    /// constructed in place at `dest` (in-place matches the IOCP backend —
    /// overlapped ops register struct addresses). evp/key are the Windows
    /// association params — unused here.
    pub fn startConnectInto(self: *Stream, alloc: std.mem.Allocator, host: []const u8, port: u16, evp: anytype, key: ?*anyopaque) PlainNb.Error!void {
        _ = evp;
        _ = key;
        ulog.vprint("mcp-bridge: [tls] resolving {s}:{d}\n", .{ host, port });
        self.* = .{ .plain = try PlainNb.startConnect(alloc, host, port) };
    }

    /// Confirm the connect after the first write event (SO_ERROR).
    pub fn connectDone(self: *Stream) PlainNb.Error!void {
        return switch (self.*) {
            .plain => |*s| s.connectDone(),
            .tls => unreachable, // connect only completes in the plain phase
        };
    }

    /// Replace the plain variant with a TLS client on the same fd.
    pub fn swapToTls(self: *Stream, alloc: std.mem.Allocator, host: []const u8) tls_openssl.TlsError!void {
        _ = alloc;
        const sock = switch (self.*) {
            .plain => |*s| s.sock,
            .tls => unreachable,
        };
        self.* = .{ .tls = try TlsNb.initOnSocket(sock, host) };
    }

    /// Drive the TLS handshake; plain streams are done by definition.
    pub fn handshakeDrive(self: *Stream) tls_openssl.TlsError!Drive {
        return switch (self.*) {
            .plain => .done,
            .tls => |*s| s.handshakeDrive(),
        };
    }

    /// DANE/PKI verify hook after a completed TLS handshake. Synchronous
    /// (TLSA lookup is cached in the Verifier); runs on the loop thread at
    /// connection setup, never on the data path.
    pub fn verifyPeer(self: *Stream, v: *platform.Verifier) bool {
        return switch (self.*) {
            .plain => true,
            .tls => |*s| {
                const ssl = s.ssl orelse return false;
                ulog.vprint("mcp-bridge: [tls] verifying certificate\n", .{});
                if (openssl.c.SSL_get0_peer_certificate(ssl) == null) return false;
                const ok = platform.Verifier.verifyOpaque(v, ssl);
                // CI smoke tests grep this line (see ci.yml) — keep the string.
                if (ok) ulog.vprint("mcp-bridge: [tls] certificate accepted\n", .{});
                return ok;
            },
        };
    }

    pub fn readNb(self: *Stream, out: []u8) IoError!NbRead {
        return switch (self.*) {
            .plain => |*s| s.readNb(out) catch |err| switch (err) {
                error.SocketError => IoError.SocketError,
                else => unreachable,
            },
            .tls => |*s| s.readNb(out) catch |err| switch (err) {
                error.TlsError => IoError.TlsError,
                else => unreachable,
            },
        };
    }

    pub fn writeNb(self: *Stream, data: []const u8) IoError!NbWrite {
        return switch (self.*) {
            .plain => |*s| s.writeNb(data) catch |err| switch (err) {
                error.SocketError => IoError.SocketError,
                else => unreachable,
            },
            .tls => |*s| s.writeNb(data) catch |err| switch (err) {
                error.TlsError => IoError.TlsError,
                else => unreachable,
            },
        };
    }

    /// Best-effort TLS close_notify (plain: no-op).
    pub fn closeNotify(self: *Stream) void {
        switch (self.*) {
            .plain => {},
            .tls => |*s| s.closeNotify(),
        }
    }

    /// In-flight op count — always zero on POSIX (no deferred reap drain).
    pub fn pendingOps(self: *const Stream) usize {
        _ = self;
        return 0;
    }

    /// Frees TLS state (if any) and closes the fd.
    pub fn deinit(self: *Stream) void {
        switch (self.*) {
            .plain => |*s| s.deinit(),
            .tls => |*s| s.deinit(),
        }
    }
};
