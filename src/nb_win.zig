// Windows non-blocking stream layer for the event core (issue #7):
// overlapped WSA sockets on IOCP + the SChannel state machine (TlsNb lives
// in schannel.zig, re-exported here).
//
// Completion model: all socket I/O is overlapped. The conn posts ops via
// readNb/writeNb/startConnect; the IOCP port delivers completions; the
// conn classifies them by OVERLAPPED address via absorbCompletion() (the
// OVERLAPPED structs live in the conn-owned stream — heap-stable), which
// flips the ready state the conn's drive() logic then consumes.
//
// Teardown: cancelAndClose() (CancelIoEx + closesocket) aborts in-flight
// ops; their completions still arrive — the core reaps a conn only once
// pendingOps() == 0, so OVERLAPPED memory never outlives its ops.
//
// stdio is NOT here: IDE-spawned anonymous pipes can't do overlapped I/O
// (verified empirically), so stdin/stdout use libuv-style relay threads
// posting to the loop's IOCP (see main.zig).

const std = @import("std");
const windows = std.os.windows;
const win = @import("win.zig");
const platform = @import("platform.zig");
const evport = @import("born");
const schannel = @import("schannel.zig");

pub const TlsNb = schannel.TlsNb;
pub const Fd = win.SOCKET;

/// Same outcome shapes as the POSIX nb layer.
pub const NbRead = evport.socket.NbRead;
pub const NbWrite = evport.socket.NbWrite;

pub const Drive = union(enum) {
    done,
    want_read,
    want_write,
};

pub const IoError = evport.socket.IoError || error{TlsError};

// Which overlapped op a completion belongs to.
pub const CompletionKind = evport.socket.CompletionKind;
pub const PlainNb = evport.socket.PlainNb;

test "Windows stream shares Born socket outcome types with Schannel" {
    try std.testing.expect(NbRead == evport.socket.NbRead);
    try std.testing.expect(NbWrite == evport.socket.NbWrite);
    try std.testing.expect(CompletionKind == evport.socket.CompletionKind);
    try std.testing.expect(@FieldType(TlsNb, "plain") == PlainNb);
    std.testing.refAllDecls(Stream);
    std.testing.refAllDecls(TlsNb);
}

/// The platform stream union: plain TCP or SChannel TLS over one socket.
pub const Stream = union(enum) {
    plain: PlainNb,
    tls: TlsNb,

    pub fn fd(self: *const Stream) win.SOCKET {
        return switch (self.*) {
            .plain => |*s| s.sock,
            .tls => |*s| s.plain.sock,
        };
    }

    pub fn startConnectInto(self: *Stream, alloc: std.mem.Allocator, host: []const u8, port: u16, evp: *evport.EvPort, key: ?*anyopaque) IoError!void {
        self.* = .{ .plain = .{} };
        return self.plain.startConnectInto(alloc, host, port, evp, key);
    }

    pub fn connectDone(self: *Stream) IoError!void {
        return switch (self.*) {
            .plain => |*s| s.connectDone(),
            .tls => unreachable,
        };
    }

    /// Replace the plain variant with a TLS client on the same socket.
    /// No ops are in flight at this point (connect just completed), so the
    /// move is safe.
    pub fn swapToTls(self: *Stream, alloc: std.mem.Allocator, host: []const u8) schannel.TlsError!void {
        std.debug.assert(self.pendingOps() == 0);
        var tls = try TlsNb.initFromPlain(alloc, .{}, host);
        tls.plain = switch (self.*) {
            .plain => |*s| s.*,
            .tls => unreachable,
        };
        self.* = .{ .tls = tls };
    }

    pub fn handshakeDrive(self: *Stream) schannel.TlsError!Drive {
        return switch (self.*) {
            .plain => .done,
            .tls => |*s| s.handshakeDrive(),
        };
    }

    /// DANE/PKI verify hook after a completed TLS handshake (synchronous;
    /// runs on the loop thread at connection setup).
    pub fn verifyPeer(self: *Stream, v: *platform.Verifier) bool {
        return switch (self.*) {
            .plain => true,
            .tls => |*s| s.verifyPeer(v),
        };
    }

    pub fn readNb(self: *Stream, out: []u8) IoError!NbRead {
        return switch (self.*) {
            .plain => |*s| s.readNb(out),
            .tls => |*s| s.readNb(out) catch |err| switch (err) {
                error.OutOfMemory => IoError.OutOfMemory,
                else => IoError.TlsError,
            },
        };
    }

    pub fn writeNb(self: *Stream, data: []const u8) IoError!NbWrite {
        return switch (self.*) {
            .plain => |*s| s.writeNb(data),
            .tls => |*s| s.writeNb(data) catch |err| switch (err) {
                error.OutOfMemory => IoError.OutOfMemory,
                else => IoError.TlsError,
            },
        };
    }

    /// Route a completion into the owning sub-stream.
    pub fn absorbCompletion(self: *Stream, ov: ?*windows.OVERLAPPED, bytes: usize, err: ?usize) CompletionKind {
        return switch (self.*) {
            .plain => |*s| s.absorbCompletion(ov, bytes, err),
            .tls => |*s| s.plain.absorbCompletion(ov, bytes, err),
        };
    }

    pub fn pendingOps(self: *const Stream) usize {
        return switch (self.*) {
            .plain => |*s| s.pendingOps(),
            .tls => |*s| s.plain.pendingOps(),
        };
    }

    /// Best-effort TLS close_notify (plain: no-op).
    pub fn closeNotify(self: *Stream) void {
        switch (self.*) {
            .plain => {},
            .tls => |*s| s.closeNotify(),
        }
    }

    /// Cancel in-flight ops + close the socket + free TLS state.
    pub fn deinit(self: *Stream) void {
        switch (self.*) {
            .plain => |*s| s.deinit(),
            .tls => |*s| s.deinit(),
        }
    }
};
