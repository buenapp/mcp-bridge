// Platform seam: comptime selection between the Windows backend
// (SChannel/crypt32/dnsapi) and the POSIX backend (OpenSSL/res_query).
//
// The `@import`s behind a comptime-known `builtin.os.tag` condition are
// never analyzed on the non-matching target, so POSIX files don't exist as
// far as the Windows build is concerned (and vice versa). Each platform
// pair exposes an identical public surface so main.zig stays portable.

const std = @import("std");
const builtin = @import("builtin");
const dane = @import("dane.zig");

pub const is_windows = builtin.os.tag == .windows;

const tls_impl = if (is_windows) @import("schannel.zig") else @import("tls_openssl.zig");
const plain_impl = if (is_windows) @import("plain.zig") else @import("posix.zig");
const dns_impl = if (is_windows) @import("dns.zig") else @import("dns_posix.zig");
const verifier_impl = if (is_windows) @import("verifier_win.zig") else @import("verifier_posix.zig");
const posix_impl = if (is_windows) struct {} else @import("posix.zig");
const win_impl = if (is_windows) @import("win.zig") else struct {};

pub const TlsStream = tls_impl.TlsStream;
pub const PlainStream = plain_impl.PlainStream;
pub const Verifier = verifier_impl.Verifier;

/// TCP + TLS connect with DANE/PKI certificate verification.
pub fn connectTls(
    alloc: std.mem.Allocator,
    host: []const u8,
    port: u16,
    verifier: *Verifier,
) tls_impl.TlsError!TlsStream {
    return tls_impl.connect(alloc, host, port, verifier, Verifier.verifyOpaque);
}

/// Propagate the --verbose flag into the platform leaf modules.
pub fn setVerbose(v: bool) void {
    tls_impl.verbose = v;
    dns_impl.verbose = v;
    dane.verbose = v;
}

// ---------------------------------------------------------------- stdio ----

/// Read from stdin. Returns 0 on EOF.
pub fn readStdin(buf: []u8) !usize {
    if (is_windows) {
        const h = win_impl.GetStdHandle(win_impl.STD_INPUT_HANDLE) orelse return error.NoStdin;
        var nread: win_impl.DWORD = 0;
        const ok = win_impl.ReadFile(h, buf.ptr, @intCast(buf.len), &nread, null);
        if (ok == 0) return 0; // read error → treat as EOF (matches v0.1.0 behavior)
        return nread;
    }
    return posix_impl.readStdin(buf);
}

/// Write all bytes to stdout.
pub fn writeStdoutAll(bytes: []const u8) !void {
    if (is_windows) {
        const stdout_h = win_impl.GetStdHandle(win_impl.STD_OUTPUT_HANDLE) orelse return error.NoStdout;
        var off: usize = 0;
        while (off < bytes.len) {
            var written: win_impl.DWORD = 0;
            if (win_impl.WriteFile(stdout_h, bytes.ptr + off, @intCast(bytes.len - off), &written, null) == 0)
                return error.WriteFailed;
            off += written;
        }
        return;
    }
    return posix_impl.writeStdoutAll(bytes);
}
