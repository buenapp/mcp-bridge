// Platform seam: comptime selection between the Windows backend
// (SChannel/crypt32/dnsapi) and the POSIX backend (OpenSSL/res_query).
//
// The `@import`s behind a comptime-known `builtin.os.tag` condition are
// never analyzed on the non-matching target, so POSIX files don't exist as
// far as the Windows build is concerned (and vice versa).
//
// The event-driven core uses evport.zig (kqueue/epoll/IOCP) and the
// non-blocking stream layer (nb_posix.zig / nb_win.zig); what remains
// here is the certificate Verifier and verbose propagation.

const std = @import("std");
const builtin = @import("builtin");
const dane = @import("dane.zig");

pub const is_windows = builtin.os.tag == .windows;

const tls_impl = if (is_windows) @import("schannel.zig") else @import("tls_openssl.zig");
const dns_impl = if (is_windows) @import("dns.zig") else @import("dns_posix.zig");
const verifier_impl = if (is_windows) @import("verifier_win.zig") else @import("verifier_posix.zig");

pub const Verifier = verifier_impl.Verifier;

/// Propagate the --verbose flag into the platform leaf modules.
pub fn setVerbose(v: bool) void {
    tls_impl.verbose = v;
    dns_impl.verbose = v;
    dane.verbose = v;
}
