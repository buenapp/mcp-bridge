// Event port seam: comptime selection of the per-platform event
// notification backend. Same pattern as platform.zig — the @imports behind
// a comptime-known builtin.os.tag are never analyzed on other targets.
//
//   FreeBSD: kqueue (evport_kqueue.zig)
//   Linux:   epoll + eventfd (evport_epoll.zig)
//   Windows: IOCP (evport_iocp.zig)
//
// Common contract:
//   - ONE syscall per wait() carries staged registrations + event harvest.
//   - Sockets: read interest is persistent edge-triggered (handlers fully
//     drain); write interest is one-shot, re-armed on demand.
//   - fds are never deleted while closed/recycled: the core defers close()
//     to the reap point right after wait() flushes the staged changelist
//     (see main.zig). unmonitorWrite/unmonitor are for fds that STAY OPEN.
//   - wake() posts a loop wakeup from any thread (pipe/eventfd/IOCP post);
//     delivered as a single Event{ .wake = true }.

const std = @import("std");
const builtin = @import("builtin");

const impl = switch (builtin.os.tag) {
    .freebsd => @import("evport_kqueue.zig"),
    .linux => @import("evport_epoll.zig"),
    .windows => @import("evport_iocp.zig"),
    else => @compileError("no event port backend for this OS"),
};

pub const EvPort = impl.EvPort;
pub const Event = impl.Event;
