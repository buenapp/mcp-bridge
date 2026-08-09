// Linux event port: epoll + eventfd backend.
// Implemented in the rework phase after the FreeBSD kqueue core lands
// (issue #7 phase order: kqueue core -> epoll -> IOCP). Referencing this
// backend is a compile error until then — cross-builds must NOT go green
// before the real implementation exists.

comptime {
    @compileError("evport_epoll.zig is not implemented yet (issue #7: epoll phase)");
}
