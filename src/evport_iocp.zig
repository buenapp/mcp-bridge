// Windows event port: IOCP backend (overlapped stdin ReadFile, WSA
// overlapped socket I/O). Implemented in the rework phase after epoll
// (issue #7 phase order: kqueue core -> epoll -> IOCP). Referencing this
// backend is a compile error until then — cross-builds must NOT go green
// before the real implementation exists.

comptime {
    @compileError("evport_iocp.zig is not implemented yet (issue #7: IOCP phase)");
}
