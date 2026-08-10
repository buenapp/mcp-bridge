// Windows non-blocking stream union for the event core (issue #7):
// overlapped WSA sockets + the SChannel encrypt/decrypt state machine.
// Implemented in the IOCP phase; referencing this module is a compile
// error until then — cross-builds must NOT go green early.

comptime {
    @compileError("nb_win.zig is not implemented yet (issue #7: IOCP phase)");
}
