# mcp-bridge agent notes

## Toolchain (PINNED)
- Build with `zig0152` (Zig 0.15.2, /opt/zig-x86_64-freebsd-0.15.2). The
  system `zig` is 0.16.0 (upgraded 2026-08-10) whose std APIs are
  incompatible (std.fs → std.Io with Io instances, std.posix socket fns
  removed, std.heap.DebugAllocator rename, etc.). Do NOT "fix" the sources
  for 0.16 — the deliberate 0.16 port is a separate tracked effort.
  - Tests: `zig0152 build test`
  - Release builds: `zig0152 build -Dtarget=x86_64-{freebsd,windows-gnu,linux-gnu} -Doptimize=ReleaseSafe`
- Linux test binary cross-build (for the VMs): see git log / Heliofane
  McpBridge notes.
- Multi-process live test for the OAuth lockfile coordination (issue #3):
  build the native binary first (`zig0152 build -Dtarget=x86_64-freebsd`),
  then `python3 tests/live_oauth_lock.py` (needs openssl + curl; spins a
  local HTTPS mock AS with a throwaway CA via SSL_CERT_FILE and races two
  bridge processes on a shared token cache).

## Architecture (post issue #7 rework)
- Single event loop over src/evport.zig (kqueue FreeBSD / epoll Linux /
  IOCP Windows). No I/O threads, no timers/select/poll.
- src/httpc.zig = event-driven HTTP conn state machine; src/nb_posix.zig
  (+ nb_win.zig) = non-blocking stream union; src/syncreq.zig = OAuth
  one-shots on a private event port.
- Conn lifecycle: close() marks; end-of-batch reap purges staged
  changelist entries then close(2) (kqueue) — never stage registrations
  for fds about to close.
- FreeBSD kqueue: struct kevent is 64 BYTES (ext[4]) — a 32-byte extern
  declaration corrupts multi-entry changelists.

## Windows notes
- Inherited anonymous-pipe stdin CANNOT do overlapped I/O (empirically
  verified on win11-dev: CreateIoCompletionPort EINVAL, ReOpenFile
  PIPE_BUSY all variants). Stdio uses libuv-style relay threads; sockets
  are true overlapped IOCP.
- win11-dev (192.168.1.195) via vnc MCP: vnc_run_command works; serve
  files over HTTP from 192.168.1.233 (the MCP server's fs view differs).
