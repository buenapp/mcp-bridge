# mcp-bridge agent notes

## Toolchain (PINNED)
- Build with Zig 0.15.2. On freebsd-dev1 it is the `zig015-0.15.2` pkg,
  installed as `/usr/local/bin/zig` (verify: `zig version` → 0.15.2). The
  `zig0152`/`zig016` symlinks into `/opt/zig-x86_64-freebsd-*` dangle —
  that /opt layout does not exist on this host.
- Zig 0.16.0 std APIs are incompatible with these sources (std.fs →
  std.Io with Io instances, std.posix socket fns removed,
  std.heap.DebugAllocator rename, etc.). Do NOT "fix" the sources for 0.16
  — the deliberate 0.16 port is a separate tracked effort.
  - Tests: `zig build test`
  - Release builds: `zig build -Dtarget=x86_64-{freebsd,windows-gnu,linux-gnu} -Doptimize=ReleaseSafe`
- Linux test binary cross-build (for the VMs): see git log / Heliofane
  McpBridge notes.
- Multi-process live test for the OAuth lockfile coordination (issue #3):
  build the native binary first (`zig build -Dtarget=x86_64-freebsd`),
  then `python3 tests/live_oauth_lock.py` (needs openssl + curl; spins a
  local HTTPS mock AS with a throwaway CA via SSL_CERT_FILE and races two
  bridge processes on a shared token cache).
- Local born integration regression: after the native build run
  `python3 tests/live_born.py --timeout 60` (optional first argument: binary).
  It uses only standard Python, ephemeral local sockets and subprocess pipes:
  53 assertions covering JSON, fragmented/chunked SSE, UTF-8 and typed IDs,
  concurrent responses, 4 MiB backpressure, refusal/truncated peers,
  bounded retries, GET resume and session deletion.

## Architecture (post issue #7 rework; event port lives in born since PR #9)
- Single event loop over born (`@import("born")`, pinned in
  build.zig.zon; kqueue FreeBSD / epoll Linux / IOCP Windows). No socket
  I/O threads, no timers/select/poll; inherited Windows stdio uses the
  relay threads described below.
- Plain TCP/overlapped socket ownership lives in `born.socket.PlainNb`.
  src/posix.zig and src/nb_win.zig alias its types; TLS, DANE, and logging
  remain in mcp-bridge.
- src/httpc.zig = event-driven HTTP conn state machine; src/nb_posix.zig
  (+ nb_win.zig) = non-blocking stream union; src/syncreq.zig = OAuth
  one-shots on a private event port.
- Remote stdio forward (issue #15, src/stdiofwd.zig + fwd* in main.zig):
  stdio+tcp (POSIX only) and stdio+ssh (also Windows via child-pipe relay
  threads). Gotchas learned live: never double-close the shared tcp fd
  (rd_fd == wr_fd); disown child pipe Files (c.stdin/c.stdout = null)
  before Child.kill() or cleanupStreams BADF-panics.
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
- Born associates Windows sockets during `startConnectInto`; do not repeat
  IOCP association in the HTTP layer. POSIX still registers read interest.
- Schannel must retain its native context across incomplete TLS records,
  flush final handshake tokens, and acknowledge plaintext only after the
  entire encrypted record completes. Partial writes must post the remainder,
  not wait without an outstanding operation.
- Focused Windows regressions (with sibling Born checkout):
  `zig test -target x86_64-windows-gnu -O ReleaseSafe --dep born -Mroot=src/schannel.zig -target x86_64-windows-gnu -O ReleaseSafe -Mborn=../Born/src/root.zig -lws2_32 -lsecur32 -lcrypt32 -ldnsapi -lkernel32 -lshell32 --test-no-exec -femit-bin=/tmp/mcp-schannel-tests.exe`
  Run the resulting executable on Windows; cross-compilation alone does not
  verify the native Schannel context-fragmentation test.
