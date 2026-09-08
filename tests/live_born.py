#!/usr/bin/env python3
"""Local-only bridge integration: python3 tests/live_born.py [binary] --timeout 60.

Uses actual subprocess pipes and ephemeral loopback HTTP/SSE peers. Blocking
socket threads and Events coordinate the adversarial cases; only the supervisor
has a watchdog deadline. No credentials, external services, or build step needed.
"""

import argparse
import collections
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import traceback
from http.server import BaseHTTPRequestHandler


SESSION = "born-local-session"
PROTOCOL = "2025-03-26"
LARGE = "0123456789abcdef" * (256 * 1024)
TOOL = {
    "name": "echo",
    "description": "Local test echo only",
    "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}},
}


def encode(obj):
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def request(rid, method, params=None):
    obj = {"jsonrpc": "2.0", "id": rid, "method": method}
    if params is not None:
        obj["params"] = params
    return obj


def result(rid, value):
    return {"jsonrpc": "2.0", "id": rid, "result": value}


def text_result(rid, text):
    return result(rid, {"content": [{"type": "text", "text": text}], "isError": False})


def transport_error(rid, reason):
    return {"jsonrpc": "2.0", "id": rid,
            "error": {"code": -32603, "message": f"bridge transport error: {reason}"}}


def notification(method, params=None):
    obj = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        obj["params"] = params
    return obj


def event(obj, event_id=None):
    prefix = b"event: message\r\n"
    if event_id is not None:
        prefix += b"id: " + event_id.encode() + b"\r\n"
    return prefix + b"data: " + encode(obj) + b"\r\n\r\n"


class Checks:
    def __init__(self):
        self.count = 0

    def equal(self, actual, expected, label):
        if actual != expected:
            raise AssertionError(f"{label}: got {repr(actual)[:500]}, expected {repr(expected)[:500]}")
        self.count += 1


class Mock:
    def __init__(self):
        self.lock = threading.Lock()
        self.records = []
        self.errors = []
        self.connections = []
        self.threads = []
        self.attempts = collections.Counter()
        self.stopping = threading.Event()
        self.split_release = threading.Event()
        self.slow_seen = threading.Event()
        self.slow_release = threading.Event()
        self.large_sent = threading.Event()
        self.probe_seen = threading.Event()
        self.push_closed = [threading.Event(), threading.Event()]
        self.get_count = 0
        self.bridge = None
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(32)
        self.address = self.listener.getsockname()
        self.url = f"http://127.0.0.1:{self.address[1]}/mcp"
        self.accept_thread = threading.Thread(target=self.accept, daemon=True)
        self.accept_thread.start()

    def accept(self):
        while True:
            conn, address = self.listener.accept()
            if self.stopping.is_set():
                conn.close()
                return
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            with self.lock:
                number = len(self.connections)
                self.connections.append(conn)
                thread = threading.Thread(target=self.serve, args=(conn, address, number), daemon=True)
                self.threads.append(thread)
            thread.start()

    def serve(self, conn, address, number):
        mock = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def head(self, status=200, content_type="application/json", length=None, keep=False, extra=None):
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Connection", "keep-alive" if keep else "close")
                if length is not None:
                    self.send_header("Content-Length", str(length))
                for key, value in (extra or {}).items():
                    self.send_header(key, value)
                self.end_headers()
                self.close_connection = not keep

            def reply(self, obj=None, status=200, keep=False, extra=None):
                body = encode(obj) if obj is not None else b""
                self.head(status, length=len(body), keep=keep, extra=extra)
                self.wfile.write(body)

            def chunk(self, data):
                wire = f"{len(data):x};test=split\r\n".encode() + data + b"\r\n"
                for start in range(0, len(wire), 13):
                    self.wfile.write(wire[start:start + 13])

            def record(self, obj=None):
                with mock.lock:
                    mock.records.append((self.command, self.path, dict(self.headers.items()), obj, number))

            def do_GET(self):
                self.record()
                with mock.lock:
                    index = mock.get_count
                    mock.get_count += 1
                if index >= 2:
                    self.reply(status=405)
                    return
                self.head(content_type="text/event-stream", extra={"Transfer-Encoding": "chunked"})
                self.chunk(event(notification("notifications/message", {"data": f"push-{index + 1}"}), f"push-{index + 1}"))
                self.wfile.write(b"0\r\n\r\n")
                conn.shutdown(socket.SHUT_WR)
                if conn.recv(1) != b"":
                    raise AssertionError("GET stream unexpectedly received client bytes")
                mock.push_closed[index].set()

            def do_DELETE(self):
                self.record()
                self.reply(status=204)

            def do_POST(self):
                length = int(self.headers["Content-Length"])
                raw = self.rfile.read(length)
                if len(raw) != length:
                    raise AssertionError("incomplete request body")
                obj = json.loads(raw)
                self.record(obj)
                rid = obj.get("id")
                method = obj["method"]
                with mock.lock:
                    mock.attempts[rid] += 1
                    attempt = mock.attempts[rid]
                if method == "notifications/test-release":
                    mock.split_release.set()
                    self.reply(status=202)
                elif method == "notifications/initialized":
                    self.reply(status=202)
                elif method == "initialize":
                    self.reply(result(rid, {
                        "protocolVersion": PROTOCOL,
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "born-mock", "version": "1"},
                    }), extra={"Mcp-Session-Id": SESSION})
                elif method == "tools/list":
                    self.reply(result(rid, {"tools": [TOOL]}))
                elif method != "tools/call":
                    raise AssertionError(f"unexpected method {method}")
                elif rid == "77":
                    self.head(content_type="text/event-stream", extra={"Transfer-Encoding": "chunked"})
                    payload = event(text_result(rid, "split caf\u00e9 result"))
                    cut = payload.index(b"\xc3\xa9") + 1
                    self.chunk(b": ignored keepalive\r\n\r\n" + event(notification("notifications/progress", {
                        "progressToken": "split", "progress": 1,
                    })) + event(result(77, {"unrelated": True})) + payload[:cut])
                    mock.split_release.wait()
                    for start in range(cut, len(payload), 7):
                        self.chunk(payload[start:start + 7])
                elif rid == "slow":
                    mock.slow_seen.set()
                    mock.slow_release.wait()
                    self.reply(text_result(rid, "slow complete"))
                elif rid == "fast":
                    self.reply(text_result(rid, "fast complete"))
                elif rid == "large":
                    if obj["params"]["arguments"]["text"] != LARGE:
                        raise AssertionError("large stdin/HTTP request corrupted")
                    self.reply(text_result(rid, LARGE))
                    mock.large_sent.set()
                elif rid == "probe":
                    mock.probe_seen.set()
                    self.reply(text_result(rid, "read while stdout paused"))
                elif rid in ("prime-retry", "prime-exhaust"):
                    self.reply(text_result(rid, "keep-alive ready"), keep=True)
                elif rid == "retry" and attempt == 2:
                    self.reply(text_result(rid, "fresh connection recovered"))
                elif rid in ("retry", "exhaust", "peer-close"):
                    self.close_connection = True
                elif rid == "bad-head":
                    self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Length: 40\r\n")
                    self.close_connection = True
                elif rid == "bad-chunk":
                    self.head(extra={"Transfer-Encoding": "chunked"})
                    self.wfile.write(b"20\r\n{\"jsonrpc\":")
                elif rid == "sse-eof":
                    self.head(content_type="text/event-stream")
                    self.wfile.write(event(notification("notifications/message", {"data": "before EOF"})))
                elif rid == "http-error":
                    self.head(status=503, content_type="text/plain", length=11)
                    self.wfile.write(b"unavailable")
                elif rid == "until-close":
                    self.head()
                    self.wfile.write(encode(text_result(rid, "EOF delimited JSON")))
                else:
                    self.reply(text_result(rid, obj["params"]["arguments"]["text"]))

        try:
            with conn:
                Handler(conn, address, self)
        except Exception:
            message = traceback.format_exc()
            with self.lock:
                self.errors.append(message)
            print(message, file=sys.stderr, flush=True)
            if self.bridge is not None:
                self.bridge.kill()

    def close(self):
        if self.stopping.is_set():
            return
        self.stopping.set()
        self.split_release.set()
        self.slow_release.set()
        with socket.create_connection(self.address):
            pass
        self.accept_thread.join()
        self.listener.close()
        for thread in self.threads:
            thread.join()


class Client:
    def __init__(self, binary, url, home):
        env = dict(os.environ)
        for key in list(env):
            if "proxy" in key.lower() or key.startswith("MCP_"):
                del env[key]
        for key in ("HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME", "XDG_DATA_HOME"):
            env[key] = home
        self.proc = subprocess.Popen(
            [binary, url, "--transport", "http-only", "--header", "X-Born-Test: local-only"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env, cwd=home,
        )
        print(f"bridge-pid={self.proc.pid}", flush=True)
        self.stderr = bytearray()
        self.stderr_thread = threading.Thread(target=self.drain_stderr, daemon=True)
        self.stderr_thread.start()

    def drain_stderr(self):
        for chunk in iter(lambda: self.proc.stderr.read(4096), b""):
            self.stderr.extend(chunk)

    def send(self, obj):
        self.proc.stdin.write(encode(obj) + b"\n")
        self.proc.stdin.flush()

    def call(self, rid, text="local echo"):
        self.send(request(rid, "tools/call", {"name": "echo", "arguments": {"text": text}}))

    def receive(self):
        line = self.proc.stdout.readline()
        if not line:
            raise AssertionError("bridge stdout EOF before expected response: " + self.stderr.decode(errors="replace"))
        if not line.endswith(b"\n"):
            raise AssertionError("stdout response lacks newline")
        return json.loads(line)

    def close(self):
        if self.proc.returncode is None:
            self.proc.kill()
        self.proc.wait()
        print(f"bridge-exit={self.proc.pid}", flush=True)
        self.stderr_thread.join()
        self.proc.stdin.close()
        self.proc.stdout.close()
        self.proc.stderr.close()


def check_refusal(binary, checks):
    print("stage=refused-loopback-connection", flush=True)
    # Keep this port reserved but never listen. Closing an ephemeral listener
    # before connecting would race another process claiming the port.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reserved:
        reserved.bind(("127.0.0.1", 0))
        url = f"http://127.0.0.1:{reserved.getsockname()[1]}/mcp"
        with tempfile.TemporaryDirectory(prefix="mcp-born-refusal-") as home:
            client = Client(binary, url, home)
            try:
                client.send(request(91, "initialize", {
                    "protocolVersion": PROTOCOL, "capabilities": {},
                    "clientInfo": {"name": "live-born", "version": "1"},
                }))
                checks.equal(client.receive(), transport_error(91, "ConnectFailed"),
                             "refused initialize yields a correlated error")
                client.call("refused-call")
                checks.equal(client.receive(), transport_error("refused-call", "ConnectFailed"),
                             "bridge accepts another request after connection refusal")
                client.proc.stdin.close()
                checks.equal(client.proc.stdout.read(), b"", "refusal produces no duplicate responses")
                checks.equal(client.proc.wait(), 0, "refused peer still permits clean stdin EOF shutdown")
            finally:
                client.close()


def worker(binary):
    checks = Checks()
    check_refusal(binary, checks)
    print("stage=json-initialize-and-get-reconnect", flush=True)
    mock = Mock()
    client = None
    try:
        with tempfile.TemporaryDirectory(prefix="mcp-born-test-") as home:
            client = Client(binary, mock.url, home)
            mock.bridge = client.proc
            init = request(1, "initialize", {
                "protocolVersion": PROTOCOL, "capabilities": {},
                "clientInfo": {"name": "live-born", "version": "1"},
            })
            client.send(init)
            checks.equal(client.receive(), result(1, {
                "protocolVersion": PROTOCOL, "capabilities": {"tools": {}},
                "serverInfo": {"name": "born-mock", "version": "1"},
            }), "initialize JSON response")
            checks.equal(client.receive(), notification("notifications/message", {"data": "push-1"}), "standalone GET push")
            mock.push_closed[0].wait()
            client.send(notification("notifications/initialized"))
            client.send(request("list", "tools/list"))
            replies = [client.receive(), client.receive()]
            checks.equal(sum(obj == result("list", {"tools": [TOOL]}) for obj in replies), 1, "tools/list JSON response")
            checks.equal(sum(obj == notification("notifications/message", {"data": "push-2"}) for obj in replies), 1, "GET reconnect push")
            mock.push_closed[1].wait()
            client.call("json", "caf\u00e9 / quoted \"value\" / newline\nend")
            checks.equal(client.receive(), text_result("json", "caf\u00e9 / quoted \"value\" / newline\nend"), "tools/call JSON round trip")

            print("stage=split-sse-and-typed-ids", flush=True)
            client.call("77")
            checks.equal(client.receive(), notification("notifications/progress", {"progressToken": "split", "progress": 1}), "split SSE progress before response")
            checks.equal(client.receive(), result(77, {"unrelated": True}), "numeric id must not match string id")
            client.send(notification("notifications/test-release"))
            checks.equal(client.receive(), text_result("77", "split caf\u00e9 result"), "split UTF-8 SSE matching response")

            print("stage=concurrent-out-of-order", flush=True)
            client.call("slow")
            mock.slow_seen.wait()
            client.call("fast")
            checks.equal(client.receive(), text_result("fast", "fast complete"), "concurrent fast response overtakes blocked slow request")
            mock.slow_release.set()
            checks.equal(client.receive(), text_result("slow", "slow complete"), "slow response remains correlated")

            print("stage=large-body-and-stdout-backpressure", flush=True)
            # Do not read stdout until the independent probe reaches the mock.
            # The body greatly exceeds pipe capacity, so the bridge must keep
            # reading stdin/upstream sockets even while its stdout is blocked.
            client.call("large", LARGE)
            mock.large_sent.wait()
            client.call("probe")
            mock.probe_seen.wait()
            replies = [client.receive(), client.receive()]
            checks.equal(sum(obj == text_result("large", LARGE) for obj in replies), 1, "4 MiB stdin/socket/stdout body is intact")
            checks.equal(sum(obj == text_result("probe", "read while stdout paused") for obj in replies), 1, "upstream progresses while stdout reader is paused")

            print("stage=keepalive-retries-and-truncated-peers", flush=True)
            client.call("prime-retry")
            checks.equal(client.receive(), text_result("prime-retry", "keep-alive ready"), "prime reusable connection")
            client.call("retry")
            checks.equal(client.receive(), text_result("retry", "fresh connection recovered"), "stale reused connection retries on fresh socket")
            client.call("prime-exhaust")
            checks.equal(client.receive(), text_result("prime-exhaust", "keep-alive ready"), "prime retry exhaustion")
            for rid, reason in (("exhaust", "MalformedResponse"), ("peer-close", "MalformedResponse"),
                                ("bad-head", "MalformedResponse"), ("bad-chunk", "MalformedResponse"),
                                ("sse-eof", "SseEndedWithoutResponse"), ("http-error", "HTTP 503")):
                client.call(rid)
                if rid == "sse-eof":
                    checks.equal(client.receive(), notification("notifications/message", {"data": "before EOF"}), "SSE notification survives unmatched EOF")
                checks.equal(client.receive(), transport_error(rid, reason), f"{rid} yields correlated transport error")
            client.call("until-close")
            checks.equal(client.receive(), text_result("until-close", "EOF delimited JSON"), "EOF-delimited successful body")
            client.call("recovery", "healthy after failures")
            checks.equal(client.receive(), text_result("recovery", "healthy after failures"), "bridge continues after transport failures")
            client.proc.stdin.close()
            checks.equal(client.proc.stdout.read(), b"", "no duplicate replies or replies to notifications")
            checks.equal(client.proc.wait(), 0, "clean stdin EOF shutdown")
            client.stderr_thread.join()
            # Join handlers before inspecting their final records/errors.
            mock.close()
            checks.equal(mock.errors, [], "mock handler threads completed without errors")
            checks.equal(mock.get_count, 2, "standalone GET reconnect budget is exactly one")
            records = list(mock.records)
            posts = [entry for entry in records if entry[0] == "POST"]
            gets = [entry for entry in records if entry[0] == "GET"]
            deletes = [entry for entry in records if entry[0] == "DELETE"]
            checks.equal(len(deletes), 1, "one session DELETE on shutdown")
            checks.equal(all(path == "/mcp" for _, path, _, _, _ in records), True, "all traffic stays on mock MCP path")
            headers = [{key.lower(): value for key, value in entry[2].items()} for entry in records]
            checks.equal(all(h.get("x-born-test") == "local-only" for h in headers), True, "custom header on POST/GET/DELETE")
            checks.equal(all("authorization" not in h for h in headers), True, "no authorization traffic")
            checks.equal(all(h.get("mcp-protocol-version") == PROTOCOL for h in headers), True, "protocol version on POST/GET/DELETE")
            checks.equal("mcp-session-id" in headers[0], False, "initialize does not invent a session")
            checks.equal(all(h.get("mcp-session-id") == SESSION for h in headers[1:]), True, "session header on every request after initialize")
            checks.equal({key.lower(): value for key, value in gets[1][2].items()}.get("last-event-id"), "push-1", "GET reconnect sends Last-Event-ID")
            checks.equal(posts[0][3], init, "initialize request forwarded unchanged")
            post_headers = [{key.lower(): value for key, value in entry[2].items()} for entry in posts]
            checks.equal(all(h.get("content-type") == "application/json" for h in post_headers), True, "POST content type")
            checks.equal(all("application/json" in h.get("accept", "") and "text/event-stream" in h.get("accept", "") for h in post_headers), True, "POST advertises JSON and SSE")
            for rid, prime in (("retry", "prime-retry"), ("exhaust", "prime-exhaust")):
                attempts = [entry for entry in posts if entry[3].get("id") == rid]
                primed = next(entry for entry in posts if entry[3].get("id") == prime)
                checks.equal(len(attempts), 2, f"{rid} retries exactly once")
                checks.equal(attempts[0][4], primed[4], f"{rid} first attempt uses primed keep-alive socket")
                checks.equal(attempts[1][4] != attempts[0][4], True, f"{rid} retry uses fresh socket")
                checks.equal(attempts[0][3], attempts[1][3], f"{rid} retry preserves exact request")
            checks.equal(mock.attempts["peer-close"], 1, "fresh peer-close failure is not retried")
            checks.equal(len(posts), 23, "exact upstream POST count including two notifications and retries")
            print(f"PASS: {checks.count} assertions; JSON initialize/list/call, chunked split SSE, UTF-8, typed IDs, notifications, concurrent out-of-order multiplexing, 4 MiB backpressure, connection refusal, truncated headers/chunks, peer EOF/errors, keep-alive retry budget, GET reconnect/resume, session DELETE", flush=True)
    finally:
        try:
            if client is not None:
                client.close()
        finally:
            mock.close()


def main():
    parser = argparse.ArgumentParser(description="Local subprocess/HTTP/SSE regression for the born-backed bridge")
    parser.add_argument("binary", nargs="?", default=str(Path(__file__).resolve().parents[1] / "zig-out" / "bin" / ("mcp-bridge.exe" if os.name == "nt" else "mcp-bridge")))
    parser.add_argument("--timeout", type=float, default=60, help="whole worker hang guard in seconds (default: 60)")
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    binary = str(Path(args.binary).resolve())
    if not Path(binary).is_file():
        parser.error(f"binary not found: {binary}")
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    if args.worker:
        worker(binary)
        return 0
    proc = subprocess.Popen([sys.executable, "-u", str(Path(__file__).resolve()), "--worker", binary], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        stdout, stderr = proc.communicate(timeout=args.timeout)
    except subprocess.TimeoutExpired as exc:
        active = set()
        for line in (exc.output or b"").splitlines():
            if line.startswith(b"bridge-pid="):
                active.add(int(line.split(b"=", 1)[1]))
            elif line.startswith(b"bridge-exit="):
                active.discard(int(line.split(b"=", 1)[1]))
        for pid in active:
            try:
                os.kill(pid, signal.SIGTERM if os.name == "nt" else signal.SIGKILL)
            except ProcessLookupError:
                pass  # It exited between the watchdog firing and cleanup.
        proc.kill()
        stdout, stderr = proc.communicate(timeout=10)
        sys.stdout.buffer.write(stdout)
        sys.stderr.buffer.write(stderr)
        print(f"FAIL: worker exceeded {args.timeout:g}s hang guard", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(stdout)
    sys.stderr.buffer.write(stderr)
    return proc.returncode


if __name__ == "__main__":
    sys.exit(main())
