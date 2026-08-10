#!/usr/bin/env python3
"""Multi-process live test for issue #3: OAuth lockfile coordination.

Spawns TWO mcp-bridge processes against the same mock OAuth-secured MCP
server with a shared, empty token cache. Without coordination both would
open a browser flow; with it, exactly ONE authorization happens and the
second instance adopts the tokens the first one caches.

The "browser" is curl (via $BROWSER): it fetches the authorize URL, the
mock AS 302s to the loopback redirect URI, and the flow completes
headlessly. The mock is HTTPS (a throwaway CA is trusted via
SSL_CERT_FILE) because the bridge refuses plain-HTTP OAuth.

Usage: python3 tests/live_oauth_lock.py [path-to-mcp-bridge]
Requires: openssl, curl, and a POSIX build of mcp-bridge.
"""

import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ACCESS_TOKEN = "AT-live-test"
REFRESH_TOKEN = "RT-live-test"

stats = {"authorize": 0, "register": 0, "token": 0, "mcp_401": 0, "mcp_ok": 0}
stats_lock = threading.Lock()


def bump(key):
    with stats_lock:
        stats[key] += 1


def make_handler(base_url):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def _json(self, status, obj, extra_headers=None):
            body = json.dumps(obj).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            for k, v in (extra_headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            path = self.path.split("?", 1)[0]
            if path == "/.well-known/oauth-protected-resource":
                return self._json(200, {
                    "resource": base_url,
                    "authorization_servers": [base_url],
                })
            if path == "/.well-known/oauth-authorization-server":
                return self._json(200, {
                    "issuer": base_url,
                    "authorization_endpoint": base_url + "/authorize",
                    "token_endpoint": base_url + "/token",
                    "registration_endpoint": base_url + "/register",
                })
            if path == "/authorize":
                bump("authorize")
                # Widen the lock window so the second instance reliably
                # observes the in-progress flow.
                time.sleep(0.5)
                from urllib.parse import urlparse, parse_qs
                q = parse_qs(urlparse(self.path).query)
                redirect = q["redirect_uri"][0]
                state = q["state"][0]
                sep = "&" if "?" in redirect else "?"
                self.send_response(302)
                self.send_header("Location", f"{redirect}{sep}code=code-1&state={state}")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_error(404)

        def do_POST(self):
            path = self.path.split("?", 1)[0]
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            if path == "/register":
                bump("register")
                return self._json(201, {"client_id": "live-test-client"})
            if path == "/token":
                bump("token")
                return self._json(200, {
                    "access_token": ACCESS_TOKEN,
                    "refresh_token": REFRESH_TOKEN,
                    "expires_in": 3600,
                })
            if path == "/mcp":
                if self.headers.get("Authorization") != f"Bearer {ACCESS_TOKEN}":
                    bump("mcp_401")
                    body = b"unauthorized"
                    self.send_response(401)
                    self.send_header(
                        "WWW-Authenticate",
                        f'Bearer resource_metadata="{base_url}/.well-known/oauth-protected-resource"',
                    )
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                bump("mcp_ok")
                req = json.loads(body)
                return self._json(200, {
                    "jsonrpc": "2.0",
                    "id": req.get("id"),
                    "result": {
                        "protocolVersion": req.get("params", {}).get(
                            "protocolVersion", "2025-03-26"),
                        "capabilities": {},
                        "serverInfo": {"name": "mock", "version": "0"},
                    },
                })
            self.send_error(404)

    return Handler


def make_certs(tmp):
    for tool in ("openssl", "curl"):
        if not shutil.which(tool):
            sys.exit(f"missing required tool: {tool}")
    ca = os.path.join(tmp, "ca.pem")
    key = os.path.join(tmp, "server.key")
    crt = os.path.join(tmp, "server.pem")
    ext = os.path.join(tmp, "ext.cnf")
    with open(ext, "w") as f:
        f.write("subjectAltName=DNS:localhost,IP:127.0.0.1\n")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout",
         os.path.join(tmp, "ca.key"), "-out", ca, "-days", "2", "-nodes",
         "-subj", "/CN=mcp-bridge-test-CA"],
        check=True, capture_output=True)
    subprocess.run(
        ["openssl", "req", "-newkey", "rsa:2048", "-keyout", key, "-out",
         os.path.join(tmp, "server.csr"), "-nodes", "-subj", "/CN=localhost"],
        check=True, capture_output=True)
    subprocess.run(
        ["openssl", "x509", "-req", "-in", os.path.join(tmp, "server.csr"),
         "-CA", ca, "-CAkey", os.path.join(tmp, "ca.key"), "-CAcreateserial",
         "-out", crt, "-days", "2", "-extfile", ext],
        check=True, capture_output=True)
    return ca, key, crt


def pump(stream, sink):
    try:
        for line in iter(stream.readline, b""):
            sink.append(line.decode(errors="replace"))
    except ValueError:
        pass


def main():
    bridge = os.path.abspath(sys.argv[1] if len(sys.argv) > 1
                             else "zig-out/bin/mcp-bridge")
    if not os.path.isfile(bridge):
        sys.exit(f"bridge binary not found: {bridge}")

    tmp = tempfile.mkdtemp(prefix="mcp-bridge-locktest-")
    ca, key, crt = make_certs(tmp)

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler("https://localhost:PLACE"))
    port = httpd.server_address[1]
    base = f"https://localhost:{port}"
    # Rebuild the handler bound to the real base URL.
    httpd.RequestHandlerClass = make_handler(base)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    print(f"mock AS + MCP server on {base}")

    env = dict(os.environ)
    env["XDG_DATA_HOME"] = os.path.join(tmp, "xdg")
    env["HOME"] = os.path.join(tmp, "home")  # isolate from any user config
    os.makedirs(env["HOME"], exist_ok=True)
    env["SSL_CERT_FILE"] = ca
    env["BROWSER"] = "curl -skL"  # the headless "user consent"

    procs, outs, errs = [], [], []
    init_line = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-03-26", "capabilities": {},
                   "clientInfo": {"name": "live-test", "version": "0"}},
    }) + "\n"
    for i in range(2):
        p = subprocess.Popen(
            [bridge, "--oauth", "--verbose", base + "/mcp"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=env)
        procs.append(p)
        outs.append([])
        errs.append([])
        threading.Thread(target=pump, args=(p.stdout, outs[i]), daemon=True).start()
        threading.Thread(target=pump, args=(p.stderr, errs[i]), daemon=True).start()
        p.stdin.write(init_line.encode())
        p.stdin.flush()

    deadline = time.time() + 60
    ok = [False, False]
    while time.time() < deadline and not all(ok):
        for i in range(2):
            if not ok[i] and any(
                    '"id": 1' in l.replace('"id":1', '"id": 1') and '"result"' in l
                    for l in outs[i]):
                ok[i] = True
        time.sleep(0.05)

    for p in procs:
        try:
            p.stdin.close()
        except BrokenPipeError:
            pass
    for p in procs:
        try:
            p.wait(timeout=15)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()

    time.sleep(0.2)  # let the pump threads drain
    for i in range(2):
        print(f"--- bridge[{i}] exit={procs[i].returncode} ---")
        print("".join(errs[i]), end="")

    failures = []
    if not all(ok):
        failures.append(f"initialize responses: {ok}")
    if stats["authorize"] != 1:
        failures.append(f"authorize hits = {stats['authorize']} (want 1)")
    if stats["token"] != 1:
        failures.append(f"token exchanges = {stats['token']} (want 1)")
    if stats["register"] != 1:
        failures.append(f"DCR registrations = {stats['register']} (want 1)")
    if stats["mcp_ok"] != 2:
        failures.append(f"authenticated /mcp posts = {stats['mcp_ok']} (want 2)")
    adopted = sum(1 for e in errs if "token adopted" in "".join(e)
                  or "adopted" in "".join(e))
    if adopted < 1:
        failures.append("no instance reported adopting tokens via coordination")
    for i, p in enumerate(procs):
        if p.returncode != 0:
            failures.append(f"bridge[{i}] exit code {p.returncode}")

    print(f"stats: {stats}")
    shutil.rmtree(tmp, ignore_errors=True)
    if failures:
        for f in failures:
            print(f"FAIL: {f}")
        return 1
    print("PASS: one browser flow, both instances authenticated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
