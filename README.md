# McpBridge

<img src="assets/icon.svg" align="right" width="128" alt="MCP Bridge icon">

MCP stdio bridge for **Windows, FreeBSD, and Linux**: connects MCP clients
that only speak stdio (IDEs like Windsurf/Devin/Claude) to remote MCP
servers over HTTP(S) **Streamable HTTP** transport — without Node.js.

TLS uses **SChannel** (Windows) or **OpenSSL** (POSIX) with **DANE TLSA**
verification (DANE-TA and DANE-EE, usages 0–3, selectors CERT/SPKI,
matching FULL/SHA-256/SHA-512) — **no DNSSEC required**. When the host
publishes no TLSA records, verification falls back to normal PKI against
the system trust store (Windows root store / certctl / distro bundle).

Servers that require authorization (HTTP 401) are handled with built-in
**OAuth 2.1** — no `mcp-remote` shim needed.

## Installation

Pre-built binaries and packages are on the
[releases page](https://pacyworld.dev/buenapp/mcp-bridge/releases)
([GitHub mirror](https://github.com/buenapp/mcp-bridge/releases)).
`<ver>` below is the release version without the `v` prefix (e.g. `0.2.2`).

### Windows

Download and run the installer:

- `mcp-bridge-<ver>-setup.exe` — per-user installer (no admin required,
  Authenticode-signed). Installs `mcp-bridge.exe` into
  `%LOCALAPPDATA%\Programs\MCP Bridge` and adds that directory to the user
  `PATH`. **Restart your MCP client** after installing so it picks up the
  new `PATH`.
- `mcp-bridge-<ver>.exe` — standalone binary (also signed) if you prefer
  to place it somewhere yourself.

### FreeBSD

System-wide, via pkg:

```sh
pkg install mcp-bridge                              # PortsPlus repo
# or, from a downloaded release asset:
doas pkg add mcp-bridge-<ver>-x86_64-freebsd.pkg
```

Both install `/usr/local/bin/mcp-bridge`.

User-local install (no root): download `mcp-bridge-<ver>-x86_64-freebsd`
and drop it in `$HOME/bin` — on FreeBSD that directory is in the default
login `PATH`:

```sh
mkdir -p ~/bin
fetch -o ~/bin/mcp-bridge \
  https://pacyworld.dev/buenapp/mcp-bridge/releases/download/v<ver>/mcp-bridge-<ver>-x86_64-freebsd
chmod +x ~/bin/mcp-bridge
```

### Linux

System-wide, via the package manager:

```sh
# Debian / Ubuntu
sudo dpkg -i mcp-bridge_<ver>_amd64.deb        # or: sudo apt install ./mcp-bridge_<ver>_amd64.deb

# Fedora / RHEL
sudo dnf install ./mcp-bridge-<ver>-1.*.rpm
```

Both install `/usr/bin/mcp-bridge` and pull in the distro OpenSSL 3
dependency automatically.

User-local install: download `mcp-bridge-<ver>-x86_64-linux` and place it
in `$HOME/.local/bin` (Fedora/Ubuntu default) or `$HOME/bin`:

```sh
mkdir -p ~/.local/bin
curl -L -o ~/.local/bin/mcp-bridge \
  https://pacyworld.dev/buenapp/mcp-bridge/releases/download/v<ver>/mcp-bridge-<ver>-x86_64-linux
chmod +x ~/.local/bin/mcp-bridge
```

Note: on Linux these directories are only added to `PATH` at login time
**if they already exist**, so if the directory is new you must log out and
back in once before `mcp-bridge` resolves by name. You can verify with
`command -v mcp-bridge`.

## Usage

```
mcp-bridge <url> [--header "Name: Value"]... [--verbose]
```

Example `mcp_config.json` entry:

```json
{
  "mcpServers": {
    "example": {
      "command": "mcp-bridge",
      "args": ["https://mcp.example.com/mcp"]
    }
  }
}
```

Auth headers can be passed with `--header "Authorization: Bearer <token>"`.

### Claude Desktop / Claude Code

This bridge targets stdio-only clients like Claude Desktop
(`claude_desktop_config.json`) and Claude Code:

```json
{
  "mcpServers": {
    "example": {
      "command": "mcp-bridge.exe",
      "args": ["https://mcp.example.com/mcp"]
    }
  }
}
```

Diagnostics go to stderr (`--verbose`), stdout carries only JSON-RPC.

## OAuth 2.1

When a server answers **401 Unauthorized** (or `--oauth` / a config entry
enables it), the bridge runs OAuth automatically:

1. **Discovery** — RFC 9728 protected-resource metadata (starting from the
   401's `WWW-Authenticate: resource_metadata=` URL when present), then
   RFC 8414 / OIDC authorization-server metadata.
2. **Interactive** (default) — Authorization Code + PKCE (S256). The
   browser opens at the authorization URL; the redirect lands on a
   one-shot loopback listener (`http://localhost:<ephemeral>/callback`).
   With no pre-registered `client_id`, the bridge registers itself via
   RFC 7591 dynamic client registration.
3. **Headless** — `--oauth-client-id` + `--oauth-client-secret` uses the
   Client Credentials grant instead (no browser).
4. Tokens are cached per server in the per-user data dir
   (`~/.local/share/mcp-bridge/tokens/`, `%LOCALAPPDATA%\mcp-bridge\tokens\`,
   mode 0600) and refreshed automatically; you authorize once per server.

### Remote SSH sessions

Over VS Code / Windsurf Remote SSH the flow behaves as if local: the IDE
injects `$BROWSER` into remotely-spawned processes, its helper opens the
URL in your **local** browser and auto-forwards the ephemeral loopback
port back to the remote host. Nothing to configure.

If the browser does not open (bare ssh, no IDE helper), the authorize URL
is printed on stderr; forward the callback port shown in it:

```sh
ssh -L <port>:localhost:<port> user@remote-host
```

then open the URL manually.

### CLI flags and config file

```
--oauth                     enable OAuth for this server
--oauth-client-id ID        pre-registered client id (else DCR)
--oauth-client-secret SEC   client secret (enables headless client-credentials)
--oauth-scope SCOPES        scopes to request (else the server's 401 scope)
--oauth-grant GRANT         authorization_code | client_credentials (default: auto)
--resource URI              RFC 8707 resource indicator (default: the server URL)
--config PATH               JSON config file
--oauth-logout              delete cached tokens for <url> and exit
```

**Grant selection.** With `--oauth-grant authorization_code`, a configured
client id + secret runs the interactive authorization-code flow as a
**confidential client** (the secret is sent at the token endpoint) instead
of the headless client-credentials grant. `auto` (the default) keeps the
historic behavior: id + secret → client-credentials, anything else →
authorization code + PKCE.

**Resource indicator.** The bridge sends an RFC 8707 `resource` parameter
on the authorization and token requests; it defaults to the server URL.
Set `--resource` when a multi-tenant server needs a distinct resource URI
per tenant — each explicit resource also gets its own entry in the token
cache, so the same server URL can serve multiple tenants without their
sessions overwriting each other.

Optional config file (`~/.config/mcp-bridge/config.json` on POSIX,
`%APPDATA%\mcp-bridge\config.json` on Windows), keyed by server URL;
flags override file values:

```json
{
  "servers": {
    "https://mcp.example.com/mcp": {
      "oauth": true,
      "client_id": "my-client",
      "scope": "openid profile",
      "resource": "https://tenant1.example.net/",
      "grant": "authorization_code"
    }
  }
}
```

## Protocol behavior

- stdin: newline-delimited JSON-RPC (one message per line)
- Each message is POSTed to the URL with `Content-Type: application/json`,
  `Accept: application/json, text/event-stream` (plain JSON and SSE-framed
  responses both supported)
- `MCP-Session-Id` from the initialize response is sent on later requests
- Response bodies are written to stdout, one line each; notifications
  (HTTP 202, empty body) produce no output
- Transport errors produce a synthesized JSON-RPC error on stdout

## Building

Zig 0.15.2. Windows is the default target:

```
zig build                                        # zig-out/bin/mcp-bridge.exe (x86_64-windows-gnu)
zig build test                                   # host-side unit tests
zig build -Dtarget=x86_64-freebsd                # FreeBSD (base OpenSSL, certctl trust)
zig build -Dtarget=x86_64-linux-gnu              # Linux (needs OpenSSL dev files;
                                                 #  cross: -Dlinux-sysroot=.sysroot/ubuntu-24.04)
```

Runtime dependencies: none on Windows; base-system OpenSSL on FreeBSD;
distro OpenSSL 3 (`libssl.so.3`) + glibc on Linux.

## DANE policy

1. TLSA lookup for `_<port>._tcp.<host>` (Windows DnsQuery / POSIX
   res_query).
2. Records exist → cert chain MUST match (DANE-EE: leaf; DANE-TA: any chain
   cert). A match is accepted even if PKI chain validation would fail
   (self-signed DANE-EE works). No match → connection refused.
3. No TLSA records → standard PKI against the system trust store,
   including hostname check.
4. DNS lookup error (vs. empty answer) → connection refused.

## License

BSD 2-Clause — see LICENSE.
