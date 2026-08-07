# McpBridge

MCP stdio bridge for Windows: connects MCP clients that only speak stdio
(IDEs like Windsurf/Devin) to remote MCP servers over HTTP(S) **Streamable
HTTP** transport — without Node.js.

TLS uses Windows **SChannel** with **DANE TLSA** verification
(DANE-TA and DANE-EE, usages 0–3, selectors CERT/SPKI, matching
FULL/SHA-256/SHA-512) — **no DNSSEC required**. When the host publishes no
TLSA records, verification falls back to normal PKI against the **Windows
CA root store**.

## Usage

```
mcp-bridge.exe <url> [--header "Name: Value"]... [--verbose]
```

Example `mcp_config.json` entry:

```json
{
  "mcpServers": {
    "memory": {
      "command": "C:\\tools\\mcp-bridge.exe",
      "args": ["https://memory.morante.com/mcp"]
    }
  }
}
```

Auth headers can be passed with `--header "Authorization: Bearer <token>"`.

## Protocol behavior

- stdin: newline-delimited JSON-RPC (one message per line)
- Each message is POSTed to the URL with `Content-Type: application/json`,
  `Accept: application/json` (plain JSON responses, no SSE)
- `MCP-Session-Id` from the initialize response is sent on later requests
- Response bodies are written to stdout, one line each; notifications
  (HTTP 202, empty body) produce no output
- Transport errors produce a synthesized JSON-RPC error on stdout

## Building

Cross-compiles from FreeBSD/Linux (Zig 0.15.2):

```
zig build                # zig-out/bin/mcp-bridge.exe (x86_64-windows-gnu)
zig build test           # host-side unit tests (DANE matcher, JSON helpers)
```

## DANE policy

1. TLSA lookup for `_<port>._tcp.<host>` via Windows DnsQuery.
2. Records exist → cert chain MUST match (DANE-EE: leaf; DANE-TA: any chain
   cert). A match is accepted even if PKI chain validation would fail
   (self-signed DANE-EE works). No match → connection refused.
3. No TLSA records → standard PKI against the Windows root store,
   including hostname check.
4. DNS lookup error (vs. empty answer) → connection refused.

## License

BSD 2-Clause — see LICENSE.
