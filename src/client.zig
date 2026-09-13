// Public module root (issue #28): the event-driven HTTP/TLS/DANE/SSE
// client layer, importable from a downstream Zig package as
// "mcp-bridge-client":
//
//     const client = @import("mcp-bridge-client");
//     const target = try client.parseUrl("https://example.com/mcp");
//
// One httpc.Conn = one upstream connection driven by the born event port
// (kqueue/epoll/IOCP): a POST with a plain-JSON or SSE-framed response,
// or a long-lived GET event stream. TLS verification is DANE-first with
// a system-trust fallback (platform.Verifier).
//
// MCP-shaped but inert for non-MCP callers: pass PostCtx defaults and
// ignore http.Response.mcp_session_id. For a token stream
// (OpenAI-style streaming completions — a POST whose response is
// text/event-stream), use client.Conn.startPostStream: the head is
// consulted via onStreamHead, every event is delivered to onEvent, and
// stream end is a clean onEnd(null) (issue #30).
//
// Nothing here touches build_options; the module needs only the born
// import plus the platform link wiring. A downstream build.zig must
// repeat that wiring on its own root module — linkPlatform() in this
// repo's build.zig is the reference implementation (see README).

pub const httpc = @import("httpc.zig");
pub const http = @import("http.zig");
pub const sse = @import("sse.zig");
pub const dane = @import("dane.zig");
pub const platform = @import("platform.zig");

pub const Conn = httpc.Conn;
pub const Handler = httpc.Handler;
pub const PostCtx = httpc.PostCtx;
pub const buildRequest = httpc.buildRequest;

pub const Target = http.Target;
pub const Response = http.Response;
pub const parseUrl = http.parseUrl;
pub const getHeaderValue = http.getHeaderValue;

pub const Event = sse.Event;
pub const Parser = sse.Parser;

pub const TlsaRecord = dane.TlsaRecord;
pub const DaneResult = dane.DaneResult;

pub const Verifier = platform.Verifier;

test {
    // Keep every re-export analyzeable from this root.
    _ = httpc;
    _ = http;
    _ = sse;
    _ = dane;
    _ = platform;
}
