// One-shot synchronous HTTP request over the event machinery (issue #7).
//
// OAuth 2.1's discovery/registration/token calls (and any other
// request/response one-shot) are sequential: they run a single Conn on a
// PRIVATE event port, driven to completion. No blocking socket I/O exists
// anywhere in the bridge — even the "synchronous" helpers are the same
// non-blocking state machine, just pumped by a nested loop.
//
// The wait carries a generous bound (120s per event wait, vs the legacy
// 30s SO_RCVTIMEO per read) so a dead peer cannot hang the caller forever;
// it is a deadline on a run-to-completion operation, not a multiplexing
// timer.

const std = @import("std");
const platform = @import("platform.zig");
const evport = @import("evport.zig");
const http = @import("http.zig");
const httpc = @import("httpc.zig");

pub const Error = error{
    ConnectFailed,
    HandshakeFailed,
    PkiValidationFailed,
    SocketError,
    TlsError,
    MalformedResponse,
    ResponseTooLarge,
    SseEndedWithoutResponse,
    ProxyTunnelFailed,
    Timeout,
    UnexpectedEnd,
    EventPortFailed,
    OutOfMemory,
};

const Ctx = struct {
    done: bool = false,
    resp: ?http.Response = null,
    err: ?anyerror = null,
};

fn onResponse(ctx: *anyopaque, conn: *httpc.Conn, resp: http.Response) void {
    const self: *Ctx = @ptrCast(@alignCast(ctx));
    self.resp = resp; // ownership moves to the caller
    self.done = true;
    conn.close();
}

fn onStreamHead(ctx: *anyopaque, conn: *httpc.Conn, status: u16, is_sse: bool, session_id: ?[]const u8, www_authenticate: ?[]const u8) void {
    _ = ctx;
    _ = status;
    _ = is_sse;
    _ = session_id;
    _ = www_authenticate;
    conn.close(); // one-shots never open streams
}

fn onEvent(ctx: *anyopaque, conn: *httpc.Conn, ev: *const @import("sse.zig").Event) void {
    _ = ctx;
    _ = conn;
    _ = ev;
}

fn onEnd(ctx: *anyopaque, conn: *httpc.Conn, err: ?anyerror) void {
    const self: *Ctx = @ptrCast(@alignCast(ctx));
    self.err = err orelse error.UnexpectedEnd;
    self.done = true;
    conn.close();
}

/// Run one HTTP request to completion. `verifier` is required for https
/// targets (borrowed; must outlive the call). Returns an owned Response.
pub fn request(
    alloc: std.mem.Allocator,
    method: []const u8,
    target: http.Target,
    accept: []const u8,
    content_type: ?[]const u8,
    extra_headers: []const []const u8,
    body: ?[]const u8,
    verifier: ?*platform.Verifier,
) Error!http.Response {
    var evp = evport.EvPort.init(alloc) catch |err| switch (err) {
        error.OutOfMemory => return Error.OutOfMemory,
        else => return Error.EventPortFailed,
    };
    defer evp.deinit();

    var ctx = Ctx{};
    const handler = httpc.Handler{
        .ctx = &ctx,
        .onResponse = onResponse,
        .onStreamHead = onStreamHead,
        .onEvent = onEvent,
        .onEnd = onEnd,
    };

    var req = try httpc.buildRequest(alloc, method, target.path, target.host, accept, content_type, extra_headers, body);
    errdefer req.deinit(alloc);

    const conn = try httpc.Conn.startPost(alloc, &evp, handler, target, req, null, null, verifier);
    // No conn registry here: this private loop reaps directly once done.

    var events: [16]evport.Event = undefined;
    while (!ctx.done) {
        const n = evp.wait(&events, 120_000) catch return Error.EventPortFailed;
        if (n == 0) {
            ctx.err = error.Timeout;
            conn.close();
            break;
        }
        for (events[0..n]) |ev| {
            if (ev.udata) |ud| {
                const c: *httpc.Conn = @ptrCast(@alignCast(ud));
                c.onEvent(ev);
            }
        }
    }

    conn.reapClose();
    conn.deinitMem();

    if (ctx.err) |e| {
        return switch (e) {
            error.ConnectFailed => Error.ConnectFailed,
            error.HandshakeFailed => Error.HandshakeFailed,
            error.PkiValidationFailed => Error.PkiValidationFailed,
            error.SocketError => Error.SocketError,
            error.TlsError => Error.TlsError,
            error.MalformedResponse => Error.MalformedResponse,
            error.ResponseTooLarge => Error.ResponseTooLarge,
            error.SseEndedWithoutResponse => Error.SseEndedWithoutResponse,
            error.ProxyTunnelFailed => Error.ProxyTunnelFailed,
            error.Timeout => Error.Timeout,
            error.OutOfMemory => Error.OutOfMemory,
            else => Error.UnexpectedEnd,
        };
    }
    return ctx.resp orelse Error.UnexpectedEnd;
}
