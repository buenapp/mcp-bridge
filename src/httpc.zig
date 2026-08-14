// Event-driven HTTP/1.1 client connection for the event core (issue #7).
//
// One Conn = one upstream connection with one HTTP role:
//   .post     — one request, one complete response. Plain JSON body, or an
//               SSE-framed body where the event whose JSON-RPC id matches
//               expect_id becomes the response and all other events are
//               delivered as push events.
//   .sse_get  — long-lived text/event-stream (legacy transport GET stream,
//               Streamable HTTP standalone GET push stream).
//
// All I/O is non-blocking and driven by the platform event port. Nothing
// blocks, nothing polls, no threads. Progress happens from onEvent() →
// drive(), and from drive() alone while buffered state permits.
//
// Lifecycle and ownership (see main.zig for the core loop):
//   - The core creates conns via startPost/startStreamGet and tracks them.
//   - conn.close() only MARKS the conn closing. The core closes the fd
//     right after the next evport.wait() flush (so staged registrations
//     never reference a recycled fd) and frees the conn after that batch's
//     event handling (so in-flight event udata never dangles).
//   - Handlers run synchronously on the loop thread and may call close().

const std = @import("std");
const platform = @import("platform.zig");
const evport = @import("evport.zig");
const http = @import("http.zig");
const mcp = @import("mcp.zig");
const sse = @import("sse.zig");
const nb = if (platform.is_windows) @import("nb_win.zig") else @import("nb_posix.zig");

const log = std.log.scoped(.httpc);

pub const Error = error{
    ConnectFailed,
    SocketError,
    HandshakeFailed,
    PkiValidationFailed,
    TlsError,
    MalformedResponse,
    ResponseTooLarge,
    SseEndedWithoutResponse,
    OutOfMemory,
};

pub const State = enum {
    connecting, // TCP connect in flight (EINPROGRESS)
    handshaking, // TLS handshake driving
    writing, // request bytes flushing
    read_head, // accumulating response headers
    read_body, // de-framing a bounded response body
    sse_stream, // event stream (long-lived, or a POST's SSE response)
    idle, // keep-alive: reusable for another POST (bridge-level decision)
    done, // terminal; handler has been (or is being) notified
};

pub const Role = union(enum) {
    post: PostCtx,
    sse_get,
};

pub const PostCtx = struct {
    /// Raw JSON-RPC id to match in an SSE-framed response (null =
    /// notification: first message event wins). Owned.
    expect_id: ?[]const u8 = null,
    /// Original stdin line, kept for resend (transport fallback /
    /// stale-connection retry). Owned.
    line: ?[]const u8 = null,
    /// True when this POST rides a reused keep-alive connection.
    reused: bool = false,
    /// Which transport created this POST (responses route on this, not on
    /// the bridge's current mode — a mid-flight mode switch must not
    /// misroute a streamable response to the legacy handler).
    kind: enum { streamable, legacy } = .streamable,
    /// 401 already re-authenticated once (bridge-level retry budget).
    auth_retried: bool = false,
    /// 403 insufficient_scope already stepped up once (RFC 6750 §3.1).
    step_up_retried: bool = false,
    /// A reused-conn failure already retried once on a fresh conn.
    retried: bool = false,
};

/// Synchronous callbacks into the bridge (single-threaded; invoked from
/// drive()). onResponse hands over an owned Response (deinit with
/// conn.alloc). onStreamHead must call conn.proceedStream() or
/// conn.close(). onEnd reports termination: err == null is a clean end
/// (stream EOF, idle close), non-null a failure.
pub const Handler = struct {
    ctx: *anyopaque,
    onResponse: *const fn (ctx: *anyopaque, conn: *Conn, resp: http.Response) void,
    onStreamHead: *const fn (ctx: *anyopaque, conn: *Conn, status: u16, is_sse: bool, session_id: ?[]const u8, www_authenticate: ?[]const u8) void,
    onEvent: *const fn (ctx: *anyopaque, conn: *Conn, ev: *const sse.Event) void,
    onEnd: *const fn (ctx: *anyopaque, conn: *Conn, err: ?anyerror) void,
};

/// Build the wire bytes for a request. method: "POST"/"GET"/"DELETE".
/// accept: e.g. "application/json, text/event-stream". content_type/body
/// only for POST.
pub fn buildRequest(
    alloc: std.mem.Allocator,
    method: []const u8,
    path: []const u8,
    host: []const u8,
    accept: []const u8,
    content_type: ?[]const u8,
    extra_headers: []const []const u8,
    body: ?[]const u8,
) Error!std.ArrayList(u8) {
    var req: std.ArrayList(u8) = .empty;
    errdefer req.deinit(alloc);

    appendFmt(alloc, &req, "{s} {s} HTTP/1.1\r\nHost: {s}\r\n", .{ method, path, host }) catch return Error.OutOfMemory;
    appendFmt(alloc, &req, "Accept: {s}\r\n", .{accept}) catch return Error.OutOfMemory;
    if (content_type) |ct| appendFmt(alloc, &req, "Content-Type: {s}\r\n", .{ct}) catch return Error.OutOfMemory;
    for (extra_headers) |h| {
        appendFmt(alloc, &req, "{s}\r\n", .{h}) catch return Error.OutOfMemory;
    }
    if (body) |b| {
        appendFmt(alloc, &req, "Content-Length: {d}\r\n\r\n", .{b.len}) catch return Error.OutOfMemory;
        req.appendSlice(alloc, b) catch return Error.OutOfMemory;
    } else {
        req.appendSlice(alloc, "\r\n") catch return Error.OutOfMemory;
    }
    return req;
}

fn appendFmt(alloc: std.mem.Allocator, list: *std.ArrayList(u8), comptime fmt: []const u8, args: anytype) !void {
    const s = try std.fmt.allocPrint(alloc, fmt, args);
    defer alloc.free(s);
    try list.appendSlice(alloc, s);
}

// Body framing mode determined from response headers.
const BodyMode = union(enum) {
    length: usize, // Content-Length remaining
    chunked, // Transfer-Encoding: chunked
    until_close, // neither: body runs to EOF
};

/// Buffer-driven body de-framing (ported from the legacy wire-driven Pump;
/// here the conn feeds wire bytes into `in` and feed() consumes from it).
const BodyPump = struct {
    mode: BodyMode,
    chunk_left: usize = 0,

    const Feed = enum { need_more, done };

    /// Consume bytes from in[rpos..], append decoded body bytes to `out`.
    fn feed(self: *BodyPump, alloc: std.mem.Allocator, in: []const u8, rpos: *usize, out: *std.ArrayList(u8)) Error!Feed {
        switch (self.mode) {
            .length => |*remaining| {
                if (remaining.* == 0) return .done;
                const avail = in.len - rpos.*;
                if (avail == 0) return .need_more;
                const n = @min(avail, remaining.*);
                if (out.items.len + n > http.MAX_RESPONSE) return Error.ResponseTooLarge;
                out.appendSlice(alloc, in[rpos.* .. rpos.* + n]) catch return Error.OutOfMemory;
                rpos.* += n;
                remaining.* -= n;
                return if (remaining.* == 0) .done else .need_more;
            },
            .until_close => {
                const avail = in.len - rpos.*;
                if (avail == 0) return .need_more;
                if (out.items.len + avail > http.MAX_RESPONSE) return Error.ResponseTooLarge;
                out.appendSlice(alloc, in[rpos.*..]) catch return Error.OutOfMemory;
                rpos.* = in.len;
                return .need_more; // completes only on EOF
            },
            .chunked => {
                while (true) {
                    if (self.chunk_left == 0) {
                        const line_end = std.mem.indexOfPos(u8, in, rpos.*, "\r\n") orelse return .need_more;
                        const size_str = std.mem.trim(u8, in[rpos.*..line_end], " ");
                        const semi = std.mem.indexOfScalar(u8, size_str, ';') orelse size_str.len;
                        const chunk_size = std.fmt.parseInt(usize, size_str[0..semi], 16) catch return Error.MalformedResponse;
                        rpos.* = line_end + 2;
                        if (chunk_size == 0) return .done; // trailers ignored
                        self.chunk_left = chunk_size;
                    }
                    if (in.len - rpos.* < self.chunk_left + 2) return .need_more;
                    if (out.items.len + self.chunk_left > http.MAX_RESPONSE) return Error.ResponseTooLarge;
                    out.appendSlice(alloc, in[rpos.* .. rpos.* + self.chunk_left]) catch return Error.OutOfMemory;
                    rpos.* += self.chunk_left + 2;
                    self.chunk_left = 0;
                }
            },
        }
    }
};

/// Parsed response headers. session_id / www_authenticate are owned dupes
/// (the raw buffer gets compacted under long-lived streams).
const Head = struct {
    status: u16,
    header_end: usize, // offset of "\r\n\r\n" within the buffer
    content_length: ?usize,
    session_id: ?[]u8 = null,
    www_authenticate: ?[]u8 = null,
    server_closed: bool,
    chunked: bool,
    is_sse: bool,

    fn deinit(self: *Head, alloc: std.mem.Allocator) void {
        if (self.session_id) |s| alloc.free(s);
        if (self.www_authenticate) |s| alloc.free(s);
    }
};

fn parseHead(alloc: std.mem.Allocator, buf: []const u8, header_end: usize) Error!Head {
    const head = buf[0..header_end];

    // Status line: "HTTP/1.1 200 OK"
    const sp1 = std.mem.indexOf(u8, head, " ") orelse return Error.MalformedResponse;
    const sp2 = std.mem.indexOfPos(u8, head, sp1 + 1, " ") orelse head.len;
    const status = std.fmt.parseInt(u16, head[sp1 + 1 .. sp2], 10) catch return Error.MalformedResponse;

    const conn_hdr = http.getHeaderValue(head, "connection");
    const sid_raw = http.getHeaderValue(head, "mcp-session-id");
    const wa_raw = http.getHeaderValue(head, "www-authenticate");
    return .{
        .status = status,
        .header_end = header_end,
        .content_length = http.getHeaderNumeric(head, "content-length"),
        .session_id = if (sid_raw) |s| alloc.dupe(u8, s) catch return Error.OutOfMemory else null,
        .www_authenticate = if (wa_raw) |s| alloc.dupe(u8, s) catch return Error.OutOfMemory else null,
        .server_closed = if (conn_hdr) |v| std.ascii.eqlIgnoreCase(v, "close") else false,
        .chunked = if (http.getHeaderValue(head, "transfer-encoding")) |v|
            std.ascii.indexOfIgnoreCase(v, "chunked") != null
        else
            false,
        .is_sse = if (http.getHeaderValue(head, "content-type")) |v|
            std.ascii.indexOfIgnoreCase(v, "text/event-stream") != null
        else
            false,
    };
}

fn bodyMode(h: *const Head) BodyMode {
    if (h.chunked) return .chunked;
    if (h.content_length) |cl| return .{ .length = cl };
    return .until_close;
}

pub const Conn = struct {
    alloc: std.mem.Allocator,
    evp: *evport.EvPort,
    handler: Handler,
    role: Role,
    target: http.Target,

    stream: nb.Stream = undefined,
    state: State = .connecting,
    /// Marked by close(); the core reaps at end of batch.
    closing: bool = false,
    /// The core's reap already cancelled/closed the stream (IOCP: pending
    /// op completions may still arrive and are absorbed quietly).
    reap_closed: bool = false,

    // ---- write side ----
    wq: std.ArrayList(u8) = .empty, // request bytes
    wpos: usize = 0,
    write_ready: bool = false, // write edge seen, not yet consumed
    write_blocked: bool = false, // last writeNb said want_write
    write_want_read: bool = false, // TLS writeNb said want_read

    // ---- read side ----
    in: std.ArrayList(u8) = .empty, // raw wire bytes
    rpos: usize = 0, // parse cursor into `in`
    read_ready: bool = false, // read edge seen, not yet drained
    read_want_write: bool = false, // TLS readNb said want_write
    wire_eof: bool = false, // peer sent EOF; buffered bytes still parse first

    // ---- response state ----
    head: ?Head = null,
    pump: BodyPump = .{ .mode = .until_close },
    body: std.ArrayList(u8) = .empty, // decoded body accumulator
    decoded: std.ArrayList(u8) = .empty, // de-framed scratch for SSE feed
    parser: ?sse.Parser = null,
    sse_got_response: bool = false, // post role: matched event delivered

    // TLS certificate verification (secure conns only). `verifier` borrows
    // from the caller (bridge/syncreq outlive the conn); cross-origin
    // endpoint conns own one instead.
    verifier: ?*platform.Verifier = null,
    owned_verifier: ?platform.Verifier = null,

    handshake_need: enum { none, read, write } = .none,

    // ------------------------------------------------------------ setup ----

    /// Create + start a POST conn. `request` is moved (conn frees it).
    /// expect_id/line are duped. verifier: required for https targets.
    pub fn startPost(
        alloc: std.mem.Allocator,
        evp: *evport.EvPort,
        handler: Handler,
        target: http.Target,
        request: std.ArrayList(u8),
        expect_id: ?[]const u8,
        line: ?[]const u8,
        verifier: ?*platform.Verifier,
    ) Error!*Conn {
        const eid: ?[]u8 = if (expect_id) |e| alloc.dupe(u8, e) catch return Error.OutOfMemory else null;
        errdefer if (eid) |e| alloc.free(e);
        const ln: ?[]u8 = if (line) |l| alloc.dupe(u8, l) catch return Error.OutOfMemory else null;
        errdefer if (ln) |l| alloc.free(l);
        return start(alloc, evp, handler, target, request, .{ .post = .{ .expect_id = eid, .line = ln } }, verifier);
    }

    /// Create + start a long-lived GET stream conn.
    pub fn startStreamGet(
        alloc: std.mem.Allocator,
        evp: *evport.EvPort,
        handler: Handler,
        target: http.Target,
        request: std.ArrayList(u8),
        verifier: ?*platform.Verifier,
    ) Error!*Conn {
        return start(alloc, evp, handler, target, request, .sse_get, verifier);
    }

    fn start(
        alloc: std.mem.Allocator,
        evp: *evport.EvPort,
        handler: Handler,
        target: http.Target,
        request: std.ArrayList(u8),
        role: Role,
        verifier: ?*platform.Verifier,
    ) Error!*Conn {
        const conn = alloc.create(Conn) catch return Error.OutOfMemory;
        conn.* = .{
            .alloc = alloc,
            .evp = evp,
            .handler = handler,
            .role = role,
            .target = target,
            .wq = request,
            .verifier = verifier,
        };
        errdefer conn.deinitMem();

        nb.Stream.startConnectInto(&conn.stream, alloc, target.host, target.port, evp, conn) catch return Error.ConnectFailed;

        // Persistent edge-triggered read interest for the conn's whole
        // life; one-shot write interest for connect completion (the event
        // port dedups write arms). On IOCP these are no-ops — the
        // association + in-flight connect happened inside startConnectInto.
        evp.monitorRead(conn.stream.fd(), conn);
        evp.wantWrite(conn.stream.fd(), conn);
        return conn;
    }

    pub fn fd(self: *Conn) nb.Fd {
        return self.stream.fd();
    }

    /// Mark the conn closing. No teardown here: the core's end-of-batch
    /// reap purges staged registrations (kqueue), cancels in-flight ops
    /// (IOCP), closes the fd/socket, and frees the conn once drained.
    /// Handlers must not touch a conn after calling close().
    pub fn close(self: *Conn) void {
        self.closing = true;
    }

    /// Fd close (core reap point, after the changelist flush).
    pub fn reapClose(self: *Conn) void {
        self.stream.closeNotify();
        self.stream.deinit();
    }

    /// Memory free (core reap point, after event handling).
    pub fn deinitMem(self: *Conn) void {
        self.wq.deinit(self.alloc);
        self.in.deinit(self.alloc);
        self.body.deinit(self.alloc);
        self.decoded.deinit(self.alloc);
        if (self.head) |*h| h.deinit(self.alloc);
        if (self.parser) |*p| p.deinit();
        switch (self.role) {
            .post => |*p| {
                if (p.expect_id) |e| self.alloc.free(e);
                if (p.line) |l| self.alloc.free(l);
            },
            .sse_get => {},
        }
        self.alloc.destroy(self);
    }

    /// sse_get role, from onStreamHead: proceed into the event stream.
    pub fn proceedStream(self: *Conn) void {
        self.state = .sse_stream;
        self.parser = sse.Parser.init(self.alloc);
    }

    /// post role, from onResponse (JSON body, keep-alive): return the conn
    /// to the reusable idle state instead of closing it.
    pub fn makeIdle(self: *Conn) void {
        self.wpos = 0;
        self.wq.clearRetainingCapacity();
        self.in.clearRetainingCapacity();
        self.rpos = 0;
        self.body.clearRetainingCapacity();
        self.decoded.clearRetainingCapacity();
        if (self.head) |*h| {
            h.deinit(self.alloc);
            self.head = null;
        }
        if (self.parser) |*p| {
            p.deinit();
            self.parser = null;
        }
        switch (self.role) {
            .post => |*p| {
                if (p.expect_id) |e| {
                    self.alloc.free(e);
                    p.expect_id = null;
                }
                if (p.line) |l| {
                    self.alloc.free(l);
                    p.line = null;
                }
                p.reused = true;
            },
            .sse_get => unreachable,
        }
        self.sse_got_response = false;
        self.state = .idle;
    }

    /// Reuse an idle conn for a new POST. `request` is moved.
    pub fn reuseForPost(self: *Conn, request: std.ArrayList(u8), expect_id: ?[]const u8, line: ?[]const u8) Error!void {
        switch (self.role) {
            .post => |*p| {
                p.expect_id = if (expect_id) |e| self.alloc.dupe(u8, e) catch return Error.OutOfMemory else null;
                p.line = if (line) |l| self.alloc.dupe(u8, l) catch return Error.OutOfMemory else null;
            },
            .sse_get => unreachable,
        }
        self.wq = request;
        self.state = .writing;
        self.drive();
    }

    // ----------------------------------------------------------- events ----

    pub fn onEvent(self: *Conn, ev: evport.Event) void {
        if (self.closing) return;
        if (platform.is_windows) {
            self.absorbCompletion(ev);
            if (!self.closing) self.drive();
            return;
        }
        if (ev.readable) self.read_ready = true;
        if (ev.writable) self.write_ready = true;
        if (ev.err) {
            // Connect failures surface via SO_ERROR in connectDone; a stray
            // EV_ERROR post-connect is discovered by the next I/O attempt.
            self.read_ready = true;
            self.write_ready = true;
        }
        self.drive();
    }

    /// IOCP: classify the completion by OVERLAPPED address and update the
    /// stream's ready state. Also the closing-conn drain path (reap waits
    /// for pending ops to complete before freeing the OVERLAPPED memory).
    pub fn absorbCompletion(self: *Conn, ev: evport.Event) void {
        const kind = self.stream.absorbCompletion(ev.overlapped, ev.bytes, if (ev.err) ev.err_no else null);
        switch (kind) {
            .recv => self.read_ready = true,
            .send, .connect => self.write_ready = true,
            .unknown => {},
        }
    }

    /// Make progress while possible without blocking. Re-entrant safe per
    /// conn (handlers may trigger follow-up work; the guard caps livelock).
    pub fn drive(self: *Conn) void {
        var guard: usize = 0;
        while (!self.closing and guard < 1000) : (guard += 1) {
            const progressed = switch (self.state) {
                .connecting => self.driveConnecting(),
                .handshaking => self.driveHandshake(),
                .writing => self.driveWrite(),
                .read_head, .read_body, .sse_stream => self.driveRead(),
                .idle => self.driveIdle(),
                .done => false,
            };
            if (!progressed) break;
        }
    }

    fn driveConnecting(self: *Conn) bool {
        if (!self.write_ready) return false;
        self.write_ready = false;
        self.stream.connectDone() catch {
            self.fail(error.ConnectFailed);
            return true;
        };
        if (!self.target.secure) {
            self.state = .writing;
            return true;
        }
        self.stream.swapToTls(self.alloc, self.target.host) catch {
            self.fail(error.HandshakeFailed);
            return true;
        };
        self.state = .handshaking;
        return true;
    }

    fn driveHandshake(self: *Conn) bool {
        switch (self.handshake_need) {
            .read => if (!self.read_ready) return false,
            .write => if (!self.write_ready) return false,
            .none => {},
        }
        const r = self.stream.handshakeDrive() catch {
            self.fail(error.HandshakeFailed);
            return true;
        };
        switch (r) {
            .done => {
                const v: *platform.Verifier = if (self.owned_verifier) |*ov| ov else self.verifier orelse {
                    self.fail(error.PkiValidationFailed);
                    return true;
                };
                if (!self.stream.verifyPeer(v)) {
                    self.fail(error.PkiValidationFailed);
                    return true;
                }
                self.state = .writing;
                return true;
            },
            .want_read => {
                // OpenSSL's record layer drained the socket to EAGAIN.
                self.handshake_need = .read;
                self.read_ready = false;
                return false;
            },
            .want_write => {
                self.handshake_need = .write;
                self.write_ready = false;
                self.armWrite();
                return false;
            },
        }
    }

    fn driveWrite(self: *Conn) bool {
        if (self.wpos >= self.wq.items.len) {
            self.evp.cancelWrite(self.fd());
            self.state = .read_head;
            self.wq.clearRetainingCapacity();
            self.wpos = 0;
            return true;
        }
        if (self.write_want_read) {
            if (!self.read_ready) return false;
            // Retry below: OpenSSL completes the pending read internally.
        } else if (self.write_blocked) {
            if (!self.write_ready) {
                self.armWrite();
                return false;
            }
        }

        const r = self.stream.writeNb(self.wq.items[self.wpos..]) catch {
            self.fail(error.SocketError);
            return true;
        };
        switch (r) {
            .done => |n| {
                self.wpos += n;
                self.write_blocked = false;
                self.write_want_read = false;
                return true; // more may fit; loop
            },
            .want_write => {
                self.write_blocked = true;
                self.write_ready = false;
                self.armWrite();
                return false;
            },
            .want_read => {
                self.write_want_read = true;
                return false; // read event re-drives
            },
        }
    }

    fn driveRead(self: *Conn) bool {
        var progressed = false;
        if (self.read_want_write) {
            // TLS read needs a writable socket for a control message.
            if (!self.write_ready) {
                self.armWrite();
                return false;
            }
            self.read_want_write = false;
            self.write_ready = false;
            progressed = true;
        }
        if (platform.is_windows) {
            // IOCP is completion-based: there is no read readiness — the
            // conn always keeps a recv outstanding. Pull unconditionally;
            // readNb posts the next recv when the buffer runs dry.
            if (self.drainWire()) progressed = true;
            if (self.closing or self.state == .done) return progressed;
        } else if (self.read_ready) {
            if (self.drainWire()) progressed = true;
            if (self.closing or self.state == .done) return progressed;
        }
        // Parse to quiescence: head→stream transitions must run their
        // buffered bytes through the new state before EOF applies.
        while (!self.closing and self.state != .done) {
            if (!self.parseStep()) break;
            progressed = true;
        }
        if (self.closing or self.state == .done) return progressed;
        // EOF applies only after the buffered bytes were fully parsed.
        if (self.wire_eof) {
            self.finalizeEof();
            progressed = true;
        }
        return progressed;
    }

    fn driveIdle(self: *Conn) bool {
        // Any event on an idle keep-alive conn ends it: EOF (server closed)
        // or unexpected bytes (protocol violation) — either way the bridge
        // drops it from the pool. A stale edge with no data is ignored.
        if (!platform.is_windows and !self.read_ready) return false;
        var tmp: [1024]u8 = undefined;
        const r = self.stream.readNb(&tmp) catch {
            self.state = .done;
            self.handler.onEnd(self.handler.ctx, self, null);
            return false;
        };
        switch (r) {
            // IOCP: the posted recv is outstanding — still idle.
            // POSIX: a stale edge with no data — re-arm.
            .want_read, .want_write => {
                self.read_ready = false;
                return false;
            },
            else => {
                self.state = .done;
                self.handler.onEnd(self.handler.ctx, self, null);
                return false;
            },
        }
    }

    /// Drain the stream into `in` until want_read / eof.
    fn drainWire(self: *Conn) bool {
        var any = false;
        var tmp: [16384]u8 = undefined;
        // POSIX: only pull when a read edge was delivered (EV_CLEAR
        // contract). IOCP: pull unconditionally — readNb keeps a recv
        // outstanding and returns want_read when dry.
        while (platform.is_windows or self.read_ready) {
            const r = self.stream.readNb(&tmp) catch |err| {
                self.fail(switch (err) {
                    error.TlsError => error.TlsError,
                    else => error.SocketError,
                });
                return true;
            };
            switch (r) {
                .data => |n| {
                    if (self.state == .read_head and self.in.items.len > http.MAX_RESPONSE) {
                        self.fail(error.ResponseTooLarge);
                        return true;
                    }
                    self.in.appendSlice(self.alloc, tmp[0..n]) catch {
                        self.fail(error.OutOfMemory);
                        return true;
                    };
                    any = true;
                },
                .want_read => {
                    if (!platform.is_windows) self.read_ready = false;
                    break;
                },
                .want_write => {
                    self.read_want_write = true;
                    if (!platform.is_windows) self.read_ready = false;
                    self.armWrite();
                    break;
                },
                .eof => {
                    // Buffered bytes parse first; finalizeEof applies the
                    // per-state EOF semantics after the last parseStep.
                    self.wire_eof = true;
                    if (!platform.is_windows) self.read_ready = false;
                    break;
                },
            }
        }
        return any;
    }

    /// One parse step over buffered bytes (head, body, or SSE events).
    fn parseStep(self: *Conn) bool {
        const progressed = switch (self.state) {
            .read_head => self.parseHeadStep(),
            .read_body => self.parseBodyStep(),
            .sse_stream => self.parseSseStep(),
            else => false,
        };
        // Compaction is safe here: head slices were duped at parse time and
        // SSE events are owned copies — nothing references `in` afterwards.
        self.compact();
        return progressed;
    }

    fn parseHeadStep(self: *Conn) bool {
        const he = std.mem.indexOf(u8, self.in.items, "\r\n\r\n") orelse return false;
        self.head = parseHead(self.alloc, self.in.items, he) catch {
            self.fail(error.MalformedResponse);
            return true;
        };
        const h = &self.head.?;
        self.pump = .{ .mode = bodyMode(h) };
        self.rpos = he + 4;

        switch (self.role) {
            .post => {
                if (h.is_sse) {
                    self.state = .sse_stream;
                    self.parser = sse.Parser.init(self.alloc);
                } else {
                    self.state = .read_body;
                }
            },
            .sse_get => {
                // Handler calls proceedStream() or close().
                self.handler.onStreamHead(self.handler.ctx, self, h.status, h.is_sse, h.session_id, h.www_authenticate);
            },
        }
        return true;
    }

    fn parseBodyStep(self: *Conn) bool {
        const r = self.pump.feed(self.alloc, self.in.items, &self.rpos, &self.body) catch |err| {
            self.fail(err);
            return true;
        };
        switch (r) {
            .need_more => return false,
            .done => {
                self.finishResponseWith(self.body.items);
                return true;
            },
        }
    }

    fn parseSseStep(self: *Conn) bool {
        // De-frame wire bytes (chunked/until_close) then feed the parser.
        const r = self.pump.feed(self.alloc, self.in.items, &self.rpos, &self.decoded) catch |err| {
            self.fail(err);
            return true;
        };
        var progressed = false;
        if (self.decoded.items.len > 0) {
            progressed = true;
            self.parser.?.feed(self.decoded.items) catch {
                self.fail(error.OutOfMemory);
                return true;
            };
            self.decoded.clearRetainingCapacity();
        }
        if (self.dispatchEvents() > 0) progressed = true;
        if (self.closing or self.state == .done) return true;
        if (r == .done) {
            self.endStream();
            return true;
        }
        return progressed;
    }

    /// Drain complete parser events to the handler. Returns the count.
    fn dispatchEvents(self: *Conn) usize {
        var count: usize = 0;
        while (true) {
            const ev_raw = self.parser.?.next() catch |err| {
                self.fail(err);
                return count;
            } orelse break;
            count += 1;
            var ev = ev_raw;
            defer ev.deinit(self.alloc);

            switch (self.role) {
                .sse_get => self.handler.onEvent(self.handler.ctx, self, &ev),
                .post => |*p| {
                    const is_match = if (p.expect_id) |eid| blk: {
                        const pid = mcp.getRequestId(ev.data) orelse break :blk false;
                        break :blk std.mem.eql(u8, pid, eid);
                    } else true; // notification: first message event wins
                    if (is_match) {
                        self.sse_got_response = true;
                        self.finishResponseWith(ev.data);
                        return count;
                    }
                    self.handler.onEvent(self.handler.ctx, self, &ev);
                },
            }
            if (self.closing or self.state == .done) return count;
        }
        return count;
    }

    /// Stream terminated (chunked terminal chunk or EOF).
    fn endStream(self: *Conn) void {
        self.parser.?.endOfStream();
        _ = self.dispatchEvents();
        if (self.closing or self.state == .done) return;
        self.state = .done;
        switch (self.role) {
            .sse_get => self.handler.onEnd(self.handler.ctx, self, null),
            .post => {
                if (!self.sse_got_response) {
                    self.handler.onEnd(self.handler.ctx, self, error.SseEndedWithoutResponse);
                }
            },
        }
    }

    /// EOF with all buffered bytes parsed: complete or fail per state.
    fn finalizeEof(self: *Conn) void {
        switch (self.state) {
            .read_head => self.fail(error.MalformedResponse),
            .read_body => switch (self.pump.mode) {
                .until_close, .length => self.finishResponseWith(self.body.items), // tolerate early close
                .chunked => self.fail(error.MalformedResponse),
            },
            .sse_stream => self.endStream(),
            .idle => {
                self.state = .done;
                self.handler.onEnd(self.handler.ctx, self, null);
            },
            .connecting, .handshaking, .writing => self.fail(error.SocketError),
            .done => {},
        }
    }

    /// Complete the post role: build the Response and notify. The handler
    /// then calls close() or makeIdle().
    fn finishResponseWith(self: *Conn, resp_body: []const u8) void {
        if (self.state == .done or self.closing) return;
        const h = &self.head.?;
        const body_len = resp_body.len;
        const sid_len: usize = if (h.session_id) |s| s.len else 0;
        const wa_len: usize = if (h.www_authenticate) |s| s.len else 0;

        const backing = self.alloc.alloc(u8, body_len + sid_len + wa_len) catch {
            self.fail(error.OutOfMemory);
            return;
        };
        @memcpy(backing[0..body_len], resp_body);
        var sid: ?[]u8 = null;
        if (h.session_id) |s| {
            @memcpy(backing[body_len..][0..sid_len], s);
            sid = backing[body_len..][0..sid_len];
        }
        var wa: ?[]u8 = null;
        if (h.www_authenticate) |s| {
            @memcpy(backing[body_len + sid_len ..][0..wa_len], s);
            wa = backing[body_len + sid_len ..][0..wa_len];
        }

        self.state = .done;
        self.handler.onResponse(self.handler.ctx, self, .{
            .status = h.status,
            .body = backing[0..body_len],
            .mcp_session_id = sid,
            .www_authenticate = wa,
            .server_closed = h.server_closed or h.is_sse,
            ._backing = backing,
        });
    }

    fn fail(self: *Conn, err: anyerror) void {
        if (self.state == .done or self.closing) return;
        self.state = .done;
        self.handler.onEnd(self.handler.ctx, self, err);
    }

    fn armWrite(self: *Conn) void {
        if (self.closing) return;
        self.evp.wantWrite(self.fd(), self);
    }

    /// Drop consumed bytes so long-lived streams don't grow `in`
    /// unboundedly (the MAX_RESPONSE guard assumes bounded responses).
    fn compact(self: *Conn) void {
        if (self.rpos == 0) return;
        const rest = self.in.items.len - self.rpos;
        if (rest == 0) {
            self.in.clearRetainingCapacity();
        } else {
            std.mem.copyForwards(u8, self.in.items[0..rest], self.in.items[self.rpos..]);
            self.in.items.len = rest;
        }
        self.rpos = 0;
    }
};
