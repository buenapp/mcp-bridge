// W3C Server-Sent Events (text/event-stream) parser, incremental.
//
// Shared by the legacy HTTP+SSE transport (2024-11-05 spec), the
// Streamable HTTP standalone GET stream, and the SSE-framed POST
// responses in http.zig. Byte-fed: caller appends wire bytes with
// feed() and drains complete events with next().
//
// Line endings: LF, CRLF, and lone CR are all accepted. A buffer ending
// in '\r' is held back (it may be half of a CRLF split across reads)
// until more bytes arrive or endOfStream() is called.

const std = @import("std");

pub const Event = struct {
    /// Event type ("message" when the stream omitted `event:`). Owned.
    event: []u8,
    /// `data:` lines joined with '\n'. Owned.
    data: []u8,
    /// `id:` field of this event, if any. Owned.
    id: ?[]u8 = null,
    /// `retry:` field (milliseconds), if present and well-formed.
    retry: ?u32 = null,

    pub fn deinit(self: *Event, alloc: std.mem.Allocator) void {
        alloc.free(self.event);
        alloc.free(self.data);
        if (self.id) |i| alloc.free(i);
    }
};

pub const Error = error{OutOfMemory};

pub const Parser = struct {
    alloc: std.mem.Allocator,
    /// Raw bytes not yet consumed.
    buf: std.ArrayList(u8) = .empty,
    /// Accumulators for the event currently being built.
    data: std.ArrayList(u8) = .empty,
    event_type: std.ArrayList(u8) = .empty,
    id_buf: std.ArrayList(u8) = .empty,
    has_id: bool = false,
    retry: ?u32 = null,
    /// Last seen id, persisting across events (Last-Event-ID resumability).
    last_event_id: ?[]u8 = null,
    eof: bool = false,

    pub fn init(alloc: std.mem.Allocator) Parser {
        return .{ .alloc = alloc };
    }

    pub fn deinit(self: *Parser) void {
        self.buf.deinit(self.alloc);
        self.data.deinit(self.alloc);
        self.event_type.deinit(self.alloc);
        self.id_buf.deinit(self.alloc);
        if (self.last_event_id) |i| self.alloc.free(i);
    }

    pub fn feed(self: *Parser, bytes: []const u8) Error!void {
        try self.buf.appendSlice(self.alloc, bytes);
    }

    /// No more bytes will arrive: a trailing '\r' is a complete line ending.
    pub fn endOfStream(self: *Parser) void {
        self.eof = true;
    }

    /// Parse out the next complete event. Returns null when the buffer
    /// holds no complete event yet (feed more bytes). Events with no
    /// `data:` payload are consumed without dispatch (spec behavior; an
    /// id-only event still updates last_event_id).
    pub fn next(self: *Parser) Error!?Event {
        var line_buf: std.ArrayList(u8) = .empty;
        defer line_buf.deinit(self.alloc);
        while (true) {
            const line = try self.takeLine(&line_buf) orelse return null;
            if (line.len == 0) {
                // Blank line: dispatch.
                if (self.data.items.len == 0) {
                    // No data: no event is dispatched, but an id: field
                    // still updates last_event_id (spec behavior).
                    if (self.has_id) {
                        if (self.last_event_id) |old| self.alloc.free(old);
                        self.last_event_id = try self.alloc.dupe(u8, self.id_buf.items);
                    }
                    self.event_type.clearRetainingCapacity();
                    self.has_id = false;
                    self.id_buf.clearRetainingCapacity();
                    self.retry = null;
                    continue;
                }
                return try self.dispatch();
            }
            try self.processLine(line);
        }
    }

    /// Pop one line (without its terminator) off the buffer, or null if
    /// no complete line is buffered. The line is copied into `line_buf`
    /// (consumeLine compacts the buffer, invalidating slices into it).
    fn takeLine(self: *Parser, line_buf: *std.ArrayList(u8)) Error!?[]const u8 {
        var i: usize = 0;
        while (i < self.buf.items.len) : (i += 1) {
            const ch = self.buf.items[i];
            if (ch == '\n') {
                return try self.consumeLine(line_buf, i, 1);
            }
            if (ch == '\r') {
                if (i + 1 >= self.buf.items.len) {
                    // '\r' at buffer end: maybe half a CRLF. Only at EOF
                    // can we treat it as a full terminator.
                    if (!self.eof) return null;
                    return try self.consumeLine(line_buf, i, 1);
                }
                const skip: usize = if (self.buf.items[i + 1] == '\n') 2 else 1;
                return try self.consumeLine(line_buf, i, skip);
            }
        }
        return null;
    }

    fn consumeLine(self: *Parser, line_buf: *std.ArrayList(u8), len: usize, term: usize) Error![]const u8 {
        line_buf.clearRetainingCapacity();
        try line_buf.appendSlice(self.alloc, self.buf.items[0..len]);
        const rest = self.buf.items.len - (len + term);
        std.mem.copyForwards(u8, self.buf.items[0..rest], self.buf.items[len + term ..]);
        self.buf.items.len = rest;
        return line_buf.items;
    }

    fn processLine(self: *Parser, line: []const u8) Error!void {
        if (line[0] == ':') return; // comment
        var field: []const u8 = line;
        var value: []const u8 = "";
        if (std.mem.indexOfScalar(u8, line, ':')) |colon| {
            field = line[0..colon];
            value = line[colon + 1 ..];
            if (value.len > 0 and value[0] == ' ') value = value[1..];
        }
        if (std.mem.eql(u8, field, "data")) {
            try self.data.appendSlice(self.alloc, value);
            try self.data.append(self.alloc, '\n');
        } else if (std.mem.eql(u8, field, "event")) {
            self.event_type.clearRetainingCapacity();
            try self.event_type.appendSlice(self.alloc, value);
        } else if (std.mem.eql(u8, field, "id")) {
            if (std.mem.indexOfScalar(u8, value, 0) == null) {
                self.id_buf.clearRetainingCapacity();
                try self.id_buf.appendSlice(self.alloc, value);
                self.has_id = true;
            }
        } else if (std.mem.eql(u8, field, "retry")) {
            if (value.len > 0 and value.len <= 10) {
                var digits = true;
                for (value) |d| {
                    if (!std.ascii.isDigit(d)) {
                        digits = false;
                        break;
                    }
                }
                if (digits) self.retry = std.fmt.parseInt(u32, value, 10) catch null;
            }
        }
        // Unknown fields are ignored per spec.
    }

    fn dispatch(self: *Parser) Error!Event {
        // Data accumulator holds a trailing '\n' per spec; drop it.
        var data = self.data.items;
        if (data.len > 0 and data[data.len - 1] == '\n') data = data[0 .. data.len - 1];

        const ev: Event = .{
            .event = try self.alloc.dupe(u8, if (self.event_type.items.len > 0) self.event_type.items else "message"),
            .data = try self.alloc.dupe(u8, data),
            .id = if (self.has_id) try self.alloc.dupe(u8, self.id_buf.items) else null,
            .retry = self.retry,
        };

        if (self.has_id) {
            if (self.last_event_id) |old| self.alloc.free(old);
            self.last_event_id = try self.alloc.dupe(u8, self.id_buf.items);
        }

        self.data.clearRetainingCapacity();
        self.event_type.clearRetainingCapacity();
        self.id_buf.clearRetainingCapacity();
        self.has_id = false;
        self.retry = null;
        return ev;
    }
};

// --------------------------------------------------------------- tests ----

test "basic message event" {
    var p = Parser.init(std.testing.allocator);
    defer p.deinit();
    try p.feed("data: hello\n\n");
    var ev = (try p.next()).?;
    defer ev.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("message", ev.event);
    try std.testing.expectEqualStrings("hello", ev.data);
    try std.testing.expect(ev.id == null);
    try std.testing.expect((try p.next()) == null);
}

test "multi-line data joined with newline" {
    var p = Parser.init(std.testing.allocator);
    defer p.deinit();
    try p.feed("data: line1\ndata: line2\ndata:\n\n");
    var ev = (try p.next()).?;
    defer ev.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("line1\nline2\n", ev.data);
}

test "CRLF and lone CR line endings" {
    var p = Parser.init(std.testing.allocator);
    defer p.deinit();
    try p.feed("data: a\r\n\r\ndata: b\r\r");
    var e1 = (try p.next()).?;
    defer e1.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("a", e1.data);
    // Trailing '\r' is ambiguous (could be half a CRLF) until EOF.
    try std.testing.expect((try p.next()) == null);
    p.endOfStream();
    var e2 = (try p.next()).?;
    defer e2.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("b", e2.data);
}

test "event type and id, last-event-id persistence" {
    var p = Parser.init(std.testing.allocator);
    defer p.deinit();
    try p.feed("event: endpoint\nid: 42\ndata: /messages?session_id=xyz\n\n");
    var ev = (try p.next()).?;
    defer ev.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("endpoint", ev.event);
    try std.testing.expectEqualStrings("/messages?session_id=xyz", ev.data);
    try std.testing.expectEqualStrings("42", ev.id.?);
    try std.testing.expectEqualStrings("42", p.last_event_id.?);

    // Next event without id: last_event_id persists, event id is null.
    try p.feed("data: next\n\n");
    var e2 = (try p.next()).?;
    defer e2.deinit(std.testing.allocator);
    try std.testing.expect(e2.id == null);
    try std.testing.expectEqualStrings("42", p.last_event_id.?);
}

test "comments and unknown fields ignored" {
    var p = Parser.init(std.testing.allocator);
    defer p.deinit();
    try p.feed(": keepalive\nfoo: bar\nbarefield\ndata: x\n\n");
    var ev = (try p.next()).?;
    defer ev.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("x", ev.data);
}

test "id-only event updates last_event_id without dispatch" {
    var p = Parser.init(std.testing.allocator);
    defer p.deinit();
    try p.feed("id: 7\n\ndata: real\n\n");
    var ev = (try p.next()).?;
    defer ev.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("real", ev.data);
    try std.testing.expectEqualStrings("7", p.last_event_id.?);
}

test "retry field parsed" {
    var p = Parser.init(std.testing.allocator);
    defer p.deinit();
    try p.feed("retry: 3000\ndata: x\n\n");
    var ev = (try p.next()).?;
    defer ev.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(?u32, 3000), ev.retry);
}

test "byte-by-byte feed, CRLF split across reads" {
    var p = Parser.init(std.testing.allocator);
    defer p.deinit();
    const wire = "data: split\r\n\r\n";
    for (wire, 0..) |byte, idx| {
        try p.feed(&[_]u8{byte});
        const maybe = try p.next();
        if (idx + 1 < wire.len) {
            try std.testing.expect(maybe == null);
        } else {
            var ev = maybe.?;
            defer ev.deinit(std.testing.allocator);
            try std.testing.expectEqualStrings("split", ev.data);
        }
    }
}

test "no leading-space strip beyond one, and eof flush of trailing CR" {
    var p = Parser.init(std.testing.allocator);
    defer p.deinit();
    // data line ends with a lone CR, then a blank lone-CR line; the final
    // '\r' stays ambiguous (could be half a CRLF) until endOfStream().
    try p.feed("data:  two spaces kept\r\r");
    try std.testing.expect((try p.next()) == null);
    p.endOfStream();
    var ev = (try p.next()).?;
    defer ev.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings(" two spaces kept", ev.data);
}

test "json-rpc payload pass-through" {
    var p = Parser.init(std.testing.allocator);
    defer p.deinit();
    const payload = "{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{}}";
    try p.feed("event: message\ndata: " ++ payload ++ "\n\n");
    var ev = (try p.next()).?;
    defer ev.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("message", ev.event);
    try std.testing.expectEqualStrings(payload, ev.data);
}
