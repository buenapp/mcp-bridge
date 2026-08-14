// MCP protocol glue for the stdio bridge: JSON-RPC id extraction and
// error synthesis. Minimal scanning (GodotMCP mcp.zig pattern).

const std = @import("std");

/// Extract the raw JSON value of "id" (number, string-with-quotes, or null).
/// Returns null if no id present (notification).
pub fn getRequestId(json: []const u8) ?[]const u8 {
    var i: usize = 0;
    while (i + 5 < json.len) : (i += 1) {
        if (json[i] == '"' and std.mem.eql(u8, json[i .. i + 4], "\"id\"")) {
            var j = i + 4;
            while (j < json.len and (json[j] == ':' or json[j] == ' ' or json[j] == '\t')) j += 1;
            if (j >= json.len) return null;

            if (json[j] == '"') {
                const start = j;
                j += 1;
                while (j < json.len and json[j] != '"') {
                    if (json[j] == '\\') j += 1;
                    j += 1;
                }
                if (j < json.len) return json[start .. j + 1];
                return null;
            }
            const start = j;
            while (j < json.len and json[j] != ',' and json[j] != '}' and json[j] != ']') j += 1;
            return std.mem.trim(u8, json[start..j], " \t");
        }
    }
    return null;
}

/// Synthesize a JSON-RPC error response for a request we couldn't deliver.
pub fn formatTransportError(buf: []u8, id: ?[]const u8, msg: []const u8) []const u8 {
    const id_str = id orelse "null";
    return std.fmt.bufPrint(
        buf,
        "{{\"jsonrpc\":\"2.0\",\"id\":{s},\"error\":{{\"code\":-32603,\"message\":\"bridge transport error: {s}\"}}}}",
        .{ id_str, msg },
    ) catch "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32603,\"message\":\"bridge transport error\"}}";
}

// ------------------------------------------------------- tool filtering --

/// Glob match (mcp-remote --ignore-tool parity): '*' matches any run of
/// characters; case-insensitive; anchored at both ends.
pub fn globMatch(pattern: []const u8, name: []const u8) bool {
    return globAt(pattern, 0, name, 0);
}

fn globAt(p: []const u8, pi: usize, n: []const u8, ni: usize) bool {
    var p_i = pi;
    var n_i = ni;
    var star: ?usize = null;
    var star_n: usize = 0;
    while (n_i < n.len) {
        if (p_i < p.len and (std.ascii.toLower(p[p_i]) == std.ascii.toLower(n[n_i]))) {
            p_i += 1;
            n_i += 1;
        } else if (p_i < p.len and p[p_i] == '*') {
            star = p_i;
            star_n = n_i;
            p_i += 1;
        } else if (star) |s| {
            p_i = s + 1;
            star_n += 1;
            n_i = star_n;
        } else {
            return false;
        }
    }
    while (p_i < p.len and p[p_i] == '*') p_i += 1;
    return p_i == p.len;
}

/// Should this tool be hidden from / blocked for the client?
pub fn toolIgnored(patterns: []const []const u8, name: []const u8) bool {
    for (patterns) |p| {
        if (globMatch(p, name)) return true;
    }
    return false;
}

/// If `line` is a tools/call request, return its params.name (points into
/// memory owned by the returned parse guard — keep it alive while in use).
pub fn toolCallName(alloc: std.mem.Allocator, line: []const u8, guard: *?std.json.Parsed(std.json.Value)) ?[]const u8 {
    guard.* = std.json.parseFromSlice(std.json.Value, alloc, line, .{}) catch return null;
    const obj = switch (guard.*.?.value) {
        .object => |o| o,
        else => return null,
    };
    const method = switch (obj.get("method") orelse return null) {
        .string => |s| s,
        else => return null,
    };
    if (!std.mem.eql(u8, method, "tools/call")) return null;
    const params = switch (obj.get("params") orelse return null) {
        .object => |o| o,
        else => return null,
    };
    return switch (params.get("name") orelse return null) {
        .string => |s| if (s.len > 0) s else null,
        else => null,
    };
}

/// Filter ignored tools out of a tools/list RESPONSE body. Returns null
/// when the payload is not a tools/list result (callers forward it
/// unchanged). On a match, returns a re-serialized response (owned).
pub fn filterToolsList(alloc: std.mem.Allocator, payload: []const u8, patterns: []const []const u8) !?[]u8 {
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const a = arena.allocator();

    const parsed = try std.json.parseFromSlice(std.json.Value, a, payload, .{});
    var obj = switch (parsed.value) {
        .object => |o| o,
        else => return null,
    };
    var result = switch (obj.get("result") orelse return null) {
        .object => |o| o,
        else => return null,
    };
    const tools = switch (result.get("tools") orelse return null) {
        .array => |arr| arr,
        else => return null,
    };

    var kept = std.json.Array.init(a);
    var removed: usize = 0;
    for (tools.items) |tool| {
        const tobj = switch (tool) {
            .object => |o| o,
            else => {
                try kept.append(tool);
                continue;
            },
        };
        const name = switch (tobj.get("name") orelse .null) {
            .string => |s| s,
            else => {
                try kept.append(tool);
                continue;
            },
        };
        if (toolIgnored(patterns, name)) {
            removed += 1;
            continue;
        }
        try kept.append(tool);
    }
    if (removed == 0) return null; // nothing to change — forward as-is

    // obj/result are map COPIES sharing storage with the parsed tree; put
    // may reallocate, so serialize the mutated copies, not parsed.value.
    try result.put("tools", .{ .array = kept });
    try obj.put("result", .{ .object = result });
    return try std.json.Stringify.valueAlloc(alloc, std.json.Value{ .object = obj }, .{});
}
