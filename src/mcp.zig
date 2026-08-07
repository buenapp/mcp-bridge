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
