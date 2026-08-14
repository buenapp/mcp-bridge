// User-facing diagnostics channel.
//
// Two message classes:
//   print()  — always-on operational messages (authorize URL, token cached)
//   vprint() — --verbose diagnostics
//
// Sinks:
//   stderr      — suppressed entirely by --silent (mcp-remote parity: the
//                 IDE sees nothing on stderr); vprint additionally needs
//                 --verbose.
//   debug file  — --debug appends EVERYTHING (both classes, regardless of
//                 --verbose/--silent) to <tokens_dir>/<hash>_debug.log,
//                 timestamped, like mcp-remote's ~/.mcp-auth debug logs.
//
// std.log output (log.err et al.) is routed through stdLogFn (wired via
// std_options in main.zig) so it obeys the same rules.

const std = @import("std");
const builtin = @import("builtin");

pub var silent: bool = false;
pub var verbose: bool = false;

var debug_file: ?std.fs.File = null;
var mu: std.Thread.Mutex = .{};

/// Open the --debug log file (append). Failures are silent — diagnostics
/// must never break the bridge.
pub fn openDebugFile(path: []const u8) void {
    if (std.fs.path.dirname(path)) |dir| std.fs.cwd().makePath(dir) catch {};
    const f = std.fs.cwd().createFile(path, .{ .truncate = false }) catch return;
    f.seekFromEnd(0) catch {};
    debug_file = f;
}

pub fn print(comptime fmt: []const u8, args: anytype) void {
    emit(.info, fmt, args);
}

pub fn vprint(comptime fmt: []const u8, args: anytype) void {
    emit(.verbose, fmt, args);
}

const Class = enum { info, verbose };

fn emit(comptime class: Class, comptime fmt: []const u8, args: anytype) void {
    const to_stderr = !silent and (class == .info or verbose);
    if (!to_stderr and debug_file == null) return;

    var buf: [4096]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, fmt, args) catch return;
    if (to_stderr) std.debug.print("{s}", .{msg});
    writeDebugFile(msg);
}

fn writeDebugFile(msg: []const u8) void {
    const f = debug_file orelse return;
    mu.lock();
    defer mu.unlock();
    var tsbuf: [24]u8 = undefined;
    var line: [4352]u8 = undefined;
    const stamped = std.fmt.bufPrint(&line, "[{s}][{d}] {s}", .{ isoNow(&tsbuf), processId(), msg }) catch return;
    f.writeAll(stamped) catch {};
}

/// std.log replacement (std_options.logFn): default level/scope prefix,
/// same silent/debug-file rules as print().
pub fn stdLogFn(
    comptime level: std.log.Level,
    comptime scope: @Type(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    const to_stderr = !silent;
    if (!to_stderr and debug_file == null) return;
    var buf: [4096]u8 = undefined;
    const prefix = if (scope == .default) "" else "(" ++ @tagName(scope) ++ ") ";
    const msg = std.fmt.bufPrint(&buf, level.asText() ++ ": " ++ prefix ++ format ++ "\n", args) catch return;
    if (to_stderr) std.debug.print("{s}", .{msg});
    writeDebugFile(msg);
}

fn processId() u32 {
    if (comptime builtin.os.tag == .windows) {
        const S = struct {
            pub extern "kernel32" fn GetCurrentProcessId() u32;
        };
        return S.GetCurrentProcessId();
    }
    return @intCast(std.c.getpid());
}

fn isoNow(buf: []u8) []const u8 {
    const secs: u64 = @intCast(std.time.timestamp());
    const es: std.time.epoch.EpochSeconds = .{ .secs = secs };
    const year_day = es.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const ds = es.getDaySeconds();
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        year_day.year,
        month_day.month.numeric(),
        month_day.day_index + 1,
        ds.getHoursIntoDay(),
        ds.getMinutesIntoHour(),
        ds.getSecondsIntoMinute(),
    }) catch "0000-00-00T00:00:00Z";
}

// ------------------------------------------------------------------ tests --

test "isoNow shape" {
    var buf: [24]u8 = undefined;
    const s = isoNow(&buf);
    try std.testing.expectEqual(@as(usize, 20), s.len);
    try std.testing.expectEqual(@as(u8, 'T'), s[10]);
    try std.testing.expectEqual(@as(u8, 'Z'), s[19]);
}

test "debug file receives messages while silent suppresses stderr" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realpathAlloc(alloc, ".");
    defer alloc.free(dir);
    const path = try std.fs.path.join(alloc, &.{ dir, "x_debug.log" });
    defer alloc.free(path);

    silent = true;
    verbose = false;
    defer silent = false;
    openDebugFile(path);
    defer {
        debug_file.?.close();
        debug_file = null;
    }
    print("info-line {d}\n", .{1});
    vprint("verbose-line {d}\n", .{2});

    const text = try std.fs.cwd().readFileAlloc(alloc, path, 1 << 16);
    defer alloc.free(text);
    try std.testing.expect(std.mem.indexOf(u8, text, "info-line 1") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "verbose-line 2") != null);
    // timestamp + pid prefix
    try std.testing.expect(std.mem.startsWith(u8, text, "[20"));
}
