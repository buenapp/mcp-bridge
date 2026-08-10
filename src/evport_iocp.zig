// Windows event port: IOCP backend (issue #7).
//
// Same contract as the kqueue/epoll backends, with the completion-model
// differences handled here:
//   - No readiness registration: monitorRead(fd, udata) ASSOCIATES the
//     handle (socket) with the port; wantWrite/cancelWrite are no-ops
//     (overlapped sends are posted by the stream layer and always
//     complete). purgeFd is a no-op (closesocket/CancelIoEx teardown is
//     the stream layer's job).
//   - Events carry the completion key (udata) plus the raw OVERLAPPED
//     pointer and byte count; the owning conn classifies which operation
//     completed by comparing OVERLAPPED addresses (nb_win.zig).
//   - wait() harvests a batch in ONE GetQueuedCompletionStatusEx call.
//   - Cross-thread wakeup: PostQueuedCompletionStatus with the wake key.
//   - stdio relay threads (libuv pattern for blocking pipes) post their
//     chunks here via PQCS with the caller-chosen key.

const std = @import("std");
const windows = std.os.windows;
const kernel32 = windows.kernel32;

pub const Event = struct {
    udata: ?*anyopaque = null,
    readable: bool = false, // unused on IOCP (the conn classifies)
    writable: bool = false, // unused on IOCP
    eof: bool = false,
    err: bool = false,
    err_no: usize = 0, // NTSTATUS from the completion's Internal field
    wake: bool = false,
    /// Which operation completed (conn classifies by address). Null when
    /// the completion carries no op (relay posts).
    overlapped: ?*windows.OVERLAPPED = null,
    bytes: usize = 0,
};

pub const Error = error{
    InitFailed,
    WaitFailed,
    OutOfMemory,
};

pub const EvPort = struct {
    iocp: windows.HANDLE = windows.INVALID_HANDLE_VALUE,

    pub fn init(alloc: std.mem.Allocator) Error!EvPort {
        _ = alloc;
        const port = kernel32.CreateIoCompletionPort(windows.INVALID_HANDLE_VALUE, null, 0, 0) orelse
            return Error.InitFailed;
        return .{ .iocp = port };
    }

    pub fn deinit(self: *EvPort) void {
        if (self.iocp != windows.INVALID_HANDLE_VALUE) _ = windows.CloseHandle(self.iocp);
        self.iocp = windows.INVALID_HANDLE_VALUE;
    }

    /// Associate a handle with the port (sockets at conn start; the
    /// overlappable stdin pipe when present). No-op bookkeeping otherwise.
    pub fn monitorRead(self: *EvPort, handle: windows.HANDLE, udata: ?*anyopaque) void {
        _ = kernel32.CreateIoCompletionPort(handle, self.iocp, @intFromPtr(udata), 0);
    }

    /// Writes are driven by the stream layer's overlapped sends; interest
    /// registration does not exist on IOCP.
    pub fn wantWrite(self: *EvPort, fd: anytype, udata: ?*anyopaque) void {
        _ = self;
        _ = fd;
        _ = udata;
    }

    pub fn cancelWrite(self: *EvPort, fd: anytype) void {
        _ = self;
        _ = fd;
    }

    pub fn unmonitorRead(self: *EvPort, fd: anytype) void {
        _ = self;
        _ = fd;
    }

    pub fn purgeFd(self: *EvPort, fd: anytype) void {
        _ = self;
        _ = fd;
    }

    /// Wake a wait() blocked anywhere (relay threads, future helpers).
    pub fn wake(self: *EvPort) void {
        self.post(&wake_sentinel, null, 0);
    }

    /// Post a completion with an arbitrary key (stdio relay threads use
    /// their sentinel addresses; overlapped may be null).
    pub fn post(self: *EvPort, key: *anyopaque, overlapped: ?*windows.OVERLAPPED, bytes: usize) void {
        _ = kernel32.PostQueuedCompletionStatus(self.iocp, @intCast(bytes), @intFromPtr(key), overlapped);
    }

    pub fn wakeKey() *anyopaque {
        return &wake_sentinel;
    }

    /// Harvest one batch of completions in ONE GetQueuedCompletionStatusEx
    /// call. timeout_ms: null = block until a completion; 0 = don't block.
    pub fn wait(self: *EvPort, events: []Event, timeout_ms: ?i32) Error!usize {
        var entries: [64]windows.OVERLAPPED_ENTRY = undefined;
        const cap = @min(events.len, entries.len);
        var removed: u32 = 0;
        const ms: u32 = if (timeout_ms) |t| @intCast(@max(t, 0)) else 0xFFFFFFFF; // INFINITE
        const ok = kernel32.GetQueuedCompletionStatusEx(self.iocp, &entries, @intCast(cap), &removed, ms, 0);
        if (ok == 0) {
            const err = windows.GetLastError();
            if (err == .WAIT_TIMEOUT) return 0;
            return Error.WaitFailed;
        }

        for (entries[0..removed], 0..) |entry, i| {
            const key: ?*anyopaque = @ptrFromInt(entry.lpCompletionKey);
            if (key == @as(?*anyopaque, &wake_sentinel)) {
                events[i] = .{ .wake = true };
                continue;
            }
            const internal = entry.Internal;
            events[i] = .{
                .udata = key,
                .overlapped = entry.lpOverlapped,
                .bytes = entry.dwNumberOfBytesTransferred,
                .err = internal != 0,
                .err_no = internal,
            };
        }
        return removed;
    }
};

/// Stable address used as the wake key.
var wake_sentinel: u8 = 0;
