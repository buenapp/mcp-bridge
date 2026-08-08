// TLS client over Windows SChannel (secur32.dll) with manual certificate
// validation hook (DANE first, Windows root store PKI fallback).
//
// Handshake/decrypt carryover pattern follows the well-known SChannel
// streaming reference (extra-buffer handling for SECBUFFER_EXTRA,
// SEC_E_INCOMPLETE_MESSAGE accumulation).

const std = @import("std");
const win = @import("win.zig");
const dane = @import("dane.zig");
const dns = @import("dns.zig");

const ws2 = win.ws2;
const log = std.log.scoped(.schannel);

pub var verbose: bool = false;

fn vprint(comptime fmt: []const u8, args: anytype) void {
    if (verbose) std.debug.print(fmt, args);
}

pub const TlsError = error{
    WsaStartup,
    SocketCreate,
    ConnectFailed,
    CredentialAcquire,
    HandshakeFailed,
    NoRemoteCert,
    ChainBuildFailed,
    DaneValidationFailed,
    PkiValidationFailed,
    TlsClosed,
    TlsError,
    Timeout,
    OutOfMemory,
    Utf16Conversion,
};

pub const VerifyInfo = struct {
    dane_result: dane.DaneResult,
    tlsa_count: usize,
    used_pki_fallback: bool,
};

pub const TlsStream = struct {
    sock: ws2.SOCKET = win.INVALID_SOCKET,
    cred: win.CredHandle = .{},
    ctx: win.CtxtHandle = .{},
    have_ctx: bool = false,
    sizes: win.SecPkgContext_StreamSizes = std.mem.zeroes(win.SecPkgContext_StreamSizes),
    // carryover decrypted data from an over-read TLS record
    pending: std.ArrayList(u8) = .empty,
    // encrypted accumulation buffer
    enc_buf: std.ArrayList(u8) = .empty,
    alloc: std.mem.Allocator,

    pub fn deinit(self: *TlsStream) void {
        if (self.have_ctx) _ = win.DeleteSecurityContext(&self.ctx);
        _ = win.FreeCredentialsHandle(&self.cred);
        if (self.sock != win.INVALID_SOCKET) _ = ws2.closesocket(self.sock);
        self.pending.deinit(self.alloc);
        self.enc_buf.deinit(self.alloc);
    }

    /// Read decrypted application data. Returns 0 on clean close.
    pub fn read(self: *TlsStream, out: []u8) TlsError!usize {
        // Serve from carryover first
        if (self.pending.items.len > 0) {
            const n = @min(out.len, self.pending.items.len);
            @memcpy(out[0..n], self.pending.items[0..n]);
            // shift remainder
            const rem = self.pending.items.len - n;
            std.mem.copyForwards(u8, self.pending.items[0..rem], self.pending.items[n..]);
            self.pending.items.len = rem;
            return n;
        }

        while (true) {
            // Try to decrypt what we already have buffered
            switch (try self.tryDecrypt(out)) {
                .data => |n| return n,
                .closed => return 0,
                .need_more => {},
            }

            // Read more ciphertext from the socket
            var tmp: [16384]u8 = undefined;
            const n = ws2.recv(self.sock, tmp[0..].ptr, @intCast(tmp.len), 0);
            if (n == 0) return 0; // TCP closed
            if (n == ws2.SOCKET_ERROR) {
                if (@intFromEnum(ws2.WSAGetLastError()) == win.WSAETIMEDOUT) return TlsError.Timeout;
                return TlsError.TlsError;
            }
            self.enc_buf.appendSlice(self.alloc, tmp[0..@intCast(n)]) catch return TlsError.OutOfMemory;
        }
    }

    const DecryptOutcome = union(enum) { data: usize, closed, need_more };

    fn tryDecrypt(self: *TlsStream, out: []u8) TlsError!DecryptOutcome {
        if (self.enc_buf.items.len == 0) return .need_more;

        var bufs = [4]win.SecBuffer{
            .{ .cbBuffer = @intCast(self.enc_buf.items.len), .BufferType = win.SECBUFFER_DATA, .pvBuffer = self.enc_buf.items.ptr },
            .{ .cbBuffer = 0, .BufferType = win.SECBUFFER_EMPTY, .pvBuffer = null },
            .{ .cbBuffer = 0, .BufferType = win.SECBUFFER_EMPTY, .pvBuffer = null },
            .{ .cbBuffer = 0, .BufferType = win.SECBUFFER_EMPTY, .pvBuffer = null },
        };
        var desc = win.SecBufferDesc{ .ulVersion = win.SECBUFFER_VERSION, .cBuffers = 4, .pBuffers = &bufs };

        const status = win.DecryptMessage(&self.ctx, &desc, 0, null);

        if (status == win.SEC_E_INCOMPLETE_MESSAGE) return .need_more;

        if (status == win.SEC_I_CONTEXT_EXPIRED or status == win.SEC_E_OK) {
            // Locate data / extra buffers
            var data_len: usize = 0;
            var data_ptr: [*]u8 = undefined;
            var have_data = false;
            var extra_off: ?usize = null;

            for (bufs) |b| {
                switch (b.BufferType) {
                    win.SECBUFFER_DATA => {
                        if (b.cbBuffer > 0 and !have_data) {
                            if (b.pvBuffer) |bp| {
                                data_ptr = @ptrCast(bp);
                                data_len = b.cbBuffer;
                                have_data = true;
                            }
                        }
                    },
                    win.SECBUFFER_EXTRA => {
                        // pvBuffer may be null; EXTRA is a suffix of input.
                        extra_off = self.enc_buf.items.len - @min(b.cbBuffer, self.enc_buf.items.len);
                    },
                    else => {},
                }
            }

            if (have_data) {
                const n = @min(out.len, data_len);
                @memcpy(out[0..n], data_ptr[0..n]);
                if (data_len > n) {
                    self.pending.appendSlice(self.alloc, data_ptr[n..data_len]) catch return TlsError.OutOfMemory;
                }
            }

            // Compact enc_buf: EXTRA bytes are a SUFFIX of the input.
            if (extra_off) |off| {
                const keep = self.enc_buf.items.len - off;
                std.mem.copyForwards(u8, self.enc_buf.items[0..keep], self.enc_buf.items[off..]);
                self.enc_buf.items.len = keep;
            } else {
                self.enc_buf.clearRetainingCapacity();
            }

            if (have_data) return .{ .data = @intCast(@min(out.len, data_len)) };
            if (status == win.SEC_I_CONTEXT_EXPIRED) return .closed;
            return .need_more; // decrypted zero-length (e.g. renegotiation); loop
        }

        log.err("DecryptMessage failed: 0x{x:0>8}", .{@as(u32, @bitCast(status))});
        return TlsError.TlsError;
    }

    /// Write plaintext, encrypting per SChannel stream framing.
    pub fn writeAll(self: *TlsStream, data: []const u8) TlsError!void {
        const header = self.sizes.cbHeader;
        const trailer = self.sizes.cbTrailer;
        const max_msg = self.sizes.cbMaximumMessage;
        if (max_msg == 0) return TlsError.TlsError;

        var off: usize = 0;
        while (off < data.len) {
            const chunk = @min(max_msg, data.len - off);
            const buf_len = header + chunk + trailer;
            const buf = self.alloc.alloc(u8, buf_len) catch return TlsError.OutOfMemory;
            defer self.alloc.free(buf);

            @memcpy(buf[header .. header + chunk], data[off .. off + chunk]);

            var bufs = [4]win.SecBuffer{
                .{ .cbBuffer = header, .BufferType = win.SECBUFFER_STREAM_HEADER, .pvBuffer = buf.ptr },
                .{ .cbBuffer = @intCast(chunk), .BufferType = win.SECBUFFER_DATA, .pvBuffer = buf.ptr + header },
                .{ .cbBuffer = trailer, .BufferType = win.SECBUFFER_STREAM_TRAILER, .pvBuffer = buf.ptr + header + chunk },
                .{ .cbBuffer = 0, .BufferType = win.SECBUFFER_EMPTY, .pvBuffer = null },
            };
            var desc = win.SecBufferDesc{ .ulVersion = win.SECBUFFER_VERSION, .cBuffers = 4, .pBuffers = &bufs };

            const status = win.EncryptMessage(&self.ctx, 0, &desc, 0);
            if (!win.SUCCEEDED(status)) {
                log.err("EncryptMessage failed: 0x{x:0>8}", .{@as(u32, @bitCast(status))});
                return TlsError.TlsError;
            }

            const total: usize = bufs[0].cbBuffer + bufs[1].cbBuffer + bufs[2].cbBuffer;
            try self.sendRaw(buf[0..total]);
            off += chunk;
        }
    }

    pub fn closeNotify(self: *TlsStream) void {
        var out_buf: [256]u8 = undefined;
        var status_token: win.DWORD = win.SCHANNEL_SHUTDOWN;
        var in_bufs = [1]win.SecBuffer{
            .{ .cbBuffer = @sizeOf(u32), .BufferType = win.SECBUFFER_TOKEN, .pvBuffer = @constCast(&status_token) },
        };
        var in_desc = win.SecBufferDesc{ .ulVersion = win.SECBUFFER_VERSION, .cBuffers = 1, .pBuffers = &in_bufs };
        _ = win.ApplyControlToken(&self.ctx, &in_desc);

        var attrs: win.DWORD = 0;
        var out = [1]win.SecBuffer{
            .{ .cbBuffer = out_buf.len, .BufferType = win.SECBUFFER_TOKEN, .pvBuffer = &out_buf },
        };
        var out_desc = win.SecBufferDesc{ .ulVersion = win.SECBUFFER_VERSION, .cBuffers = 1, .pBuffers = &out };
        var ctx2: win.CtxtHandle = .{};
        const status = win.InitializeSecurityContextW(
            &self.cred,
            &self.ctx,
            null,
            win.ISC_FLAGS,
            0,
            win.SECURITY_NATIVE_DREP,
            null,
            0,
            &ctx2,
            &out_desc,
            &attrs,
            null,
        );
        if (win.SUCCEEDED(status) and out[0].cbBuffer > 0) {
            self.sendRaw(out_buf[0..out[0].cbBuffer]) catch {};
        }
    }

    fn sendRaw(self: *TlsStream, data: []const u8) TlsError!void {
        var off: usize = 0;
        while (off < data.len) {
            const n = ws2.send(self.sock, data.ptr + off, @intCast(data.len - off), 0);
            if (n <= 0) return TlsError.TlsError;
            off += @intCast(n);
        }
    }
};

/// Connect TCP + TLS handshake with manual cert validation.
/// `verify` is invoked with the leaf CERT_CONTEXT; it must return true to proceed.
pub fn connect(
    alloc: std.mem.Allocator,
    host: []const u8,
    port: u16,
    verify_ctx: *anyopaque,
    verify_fn: *const fn (ctx: *anyopaque, leaf: *win.CERT_CONTEXT) bool,
) TlsError!TlsStream {
    var stream = TlsStream{ .alloc = alloc };
    errdefer stream.deinit();

    vprint("mcp-bridge: [tls] resolving {s}:{d}\n", .{ host, port });

    // WSAStartup
    var wsa: ws2.WSADATA = undefined;
    if (ws2.WSAStartup(0x0202, &wsa) != 0) return TlsError.WsaStartup;

    // TCP connect (IPv4, getaddrinfo via std for resolution)
    const addr_list = std.net.getAddressList(alloc, host, port) catch return TlsError.ConnectFailed;
    defer addr_list.deinit();
    if (addr_list.addrs.len == 0) return TlsError.ConnectFailed;

    var connected = false;
    for (addr_list.addrs) |addr| {
        const s = ws2.socket(addr.any.family, ws2.SOCK.STREAM, 0);
        if (s == win.INVALID_SOCKET) continue;
        const rc = ws2.connect(s, &addr.any, @intCast(addr.getOsSockLen()));
        if (rc == 0) {
            stream.sock = s;
            connected = true;
            break;
        }
        _ = ws2.closesocket(s);
    }
    if (!connected) return TlsError.ConnectFailed;
    win.setTimeouts(stream.sock, 30_000, 15_000);
    vprint("mcp-bridge: [tls] tcp connected\n", .{});

    // Acquire credentials (manual validation — we verify ourselves)
    var scred: win.SCHANNEL_CRED = std.mem.zeroes(win.SCHANNEL_CRED);
    scred.dwVersion = win.SCHANNEL_CRED_VERSION;
    scred.dwFlags = win.SCH_CRED_MANUAL_CRED_VALIDATION | win.SCH_CRED_NO_DEFAULT_CREDS;
    scred.grbitEnabledProtocols = win.SP_PROT_TLS1_2 | win.SP_PROT_TLS1_3;

    var status = win.AcquireCredentialsHandleW(
        null,
        win.SCHANNEL_NAME_W.ptr,
        win.SECPKG_CRED_OUTBOUND,
        null,
        &scred,
        null,
        null,
        &stream.cred,
        null,
    );
    if (!win.SUCCEEDED(status)) {
        log.err("AcquireCredentialsHandleW failed: 0x{x:0>8}", .{@as(u32, @bitCast(status))});
        return TlsError.CredentialAcquire;
    }
    vprint("mcp-bridge: [tls] credentials acquired, handshaking\n", .{});

    // Handshake loop
    const host_w = win.utf16Z(alloc, host) catch return TlsError.Utf16Conversion;
    defer alloc.free(host_w);

    try handshake(&stream, host_w);

    vprint("mcp-bridge: [tls] handshake complete\n", .{});

    // Stream sizes for encrypt/decrypt framing
    status = win.QueryContextAttributesW(&stream.ctx, win.SECPKG_ATTR_STREAM_SIZES, &stream.sizes);
    if (!win.SUCCEEDED(status)) return TlsError.HandshakeFailed;

    // Certificate verification hook
    var remote_cert: win.PCCERT_CONTEXT = null;
    status = win.QueryContextAttributesW(&stream.ctx, win.SECPKG_ATTR_REMOTE_CERT_CONTEXT, @ptrCast(&remote_cert));
    if (!win.SUCCEEDED(status) or remote_cert == null) {
        log.err("no remote cert context: 0x{x:0>8}", .{@as(u32, @bitCast(status))});
        return TlsError.NoRemoteCert;
    }
    defer _ = win.CertFreeCertificateContext(remote_cert);

    vprint("mcp-bridge: [tls] verifying certificate\n", .{});
    if (!verify_fn(verify_ctx, remote_cert.?)) return TlsError.PkiValidationFailed;
    vprint("mcp-bridge: [tls] certificate accepted\n", .{});

    return stream;
}

fn handshake(stream: *TlsStream, host_w: [:0]const u16) TlsError!void {
    var in_data: std.ArrayList(u8) = .empty;
    defer in_data.deinit(stream.alloc);

    var have_ctx = false;
    var attrs: win.DWORD = 0;

    // Initial call produces the first token (client hello)
    var need_initial = true;

    while (true) {
        var in_bufs = [2]win.SecBuffer{
            .{ .cbBuffer = @intCast(in_data.items.len), .BufferType = win.SECBUFFER_TOKEN, .pvBuffer = if (in_data.items.len > 0) in_data.items.ptr else null },
            .{ .cbBuffer = 0, .BufferType = win.SECBUFFER_EMPTY, .pvBuffer = null },
        };
        var in_desc = win.SecBufferDesc{ .ulVersion = win.SECBUFFER_VERSION, .cBuffers = 2, .pBuffers = &in_bufs };

        var out_buf = [1]win.SecBuffer{
            .{ .cbBuffer = 0, .BufferType = win.SECBUFFER_TOKEN, .pvBuffer = null },
        };
        var out_desc = win.SecBufferDesc{ .ulVersion = win.SECBUFFER_VERSION, .cBuffers = 1, .pBuffers = &out_buf };

        var new_ctx: win.CtxtHandle = .{};
        const status = win.InitializeSecurityContextW(
            &stream.cred,
            if (have_ctx) &stream.ctx else null,
            if (have_ctx) null else host_w.ptr, // target name (SNI) on first call
            win.ISC_FLAGS,
            0,
            win.SECURITY_NATIVE_DREP,
            if (need_initial) null else &in_desc,
            0,
            &new_ctx,
            &out_desc,
            &attrs,
            null,
        );
        need_initial = false;
        stream.ctx = new_ctx;
        have_ctx = true;
        vprint("mcp-bridge: [tls] ISC status 0x{x:0>8} (input {d} bytes buffered)\n", .{ @as(u32, @bitCast(status)), in_data.items.len });

        vprint("mcp-bridge: [tls] in[1] type={d} size={d} ptr={*} out[0] type={d} size={d} ptr={*}\n", .{
            in_bufs[1].BufferType,
            in_bufs[1].cbBuffer,
            in_bufs[1].pvBuffer,
            out_buf[0].BufferType,
            out_buf[0].cbBuffer,
            out_buf[0].pvBuffer,
        });

        // Consume input: EXTRA buffer marks leftover bytes.
        // NOTE: SChannel may report EXTRA with a null pvBuffer; the
        // leftover is always a SUFFIX of the input buffer, so compute
        // the offset from cbBuffer instead of trusting the pointer.
        if (in_bufs[1].BufferType == win.SECBUFFER_EXTRA and in_bufs[1].cbBuffer > 0) {
            const keep: usize = @min(in_bufs[1].cbBuffer, in_data.items.len);
            const off = in_data.items.len - keep;
            std.mem.copyForwards(u8, in_data.items[0..keep], in_data.items[off..]);
            in_data.items.len = keep;
        } else if (status != win.SEC_E_INCOMPLETE_MESSAGE) {
            in_data.clearRetainingCapacity();
        }

        // Send output token if present
        if (out_buf[0].pvBuffer != null and out_buf[0].cbBuffer > 0) {
            const p: [*]u8 = @ptrCast(out_buf[0].pvBuffer.?);
            stream.sendRaw(p[0..out_buf[0].cbBuffer]) catch {
                _ = win.FreeContextBuffer(out_buf[0].pvBuffer);
                return TlsError.HandshakeFailed;
            };
        }
        if (out_buf[0].pvBuffer != null) _ = win.FreeContextBuffer(out_buf[0].pvBuffer);

        if (status == win.SEC_E_OK) {
            // Handshake complete. Any EXTRA leftover is post-handshake ciphertext
            // that belongs to DecryptMessage — stash it in enc_buf.
            if (in_bufs[1].BufferType == win.SECBUFFER_EXTRA and in_bufs[1].cbBuffer > 0) {
                // Suffix of in_data (pvBuffer may be null — see above).
                // in_data was already compacted above, so EXTRA bytes are
                // the whole remaining in_data.
                stream.enc_buf.appendSlice(stream.alloc, in_data.items) catch
                    return TlsError.OutOfMemory;
            }
            stream.have_ctx = true;
            return;
        }

        if (status == win.SEC_I_CONTINUE_NEEDED or status == win.SEC_E_INCOMPLETE_MESSAGE) {
            // Read more ciphertext
            var tmp: [16384]u8 = undefined;
            const n = ws2.recv(stream.sock, tmp[0..].ptr, @intCast(tmp.len), 0);
            if (n <= 0) return TlsError.HandshakeFailed;
            in_data.appendSlice(stream.alloc, tmp[0..@intCast(n)]) catch return TlsError.OutOfMemory;
            continue;
        }

        log.err("InitializeSecurityContextW failed: 0x{x:0>8}", .{@as(u32, @bitCast(status))});
        return TlsError.HandshakeFailed;
    }
}
