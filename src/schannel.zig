// TLS client over SChannel (Windows) with manual certificate validation —
// the Verifier hook (DANE first, Windows root-store PKI fallback) runs
// after the handshake.
//
// Event-core non-blocking layer (issue #7): the handshake and I/O are
// driven through the overlapped PlainNb socket (IOCP completions); nothing
// blocks. The legacy blocking TlsStream retired with the serial core.

const std = @import("std");
const win = @import("win.zig");
const platform = @import("platform.zig");
const nb = @import("nb_win.zig");

const log = std.log.scoped(.tls_schannel);
const ulog = @import("ulog.zig");

fn vprint(comptime fmt: []const u8, args: anytype) void {
    ulog.vprint(fmt, args);
}

pub const TlsError = error{
    SocketError,
    SslInitFailed,
    HandshakeFailed,
    NoRemoteCert,
    PkiValidationFailed,
    TlsError,
    OutOfMemory,
    Utf16Conversion,
    CredentialAcquire,
};

/// Non-blocking SChannel client stream. Owns the socket (via `plain`) and
/// all TLS state. The OVERLAPPED structs live in `plain` — conn-heap-stable.
pub const TlsNb = struct {
    plain: nb.PlainNb,
    alloc: std.mem.Allocator,
    cred: win.CredHandle = .{},
    ctx: win.CtxtHandle = .{},
    have_ctx: bool = false,
    sizes: win.SecPkgContext_StreamSizes = std.mem.zeroes(win.SecPkgContext_StreamSizes),
    /// SNI target for the first handshake call (utf16).
    host_w: [:0]const u16 = &.{},
    // decrypted carryover from an over-read TLS record
    pending: std.ArrayList(u8) = .empty,
    // ciphertext accumulation (handshake input and decrypt input)
    enc_buf: std.ArrayList(u8) = .empty,
    // pending ciphertext out (handshake tokens and encrypted appdata)
    enc_out: std.ArrayList(u8) = .empty,
    enc_out_off: usize = 0,
    hs_need_input: bool = false, // SChannel asked for more ciphertext

    /// Wrap an already-connected overlapped socket; acquire credentials.
    pub fn initFromPlain(alloc: std.mem.Allocator, plain: nb.PlainNb, host: []const u8) TlsError!TlsNb {
        var self = TlsNb{
            .plain = plain,
            .alloc = alloc,
            .host_w = win.utf16Z(alloc, host) catch return TlsError.Utf16Conversion,
        };
        errdefer self.deinit();

        var scred: win.SCHANNEL_CRED = std.mem.zeroes(win.SCHANNEL_CRED);
        scred.dwVersion = win.SCHANNEL_CRED_VERSION;
        scred.dwFlags = win.SCH_CRED_MANUAL_CRED_VALIDATION | win.SCH_CRED_NO_DEFAULT_CREDS;
        scred.grbitEnabledProtocols = win.SP_PROT_TLS1_2 | win.SP_PROT_TLS1_3;

        const status = win.AcquireCredentialsHandleW(
            null,
            win.SCHANNEL_NAME_W.ptr,
            win.SECPKG_CRED_OUTBOUND,
            null,
            &scred,
            null,
            null,
            &self.cred,
            null,
        );
        if (!win.SUCCEEDED(status)) {
            log.err("AcquireCredentialsHandleW failed: 0x{x:0>8}", .{@as(u32, @bitCast(status))});
            return TlsError.CredentialAcquire;
        }
        return self;
    }

    // ---------------------------------------------------------- handshake --

    /// Drive the handshake one step. Re-register for the returned direction.
    pub fn handshakeDrive(self: *TlsNb) TlsError!nb.Drive {
        while (true) {
            // Flush pending handshake output tokens first.
            if (self.enc_out_off < self.enc_out.items.len) {
                switch (self.plain.writeNb(self.enc_out.items[self.enc_out_off..]) catch return TlsError.TlsError) {
                    .done => |n| {
                        self.enc_out_off += n;
                        continue;
                    },
                    .want_write => return .want_write,
                    .want_read => return .want_read, // unreachable for plain; tolerated
                }
            }
            self.enc_out.clearRetainingCapacity();
            self.enc_out_off = 0;

            // Pull more ciphertext when SChannel asked for it.
            if (self.hs_need_input) {
                var tmp: [16384]u8 = undefined;
                switch (self.plain.readNb(&tmp) catch return TlsError.TlsError) {
                    .data => |n| self.enc_buf.appendSlice(self.alloc, tmp[0..n]) catch return TlsError.OutOfMemory,
                    .want_read => return .want_read,
                    .want_write => return .want_write,
                    .eof => return TlsError.HandshakeFailed,
                }
            }

            if (try self.handshakeStep()) return .done;
        }
    }

    /// One InitializeSecurityContext call. Returns true when the handshake
    /// completed (and stream sizes are ready for framing).
    fn handshakeStep(self: *TlsNb) TlsError!bool {
        var in_bufs = [2]win.SecBuffer{
            .{ .cbBuffer = @intCast(self.enc_buf.items.len), .BufferType = win.SECBUFFER_TOKEN, .pvBuffer = if (self.enc_buf.items.len > 0) self.enc_buf.items.ptr else null },
            .{ .cbBuffer = 0, .BufferType = win.SECBUFFER_EMPTY, .pvBuffer = null },
        };
        var in_desc = win.SecBufferDesc{ .ulVersion = win.SECBUFFER_VERSION, .cBuffers = 2, .pBuffers = &in_bufs };

        var out_buf = [1]win.SecBuffer{
            .{ .cbBuffer = 0, .BufferType = win.SECBUFFER_TOKEN, .pvBuffer = null },
        };
        var out_desc = win.SecBufferDesc{ .ulVersion = win.SECBUFFER_VERSION, .cBuffers = 1, .pBuffers = &out_buf };

        var attrs: win.DWORD = 0;
        var new_ctx: win.CtxtHandle = .{};
        const status = win.InitializeSecurityContextW(
            &self.cred,
            if (self.have_ctx) &self.ctx else null,
            if (self.have_ctx) null else self.host_w.ptr, // SNI on first call
            win.ISC_FLAGS,
            0,
            win.SECURITY_NATIVE_DREP,
            if (self.have_ctx or self.hs_need_input) &in_desc else null,
            0,
            &new_ctx,
            &out_desc,
            &attrs,
            null,
        );
        self.ctx = new_ctx;
        self.have_ctx = true;
        vprint("mcp-bridge: [tls] ISC status 0x{x:0>8} (input {d} bytes buffered)\n", .{ @as(u32, @bitCast(status)), self.enc_buf.items.len });

        // Consume input: EXTRA marks the leftover suffix (pvBuffer may be
        // null — compute the offset from cbBuffer, not the pointer).
        if (in_bufs[1].BufferType == win.SECBUFFER_EXTRA and in_bufs[1].cbBuffer > 0) {
            const keep: usize = @min(in_bufs[1].cbBuffer, self.enc_buf.items.len);
            const off = self.enc_buf.items.len - keep;
            std.mem.copyForwards(u8, self.enc_buf.items[0..keep], self.enc_buf.items[off..]);
            self.enc_buf.items.len = keep;
        } else if (status != win.SEC_E_INCOMPLETE_MESSAGE) {
            self.enc_buf.clearRetainingCapacity();
        }

        // Stage the output token (SChannel-allocated) into our own buffer.
        if (out_buf[0].pvBuffer != null) {
            const p: [*]u8 = @ptrCast(out_buf[0].pvBuffer.?);
            if (out_buf[0].cbBuffer > 0) {
                self.enc_out.appendSlice(self.alloc, p[0..out_buf[0].cbBuffer]) catch return TlsError.OutOfMemory;
            }
            _ = win.FreeContextBuffer(out_buf[0].pvBuffer);
        }

        if (status == win.SEC_E_OK) {
            // Handshake complete; stream sizes drive encrypt framing.
            const qs = win.QueryContextAttributesW(&self.ctx, win.SECPKG_ATTR_STREAM_SIZES, &self.sizes);
            if (!win.SUCCEEDED(qs)) return TlsError.HandshakeFailed;
            vprint("mcp-bridge: [tls] handshake complete\n", .{});
            return true;
        }
        if (status == win.SEC_I_CONTINUE_NEEDED or status == win.SEC_E_INCOMPLETE_MESSAGE) {
            self.hs_need_input = true;
            return false;
        }
        log.err("InitializeSecurityContext failed: 0x{x:0>8}", .{@as(u32, @bitCast(status))});
        return TlsError.HandshakeFailed;
    }

    /// DANE/PKI verify hook after the handshake.
    pub fn verifyPeer(self: *TlsNb, v: *platform.Verifier) bool {
        var remote_cert: win.PCCERT_CONTEXT = null;
        const status = win.QueryContextAttributesW(&self.ctx, win.SECPKG_ATTR_REMOTE_CERT_CONTEXT, @ptrCast(&remote_cert));
        if (!win.SUCCEEDED(status) or remote_cert == null) {
            log.err("no remote cert context: 0x{x:0>8}", .{@as(u32, @bitCast(status))});
            return false;
        }
        vprint("mcp-bridge: [tls] verifying certificate\n", .{});
        defer _ = win.CertFreeCertificateContext(remote_cert);
        const ok = platform.Verifier.verifyOpaque(v, remote_cert.?);
        if (ok) vprint("mcp-bridge: [tls] certificate accepted\n", .{});
        return ok;
    }

    // -------------------------------------------------------------- read --

    const DecryptOutcome = union(enum) { data: usize, closed, need_more };

    /// Read decrypted application data. Draining to .want_read implies the
    /// underlying socket is drained (the completion model's re-arm point).
    pub fn readNb(self: *TlsNb, out: []u8) TlsError!nb.NbRead {
        // Decrypted carryover first.
        if (self.pending.items.len > 0) {
            const n = @min(out.len, self.pending.items.len);
            @memcpy(out[0..n], self.pending.items[0..n]);
            const rem = self.pending.items.len - n;
            std.mem.copyForwards(u8, self.pending.items[0..rem], self.pending.items[n..]);
            self.pending.items.len = rem;
            return .{ .data = n };
        }

        while (true) {
            switch (try self.tryDecrypt(out)) {
                .data => |n| return .{ .data = n },
                .closed => return .eof,
                .need_more => {
                    var tmp: [16384]u8 = undefined;
                    switch (self.plain.readNb(&tmp) catch return TlsError.TlsError) {
                        .data => |n| self.enc_buf.appendSlice(self.alloc, tmp[0..n]) catch return TlsError.OutOfMemory,
                        .want_read => return .want_read,
                        .want_write => return .want_write,
                        .eof => return .eof,
                    }
                },
            }
        }
    }

    fn tryDecrypt(self: *TlsNb, out: []u8) TlsError!DecryptOutcome {
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

    // ------------------------------------------------------------- write --

    /// Write plaintext; encrypts one SChannel-framed chunk per call.
    /// Plaintext is consumed once encrypted into our staging buffer — the
    /// pending ciphertext flushes ahead of the next call.
    pub fn writeNb(self: *TlsNb, data: []const u8) TlsError!nb.NbWrite {
        // Flush pending ciphertext first.
        if (self.enc_out_off < self.enc_out.items.len) {
            switch (self.plain.writeNb(self.enc_out.items[self.enc_out_off..]) catch return TlsError.TlsError) {
                .done => |n| self.enc_out_off += n,
                .want_write => return .want_write,
                .want_read => return .want_read,
            }
            if (self.enc_out_off < self.enc_out.items.len) return .want_write;
            self.enc_out.clearRetainingCapacity();
            self.enc_out_off = 0;
        }
        if (data.len == 0) return .{ .done = 0 };

        const header: usize = self.sizes.cbHeader;
        const trailer: usize = self.sizes.cbTrailer;
        const max_msg: usize = self.sizes.cbMaximumMessage;
        if (max_msg == 0) return TlsError.TlsError;

        const chunk = @min(max_msg, data.len);
        try self.enc_out.resize(self.alloc, header + chunk + trailer);
        @memcpy(self.enc_out.items[header .. header + chunk], data[0..chunk]);

        var bufs = [4]win.SecBuffer{
            .{ .cbBuffer = @intCast(header), .BufferType = win.SECBUFFER_STREAM_HEADER, .pvBuffer = self.enc_out.items.ptr },
            .{ .cbBuffer = @intCast(chunk), .BufferType = win.SECBUFFER_DATA, .pvBuffer = self.enc_out.items.ptr + header },
            .{ .cbBuffer = @intCast(trailer), .BufferType = win.SECBUFFER_STREAM_TRAILER, .pvBuffer = self.enc_out.items.ptr + header + chunk },
            .{ .cbBuffer = 0, .BufferType = win.SECBUFFER_EMPTY, .pvBuffer = null },
        };
        var desc = win.SecBufferDesc{ .ulVersion = win.SECBUFFER_VERSION, .cBuffers = 4, .pBuffers = &bufs };

        const status = win.EncryptMessage(&self.ctx, 0, &desc, 0);
        if (!win.SUCCEEDED(status)) {
            log.err("EncryptMessage failed: 0x{x:0>8}", .{@as(u32, @bitCast(status))});
            return TlsError.TlsError;
        }

        const total: usize = bufs[0].cbBuffer + bufs[1].cbBuffer + bufs[2].cbBuffer;
        self.enc_out.items.len = total;

        // Flush once; any remainder stays pending for the next call.
        switch (self.plain.writeNb(self.enc_out.items) catch return TlsError.TlsError) {
            .done => |n| self.enc_out_off = n,
            .want_write => {},
            .want_read => {},
        }
        return .{ .done = chunk }; // plaintext consumed; cipher is ours
    }

    /// Best-effort close_notify.
    pub fn closeNotify(self: *TlsNb) void {
        if (!self.have_ctx) return;
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
            _ = self.plain.writeNb(out_buf[0..out[0].cbBuffer]) catch {};
        }
    }

    pub fn deinit(self: *TlsNb) void {
        if (self.have_ctx) _ = win.DeleteSecurityContext(&self.ctx);
        self.have_ctx = false;
        _ = win.FreeCredentialsHandle(&self.cred);
        self.alloc.free(self.host_w);
        self.pending.deinit(self.alloc);
        self.enc_buf.deinit(self.alloc);
        self.enc_out.deinit(self.alloc);
        self.plain.deinit();
    }
};
