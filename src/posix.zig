// POSIX non-blocking socket layer for the event core (issue #7):
// EINPROGRESS connect, WouldBlock-mapped reads/writes, MSG_NOSIGNAL sends
// (the bridge never takes SIGPIPE). The legacy blocking streams and
// timeout plumbing retired with the serial core.

const std = @import("std");
const socket = @import("born").socket;

// ------------------------------------------------------- non-blocking ----

pub const NbRead = socket.NbRead;
pub const NbWrite = socket.NbWrite;
pub const PlainNb = socket.PlainNb;

// --------------------------------------------------------------- tests ----

test "PlainNb: non-blocking connect + round trip over loopback" {
    const evport = @import("born");
    const alloc = std.testing.allocator;

    const addr = try std.net.Address.parseIp4("127.0.0.1", 0);
    var server = try addr.listen(.{});
    defer server.deinit();

    var client = try PlainNb.startConnect(alloc, "127.0.0.1", server.listen_address.getPort());
    defer client.deinit();

    var evp = try evport.EvPort.init(alloc);
    defer evp.deinit();
    var tag: u8 = 9;
    evp.wantWrite(client.sock, &tag);

    var events: [8]evport.Event = undefined;
    try std.testing.expectEqual(@as(usize, 1), try evp.wait(&events, 1000));
    try std.testing.expect(events[0].writable);
    try client.connectDone();

    // Write a request; the server echoes it.
    switch (try client.writeNb("ping")) {
        .done => |n| try std.testing.expectEqual(@as(usize, 4), n),
        else => return error.TestUnexpectedResult,
    }
    var conn = try server.accept();
    var rbuf: [16]u8 = undefined;
    const rn = try conn.stream.read(&rbuf);
    try std.testing.expectEqualStrings("ping", rbuf[0..rn]);
    _ = try conn.stream.write("pong");

    // Read side: readable event, then data, then EAGAIN.
    evp.monitorRead(client.sock, &tag);
    try std.testing.expectEqual(@as(usize, 1), try evp.wait(&events, 1000));
    try std.testing.expect(events[0].readable);
    switch (try client.readNb(&rbuf)) {
        .data => |n| try std.testing.expectEqualStrings("pong", rbuf[0..n]),
        else => return error.TestUnexpectedResult,
    }
    switch (try client.readNb(&rbuf)) {
        .want_read => {},
        else => return error.TestUnexpectedResult,
    }

    // Peer close → readable + eof.
    conn.stream.close();
    try std.testing.expectEqual(@as(usize, 1), try evp.wait(&events, 1000));
    try std.testing.expect(events[0].readable or events[0].eof);
    switch (try client.readNb(&rbuf)) {
        .eof => {},
        else => return error.TestUnexpectedResult,
    }
}

test "PlainNb: connect refused surfaces at connectDone" {
    const evport = @import("born");
    const alloc = std.testing.allocator;

    // Bind+close to find a free port nothing listens on.
    const addr = try std.net.Address.parseIp4("127.0.0.1", 0);
    var server = try addr.listen(.{});
    const port = server.listen_address.getPort();
    server.deinit();

    // Loopback refusal is timing-dependent: connect() may report
    // ECONNREFUSED synchronously (startConnect fails) instead of
    // EINPROGRESS-then-SO_ERROR. Both report ConnectFailed; accept either.
    var client = PlainNb.startConnect(alloc, "127.0.0.1", port) catch |err| {
        try std.testing.expectEqual(PlainNb.Error.ConnectFailed, err);
        return;
    };
    defer client.deinit();

    var evp = try evport.EvPort.init(alloc);
    defer evp.deinit();
    var tag: u8 = 10;
    evp.wantWrite(client.sock, &tag);

    var events: [8]evport.Event = undefined;
    _ = try evp.wait(&events, 1000);
    try std.testing.expectError(PlainNb.Error.ConnectFailed, client.connectDone());
}
