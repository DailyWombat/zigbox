//! A tiny single-threaded HTTP/1.1 file server driven by the harness's poll loop. It serves
//! the cloud-init seed (`user-data`, `meta-data`) and the binary under test to the guest,
//! which reaches the host at 10.0.2.2. Only GET, only exact paths, one response per
//! connection (`Connection: close`). Bodies are borrowed, never copied.

const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const limits = @import("limits.zig");

pub const Route = struct {
    path: []const u8,
    body: []const u8,
};

const Phase = enum { free, reading, writing };

const header_bytes_max = 160;

const Connection = struct {
    descriptor: i32 = -1,
    phase: Phase = .free,
    request: [limits.http_request_bytes_max]u8 = undefined,
    request_len: u32 = 0,
    header: [header_bytes_max]u8 = undefined,
    header_len: u32 = 0,
    body: []const u8 = "",
    sent: u32 = 0,
};

pub const Server = struct {
    listener: i32 = -1,
    port: u16 = 0,
    routes: [limits.http_routes_max]Route = undefined,
    route_count: u32 = 0,
    connections: [limits.http_connections_max]Connection = @splat(.{}),

    /// Listens on 127.0.0.1 with an ephemeral port.
    pub fn start(server: *Server) !void {
        const kind = linux.SOCK.STREAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC;
        const created = linux.socket(linux.AF.INET, kind, 0);
        if (linux.errno(created) != .SUCCESS) return error.SocketFailed;
        server.listener = @intCast(created);
        var address: linux.sockaddr.in = .{
            .port = std.mem.nativeToBig(u16, 0),
            .addr = std.mem.nativeToBig(u32, 0x7f000001),
        };
        const bound = linux.bind(server.listener, @ptrCast(&address), @sizeOf(@TypeOf(address)));
        if (linux.errno(bound) != .SUCCESS) return error.BindFailed;
        if (linux.errno(linux.listen(server.listener, 8)) != .SUCCESS) return error.ListenFailed;
        var length: linux.socklen_t = @sizeOf(@TypeOf(address));
        const named = linux.getsockname(server.listener, @ptrCast(&address), &length);
        if (linux.errno(named) != .SUCCESS) return error.SocketFailed;
        server.port = std.mem.bigToNative(u16, address.port);
        assert(server.port != 0);
    }

    pub fn stop(server: *Server) void {
        for (&server.connections) |*connection| server.close_connection(connection);
        if (server.listener >= 0) _ = linux.close(server.listener);
        server.listener = -1;
    }

    pub fn add_route(server: *Server, path: []const u8, body: []const u8) void {
        assert(server.route_count < limits.http_routes_max);
        assert(body.len <= limits.http_body_bytes_max);
        assert(path.len > 0);
        assert(path[0] == '/');
        server.routes[server.route_count] = .{ .path = path, .body = body };
        server.route_count += 1;
    }

    /// Fills `entries` with what to poll for (the listener first, then each live connection)
    /// and returns how many. Pair with `handle` using the same `entries`.
    pub fn poll_entries(server: *Server, entries: []linux.pollfd) u32 {
        assert(entries.len >= 1 + limits.http_connections_max);
        entries[0] = .{ .fd = server.listener, .events = linux.POLL.IN };
        var count: u32 = 1;
        for (&server.connections) |*connection| {
            if (connection.phase == .free) continue;
            const events: i16 = if (connection.phase == .reading) linux.POLL.IN else linux.POLL.OUT;
            entries[count] = .{ .fd = connection.descriptor, .events = events };
            count += 1;
        }
        return count;
    }

    pub fn handle(server: *Server, entries: []linux.pollfd, log: *std.Io.Writer) void {
        if (entries[0].revents & linux.POLL.IN != 0) server.accept_connection();
        var index: u32 = 1;
        for (&server.connections) |*connection| {
            if (connection.phase == .free) continue;
            // New connections accepted above are not in `entries`; they are served next round.
            if (index >= entries.len) break;
            if (entries[index].fd != connection.descriptor) continue;
            const revents = entries[index].revents;
            index += 1;
            if (revents == 0) continue;
            server.step(connection, log);
        }
    }

    fn accept_connection(server: *Server) void {
        const flags = linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC;
        const accepted = linux.accept4(server.listener, null, null, flags);
        if (linux.errno(accepted) != .SUCCESS) return;
        const descriptor: i32 = @intCast(accepted);
        for (&server.connections) |*connection| {
            if (connection.phase != .free) continue;
            connection.* = .{ .descriptor = descriptor, .phase = .reading };
            return;
        }
        _ = linux.close(descriptor); // Too many at once: the client retries.
    }

    fn close_connection(server: *Server, connection: *Connection) void {
        _ = server;
        if (connection.phase == .free) return;
        _ = linux.close(connection.descriptor);
        connection.* = .{};
    }

    fn step(server: *Server, connection: *Connection, log: *std.Io.Writer) void {
        switch (connection.phase) {
            .reading => server.read_request(connection, log),
            .writing => server.write_response(connection),
            .free => unreachable, // Free connections are skipped by the caller.
        }
    }

    fn read_request(server: *Server, connection: *Connection, log: *std.Io.Writer) void {
        const room = connection.request[connection.request_len..];
        const got = linux.read(connection.descriptor, room.ptr, room.len);
        const code = linux.errno(got);
        if (code == .AGAIN) return;
        if (code != .SUCCESS or got == 0) return server.close_connection(connection);
        connection.request_len += @intCast(got);
        const text = connection.request[0..connection.request_len];
        if (std.mem.indexOf(u8, text, "\r\n\r\n") == null) {
            const full = connection.request_len == connection.request.len;
            if (full) server.close_connection(connection);
            return;
        }
        const path = request_path(text);
        const route_body = server.find(path);
        connection.body = route_body orelse "";
        const status: []const u8 = if (route_body == null) "404 Not Found" else "200 OK";
        const format = "HTTP/1.1 {s}\r\nContent-Length: {d}\r\n" ++
            "Content-Type: application/octet-stream\r\nConnection: close\r\n\r\n";
        const lengths = .{ status, connection.body.len };
        const header = std.fmt.bufPrint(&connection.header, format, lengths);
        // Cannot fail: the header buffer holds the longest status line and a 7-digit length.
        connection.header_len = @intCast((header catch unreachable).len);
        connection.phase = .writing;
        const shown = path orelse "?";
        log.print("  http| GET {s} -> {s} ({d} bytes)\n", .{ shown, status, lengths[1] }) catch {};
    }

    fn find(server: *Server, path: ?[]const u8) ?[]const u8 {
        const wanted = path orelse return null;
        for (server.routes[0..server.route_count]) |route| {
            if (std.mem.eql(u8, route.path, wanted)) return route.body;
        }
        return null;
    }

    fn write_response(server: *Server, connection: *Connection) void {
        const total: u32 = connection.header_len + @as(u32, @intCast(connection.body.len));
        assert(connection.sent < total);
        const descriptor = connection.descriptor;
        const written = if (connection.sent < connection.header_len) blk: {
            const rest = connection.header[connection.sent..connection.header_len];
            break :blk linux.write(descriptor, rest.ptr, rest.len);
        } else blk: {
            const rest = connection.body[connection.sent - connection.header_len ..];
            break :blk linux.write(descriptor, rest.ptr, rest.len);
        };
        const code = linux.errno(written);
        if (code == .AGAIN) return;
        if (code != .SUCCESS) return server.close_connection(connection);
        connection.sent += @intCast(written);
        if (connection.sent == total) server.close_connection(connection);
    }
};

/// The path of a `GET <path> HTTP/1.x` request line, or null for anything else.
pub fn request_path(request: []const u8) ?[]const u8 {
    const line_end = std.mem.indexOf(u8, request, "\r\n") orelse return null;
    const line = request[0..line_end];
    if (!std.mem.startsWith(u8, line, "GET ")) return null;
    const rest = line[4..];
    const space = std.mem.indexOfScalar(u8, rest, ' ') orelse return null;
    if (!std.mem.startsWith(u8, rest[space..], " HTTP/1.")) return null;
    return rest[0..space];
}

test "request_path accepts only GET request lines" {
    // Goal: the exact forms cloud-init and curl send parse; everything else is refused.
    const request = "GET /user-data HTTP/1.1\r\nHost: x\r\n\r\n";
    try std.testing.expectEqualStrings("/user-data", request_path(request).?);
    try std.testing.expectEqualStrings("/", request_path("GET / HTTP/1.0\r\n\r\n").?);
    try std.testing.expect(request_path("POST /x HTTP/1.1\r\n\r\n") == null);
    try std.testing.expect(request_path("GET /x\r\n\r\n") == null);
    try std.testing.expect(request_path("GET /x HTTP/2\r\n\r\n") == null);
    try std.testing.expect(request_path("GET /x HTTP/1.1") == null);
    try std.testing.expect(request_path("") == null);
}

/// Connects a non-blocking client to 127.0.0.1:`port`; returns its descriptor.
fn test_connect(port: u16) !i32 {
    const kind = linux.SOCK.STREAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC;
    const created = linux.socket(linux.AF.INET, kind, 0);
    try std.testing.expect(linux.errno(created) == .SUCCESS);
    const descriptor: i32 = @intCast(created);
    var address: linux.sockaddr.in = .{
        .port = std.mem.nativeToBig(u16, port),
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
    const connected = linux.connect(descriptor, @ptrCast(&address), @sizeOf(@TypeOf(address)));
    const code = linux.errno(connected);
    try std.testing.expect(code == .SUCCESS or code == .INPROGRESS);
    return descriptor;
}

/// Fetches `path` from `server` by driving the server's poll loop and a client together.
/// Returns the number of response bytes read into `response`.
fn test_get(server: *Server, path: []const u8, response: []u8) !usize {
    const client = try test_connect(server.port);
    defer _ = linux.close(client);
    var request_buffer: [128]u8 = undefined;
    const format = "GET {s} HTTP/1.1\r\nHost: t\r\n\r\n";
    const request = try std.fmt.bufPrint(&request_buffer, format, .{path});
    var requested = false;
    var length: usize = 0;
    var sink: std.Io.Writer.Discarding = .init(&.{});
    for (0..100_000) |_| {
        var entries: [1 + limits.http_connections_max]linux.pollfd = undefined;
        const count = server.poll_entries(&entries);
        _ = linux.poll(&entries, count, 1);
        server.handle(entries[0..count], &sink.writer);
        if (!requested) {
            const wrote = linux.write(client, request.ptr, request.len);
            requested = linux.errno(wrote) == .SUCCESS;
        }
        while (requested) {
            const got = linux.read(client, response[length..].ptr, response.len - length);
            if (linux.errno(got) != .SUCCESS) break;
            if (got == 0) return length;
            length += got;
        }
    }
    return error.TestTimedOut;
}

test "server serves a body bigger than the socket buffers, a 404, and an empty route" {
    // Goal: the poll-driven write path survives partial writes (a 1 MiB body), unknown paths get
    // 404 with no body, and a route with an empty body (vendor-data) answers 200.
    var server: Server = .{};
    try server.start();
    defer server.stop();
    const big = try std.testing.allocator.alloc(u8, 1024 * 1024);
    defer std.testing.allocator.free(big);
    for (big, 0..) |*byte, index| byte.* = @truncate(index * 7);
    server.add_route("/big", big);
    server.add_route("/empty", "");

    const response = try std.testing.allocator.alloc(u8, big.len + 512);
    defer std.testing.allocator.free(response);
    const length = try test_get(&server, "/big", response);
    const body_at = std.mem.indexOf(u8, response[0..length], "\r\n\r\n").? + 4;
    try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 200 OK\r\n"));
    try std.testing.expectEqualSlices(u8, big, response[body_at..length]);

    const missing = try test_get(&server, "/nope", response);
    const not_found = "HTTP/1.1 404 Not Found\r\n";
    try std.testing.expect(std.mem.startsWith(u8, response[0..missing], not_found));
    const empty = try test_get(&server, "/empty", response);
    try std.testing.expect(std.mem.startsWith(u8, response[0..empty], "HTTP/1.1 200 OK\r\n"));
    try std.testing.expect(std.mem.endsWith(u8, response[0..empty], "\r\n\r\n"));
}
