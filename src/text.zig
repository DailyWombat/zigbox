//! Small text helpers: sanitising untrusted text for display and building bounded strings
//! without allocation.

const std = @import("std");
const assert = std.debug.assert;

pub fn is_printable(byte: u8) bool {
    if (byte < 0x20) return false;
    if (byte >= 0x7f) return false;
    return true;
}

/// Makes untrusted text safe to print: non-printable and non-ASCII bytes (which could carry
/// terminal escape sequences) become '?', and text longer than `storage` ends in "...".
/// Returns a slice of `storage`.
pub fn sanitise(storage: []u8, text: []const u8) []const u8 {
    const marker = "...";
    assert(storage.len >= marker.len);
    const truncated = text.len > storage.len;
    const keep = if (truncated) storage.len - marker.len else text.len;
    for (text[0..keep], storage[0..keep]) |byte, *out| {
        out.* = if (is_printable(byte)) byte else '?';
    }
    var result: []const u8 = storage[0..keep];
    if (truncated) {
        @memcpy(storage[keep..][0..marker.len], marker);
        assert(keep + marker.len == storage.len);
        result = storage[0..];
    }
    // Negative space: nothing printable-unsafe survives.
    for (result) |byte| assert(is_printable(byte));
    return result;
}

/// A fixed-capacity string. Appending past the capacity truncates and ends the text in "...",
/// so a message is always well formed and never overflows.
pub fn Bounded(comptime capacity: u32) type {
    comptime assert(capacity >= 8);
    return struct {
        const Self = @This();
        bytes: [capacity]u8 = undefined,
        len: u32 = 0,
        truncated: bool = false,

        pub fn slice(self: *const Self) []const u8 {
            assert(self.len <= capacity);
            return self.bytes[0..self.len];
        }

        pub fn print(self: *Self, comptime format: []const u8, args: anytype) void {
            assert(self.len <= capacity);
            if (self.truncated) return;
            var writer = std.Io.Writer.fixed(self.bytes[self.len..]);
            writer.print(format, args) catch {
                self.len += @intCast(writer.buffered().len);
                self.truncate();
                return;
            };
            self.len += @intCast(writer.buffered().len);
            assert(self.len <= capacity);
        }

        /// Appends `text` with unsafe bytes replaced, limited to `limit` bytes of it.
        pub fn append_sanitised(self: *Self, text: []const u8, limit: u32) void {
            assert(limit >= 4);
            var storage: [capacity]u8 = undefined;
            const room = @min(limit, capacity);
            self.print("{s}", .{sanitise(storage[0..room], text)});
        }

        fn truncate(self: *Self) void {
            self.truncated = true;
            self.len = @min(self.len, capacity);
            if (self.len < 3) self.len = 3;
            @memcpy(self.bytes[self.len - 3 .. self.len], "...");
            assert(self.len <= capacity);
        }
    };
}

test "sanitise replaces unsafe bytes and marks truncation" {
    // Goal: escapes and non-ASCII never survive, and over-long text ends in "...".
    var storage: [8]u8 = undefined;
    try std.testing.expectEqualStrings("ab?d", sanitise(&storage, "ab\x1bd"));
    try std.testing.expectEqualStrings("?????", sanitise(&storage, "\xc3\xa9\xff\x00\x7f"));
    try std.testing.expectEqualStrings("abcde...", sanitise(&storage, "abcdefghij"));
    try std.testing.expectEqualStrings("abcdefgh", sanitise(&storage, "abcdefgh"));
    try std.testing.expectEqualStrings("", sanitise(&storage, ""));
}

test "Bounded formats, truncates at the boundary and stays truncated" {
    // Goal: exact fit is not truncated; one byte more is; later appends are ignored.
    var exact: Bounded(8) = .{};
    exact.print("{s}", .{"12345678"});
    try std.testing.expectEqualStrings("12345678", exact.slice());
    try std.testing.expect(!exact.truncated);

    var over: Bounded(8) = .{};
    over.print("{s}", .{"123456789"});
    try std.testing.expectEqualStrings("12345...", over.slice());
    over.print("{s}", .{"more"});
    try std.testing.expectEqualStrings("12345...", over.slice());

    var parts: Bounded(16) = .{};
    parts.print("a{d}", .{12});
    parts.print("-{s}", .{"bc"});
    try std.testing.expectEqualStrings("a12-bc", parts.slice());
    parts.append_sanitised("x\x1by", 16);
    try std.testing.expectEqualStrings("a12-bcx?y", parts.slice());
}
