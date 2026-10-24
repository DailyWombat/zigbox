//! Release size gate: `size_check <limit_bytes> <file>...` exits 1 if any file is at or above
//! the limit. Run by `zig build release` so CI only has to run that step. Build-host tool.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");

const files_max: u32 = 16;

/// The limit is exclusive: a file of exactly `limit_bytes` fails ("under 2 MB").
pub fn within_limit(size_bytes: u64, limit_bytes: u64) bool {
    assert(limit_bytes > 0);
    return size_bytes < limit_bytes;
}

pub fn main(init: std.process.Init) !u8 {
    var buffer: [1024]u8 = undefined;
    var file_writer: std.Io.File.Writer = .init(.stderr(), init.io, &buffer);
    const out = &file_writer.interface;

    var iterator = init.minimal.args.iterate();
    _ = iterator.next();
    const limit_text = iterator.next() orelse return usage(out);
    const limit_bytes = std.fmt.parseInt(u64, limit_text, 10) catch return usage(out);
    if (limit_bytes == 0) return usage(out);

    var checked: u32 = 0;
    var failed: u32 = 0;
    while (iterator.next()) |path| {
        if (checked == files_max) return usage(out);
        checked += 1;
        const stat = try std.Io.Dir.cwd().statFile(init.io, path, .{});
        const ok = within_limit(stat.size, limit_bytes);
        const verdict = if (ok) "ok" else "TOO BIG";
        try out.print("size_check: {s}: {d} bytes (limit {d}): {s}\n", .{
            path, stat.size, limit_bytes, verdict,
        });
        if (!ok) failed += 1;
    }
    assert(failed <= checked);
    try out.flush();
    if (checked == 0) return usage(out);
    return if (failed == 0) constants.exit_ok else constants.exit_failed;
}

fn usage(out: *std.Io.Writer) u8 {
    out.writeAll("usage: size_check <limit_bytes> <file>...\n") catch {}; // Nowhere else to report.
    out.flush() catch {}; // Same.
    return constants.exit_usage;
}

test "the limit is exclusive at the boundary" {
    // Goal: 2 MiB minus one passes, exactly 2 MiB fails, and zero-size passes.
    const limit: u64 = 2 * 1024 * 1024;
    try std.testing.expect(within_limit(limit - 1, limit));
    try std.testing.expect(!within_limit(limit, limit));
    try std.testing.expect(!within_limit(limit + 1, limit));
    try std.testing.expect(within_limit(0, limit));
}
