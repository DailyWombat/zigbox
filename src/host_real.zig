//! The production `Host`: raw Linux syscalls through `std.os.linux`, no libc. This file and
//! `host.zig` are the only places that may name syscalls, or paths under /proc and /sys.

const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const constants = @import("constants.zig");
const host = @import("host.zig");

pub const HostReal = struct {
    /// Files opened and not yet closed. Pair assertion for the simulator's handle table: a
    /// close without a matching open is a programmer error.
    open_count: u32 = 0,

    pub fn interface(self: *HostReal) host.Host {
        return .{ .context = self, .vtable = &vtable };
    }

    const vtable: host.VTable = .{
        .open_read = open_read,
        .read = read,
        .close = close,
        .write = write,
        .uname = uname,
        .stat_mode = stat_mode,
        .probe = probe,
    };

    fn from_context(context: *anyopaque) *HostReal {
        return @ptrCast(@alignCast(context));
    }

    fn open_read(context: *anyopaque, path: [:0]const u8) host.Error!host.Handle {
        const self = from_context(context);
        assert(path.len > 0);
        assert(path.len <= constants.path_bytes_max);
        const flags: linux.O = .{ .ACCMODE = .RDONLY, .CLOEXEC = true };
        const result = linux.open(path.ptr, flags, 0);
        try check(result);
        assert(result <= std.math.maxInt(i32)); // A descriptor, not an errno-shaped value.
        self.open_count += 1;
        const descriptor: i32 = @intCast(result);
        return @intCast(descriptor);
    }

    fn read(context: *anyopaque, handle: host.Handle, buffer: []u8) host.Error!u32 {
        const self = from_context(context);
        assert(self.open_count > 0);
        assert(buffer.len > 0);
        assert(buffer.len <= constants.file_bytes_max);
        const descriptor: i32 = @intCast(handle);
        const result = linux.read(descriptor, buffer.ptr, buffer.len);
        try check(result);
        assert(result <= buffer.len);
        return @intCast(result);
    }

    fn close(context: *anyopaque, handle: host.Handle) void {
        const self = from_context(context);
        assert(self.open_count > 0);
        self.open_count -= 1;
        const descriptor: i32 = @intCast(handle);
        // A close error on a read-only descriptor loses no data and cannot be acted on.
        _ = linux.close(descriptor);
    }

    fn write(context: *anyopaque, stream: host.Stream, bytes: []const u8) host.Error!u32 {
        _ = from_context(context);
        assert(bytes.len > 0);
        assert(bytes.len <= constants.output_bytes_max);
        const descriptor: i32 = switch (stream) {
            .stdout => linux.STDOUT_FILENO,
            .stderr => linux.STDERR_FILENO,
        };
        const result = linux.write(descriptor, bytes.ptr, bytes.len);
        try check(result);
        assert(result <= bytes.len);
        return @intCast(result);
    }

    fn uname(context: *anyopaque) host.Error!host.Uname {
        _ = from_context(context);
        var raw: linux.utsname = undefined;
        try check(linux.uname(&raw));
        const release = std.mem.sliceTo(&raw.release, 0);
        const machine = std.mem.sliceTo(&raw.machine, 0);
        assert(release.len < constants.uname_field_bytes);
        assert(machine.len < constants.uname_field_bytes);
        return .{
            .release = host.Text.from_slice(release),
            .machine = host.Text.from_slice(machine),
        };
    }

    fn stat_mode(context: *anyopaque, path: [:0]const u8) host.Error!u32 {
        _ = from_context(context);
        assert(path.len > 0);
        const mask: linux.STATX = .{ .TYPE = true, .MODE = true };
        var buffer: linux.Statx = undefined;
        try check(linux.statx(linux.AT.FDCWD, path.ptr, 0, mask, &buffer));
        // The kernel must honour the mask for TYPE and MODE; a clear bit would mean garbage.
        assert(buffer.mask.TYPE);
        assert(buffer.mask.MODE);
        return buffer.mode;
    }

    /// The fork-and-probe machinery belongs to the doctor (slice 2). Until then the honest
    /// answer is "unsupported", which callers must report as a failed check, never as ok.
    fn probe(context: *anyopaque, kind: host.ProbeKind) host.Error!host.ProbeOutcome {
        _ = from_context(context);
        _ = kind;
        return error.Unsupported;
    }

    /// Converts a raw syscall return value into an error, or passes success through.
    fn check(result: usize) host.Error!void {
        const code = linux.errno(result);
        if (code == .SUCCESS) return;
        return switch (code) {
            .INTR => error.Interrupted,
            .AGAIN => error.WouldBlock,
            .NOENT, .NOTDIR => error.NotFound,
            .ACCES, .PERM => error.AccessDenied,
            .NOSPC => error.NoSpace,
            .NOMEM => error.OutOfMemory,
            .NAMETOOLONG => error.PathTooLong,
            .NOSYS => error.Unsupported,
            else => error.IoFailed,
        };
    }
};

test "real host reads a file, reports a missing one, and closes every handle" {
    // Goal: the production implementation honours the interface contract on the machine running
    // the tests. Method: read /proc/self/stat (always present on Linux), then a path that cannot
    // exist, and check that no handle leaked on either path.
    var real: HostReal = .{};
    const subject = real.interface();
    var buffer: [constants.file_bytes_max]u8 = undefined;

    const content = try subject.read_file("/proc/self/stat", &buffer);
    try std.testing.expect(content.len > 0);
    try std.testing.expectEqual(@as(u32, 0), real.open_count);

    try std.testing.expectError(
        error.NotFound,
        subject.read_file("/proc/zigbox-does-not-exist", &buffer),
    );
    try std.testing.expectEqual(@as(u32, 0), real.open_count);
}

test "real host refuses a file larger than the buffer instead of truncating" {
    // Goal: FileTooLarge, not a short success. Method: /proc/self/stat is over 8 bytes.
    var real: HostReal = .{};
    var small: [8]u8 = undefined;
    try std.testing.expectError(
        error.FileTooLarge,
        real.interface().read_file("/proc/self/stat", &small),
    );
    try std.testing.expectEqual(@as(u32, 0), real.open_count);
}

test "real host uname and stat_mode report plausible values" {
    // Goal: uname names a Linux release, and stat_mode distinguishes a directory from a file.
    var real: HostReal = .{};
    const subject = real.interface();
    const names = try subject.uname();
    try std.testing.expect(names.release.slice().len > 0);
    try std.testing.expect(names.machine.slice().len > 0);

    const directory_mode = try subject.stat_mode("/proc");
    try std.testing.expectEqual(@as(u32, std.posix.S.IFDIR), directory_mode & std.posix.S.IFMT);
    try std.testing.expectError(error.NotFound, subject.stat_mode("/zigbox-does-not-exist"));
}

test "real host probe is unsupported until the doctor lands" {
    // Goal: pin the honest stub so it cannot silently become "ok".
    var real: HostReal = .{};
    try std.testing.expectError(error.Unsupported, real.interface().probe(.userns));
}
