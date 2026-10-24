//! The only interface through which Zigbox touches the kernel. Two implementations exist:
//! `host_real.zig` (syscalls) and `host_sim.zig` (an in-memory model with seeded fault
//! injection). Code above this file must not know which one it is using.
//!
//! Design choice: a runtime vtable (`*anyopaque` context plus a table of function pointers)
//! rather than a comptime-selected type. Reasons: (1) the fuzzers and unit tests build real
//! binaries once and swap implementations per iteration without instantiating every caller
//! twice; (2) callers take a plain `Host` value, so no generic parameter spreads through
//! `doctor`, `cli` and the later milestones; (3) the call overhead is irrelevant next to a
//! syscall. The cost is that the compiler cannot see which implementation a call reaches. The
//! vtable struct has no field defaults, so an implementation that omits an entry does not
//! compile.
//!
//! The vtable holds only primitives. Retry and short-read logic is written once, here, in
//! `read_file` and `write_all`, so that the simulator's injected EINTR and short reads exercise
//! the same code that runs in production.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");

/// Operating errors the kernel layer can report. Deliberately coarse: callers choose a message
/// and a fix per error, never per errno.
pub const Error = error{
    NotFound,
    AccessDenied,
    Interrupted,
    WouldBlock,
    NoSpace,
    OutOfMemory,
    PathTooLong,
    InvalidPath,
    /// The file holds more bytes than the caller's buffer, which is its documented limit.
    FileTooLarge,
    /// An operation made no progress within its call bound (a livelock guard).
    Stalled,
    Unsupported,
    /// The file exists but does not have the requested extended attribute.
    NoData,
    IoFailed,
};

/// An open, read-only file. Small integers so the simulator can hand out table indexes.
pub const Handle = u32;

pub const Stream = enum { stdout, stderr };

pub const Text = struct {
    bytes: [constants.uname_field_bytes]u8,
    len: u8,

    pub fn slice(text: *const Text) []const u8 {
        assert(text.len < constants.uname_field_bytes);
        assert(text.bytes[text.len] == 0); // from_slice zero-fills past the end.
        return text.bytes[0..text.len];
    }

    pub fn from_slice(source: []const u8) Text {
        assert(source.len < constants.uname_field_bytes);
        var text: Text = .{ .bytes = @splat(0), .len = @intCast(source.len) };
        @memcpy(text.bytes[0..source.len], source);
        assert(text.bytes[source.len] == 0);
        return text;
    }
};

pub const Uname = struct {
    release: Text,
    machine: Text,
};

/// File type and permission bits, and the owner, as `stat` reports them.
pub const Stat = struct {
    mode: u32,
    uid: u32,
};

/// Probes run in a forked child so a failed probe cannot damage the caller. The child runs as
/// an unprivileged user even when the caller is root, so the answer is about ordinary users.
pub const ProbeKind = enum { userns, overlay };

pub const ProbeOutcome = enum {
    ok,
    /// The operation under test was refused (EPERM, EACCES, ENOSPC, ENODEV, EINVAL ...).
    denied,
    /// Overlay only: the child could not enter the user and mount namespaces the probe needs.
    setup_denied,
    /// The namespace was created but writing setgroups/uid_map/gid_map was refused.
    map_denied,
    /// The child failed for a reason that says nothing about the feature (no memory, ...).
    failed,
    /// The child was killed by a signal.
    signaled,
    /// The child did not finish within the probe timeout and was killed and reaped.
    timed_out,
};

pub const VTable = struct {
    open_read: *const fn (context: *anyopaque, path: [:0]const u8) Error!Handle,
    read: *const fn (context: *anyopaque, handle: Handle, buffer: []u8) Error!u32,
    close: *const fn (context: *anyopaque, handle: Handle) void,
    write: *const fn (context: *anyopaque, stream: Stream, bytes: []const u8) Error!u32,
    uname: *const fn (context: *anyopaque) Error!Uname,
    stat: *const fn (context: *anyopaque, path: [:0]const u8) Error!Stat,
    /// Reads the raw `security.capability` xattr. Returns `NoData` if the file has none and
    /// `FileTooLarge` if it does not fit `buffer`.
    read_capability: *const fn (
        context: *anyopaque,
        path: [:0]const u8,
        buffer: []u8,
    ) Error!u32,
    /// The mode of the seccomp filter of this process, from `prctl(PR_GET_SECCOMP)`.
    seccomp_mode: *const fn (context: *anyopaque) Error!u32,
    is_terminal: *const fn (context: *anyopaque, stream: Stream) bool,
    /// The real user id of this process.
    uid: *const fn (context: *anyopaque) u32,
    probe: *const fn (context: *anyopaque, kind: ProbeKind) Error!ProbeOutcome,
};

pub const Host = struct {
    context: *anyopaque,
    vtable: *const VTable,

    /// Reads the whole file into `buffer` and returns the filled prefix. A file longer than
    /// `buffer` is `FileTooLarge`; it is never silently truncated, because a truncated
    /// /proc or /etc file could turn a failing check into a passing one.
    pub fn read_file(host: Host, path: []const u8, buffer: []u8) Error![]u8 {
        assert(buffer.len > 0);
        assert(buffer.len <= constants.file_bytes_max);
        var path_z: PathZ = undefined;
        const path_sentinel = try path_z.init(path);

        const handle = try host.open_retrying(path_sentinel);
        defer host.vtable.close(host.context, handle);

        const length = try host.read_all(handle, buffer);
        assert(length <= buffer.len);
        return buffer[0..length];
    }

    pub fn write_all(host: Host, stream: Stream, bytes: []const u8) Error!void {
        assert(bytes.len <= constants.output_bytes_max);
        var written: u32 = 0;
        var retries: u32 = 0;
        var calls: u32 = 0;
        // Interrupted calls do not count toward `calls` but are bounded by `retries`, which
        // only a non-interrupted call resets, so the loop terminates.
        while (calls < constants.write_calls_max) {
            if (written == bytes.len) return;
            assert(written < bytes.len);
            const result = host.vtable.write(host.context, stream, bytes[written..]);
            const count = result catch |err| switch (err) {
                error.Interrupted => {
                    retries += 1;
                    if (retries > constants.eintr_retries_max) return error.IoFailed;
                    continue;
                },
                else => return err,
            };
            retries = 0;
            calls += 1;
            assert(count <= bytes.len - written);
            written += count;
        }
        // Each non-EINTR call that returned 0 made no progress; bounded loops end here.
        return error.Stalled;
    }

    pub fn uname(host: Host) Error!Uname {
        const result = try host.vtable.uname(host.context);
        assert(result.release.len < constants.uname_field_bytes);
        assert(result.machine.len < constants.uname_field_bytes);
        return result;
    }

    pub fn stat(host: Host, path: []const u8) Error!Stat {
        var path_z: PathZ = undefined;
        const path_sentinel = try path_z.init(path);
        assert(path_sentinel.len == path.len);
        const result = try host.vtable.stat(host.context, path_sentinel);
        assert(result.mode <= std.math.maxInt(u16)); // st_mode is 16 bits in the kernel ABI.
        return result;
    }

    /// Returns the filled prefix of `buffer`.
    pub fn read_capability(host: Host, path: []const u8, buffer: []u8) Error![]u8 {
        assert(buffer.len > 0);
        assert(buffer.len <= constants.capability_bytes_max);
        var path_z: PathZ = undefined;
        const path_sentinel = try path_z.init(path);
        const length = try host.vtable.read_capability(host.context, path_sentinel, buffer);
        assert(length <= buffer.len);
        return buffer[0..length];
    }

    pub fn seccomp_mode(host: Host) Error!u32 {
        const mode = try host.vtable.seccomp_mode(host.context);
        assert(mode <= 2); // The kernel's modes: disabled, strict, filter.
        return mode;
    }

    pub fn is_terminal(host: Host, stream: Stream) bool {
        return host.vtable.is_terminal(host.context, stream);
    }

    pub fn uid(host: Host) u32 {
        const id = host.vtable.uid(host.context);
        assert(id != std.math.maxInt(u32)); // (uid_t)-1 means "no change", never a real id.
        return id;
    }

    pub fn probe(host: Host, kind: ProbeKind) Error!ProbeOutcome {
        return host.vtable.probe(host.context, kind);
    }

    fn open_retrying(host: Host, path: [:0]const u8) Error!Handle {
        assert(path.len > 0);
        assert(path[path.len] == 0);
        for (0..constants.eintr_retries_max + 1) |_| {
            return host.vtable.open_read(host.context, path) catch |err| switch (err) {
                error.Interrupted => continue,
                else => return err,
            };
        }
        return error.IoFailed;
    }

    fn read_all(host: Host, handle: Handle, buffer: []u8) Error!u32 {
        assert(buffer.len > 0);
        assert(handle < std.math.maxInt(i32)); // Descriptors are non-negative i32.
        var filled: u32 = 0;
        var retries: u32 = 0;
        var calls: u32 = 0;
        // See `write_all` for why interrupted calls are bounded separately from `calls`.
        while (calls < constants.read_calls_max) {
            // When the buffer is full, one more byte decides between "exactly full" and
            // "too large". The probe byte is read into scratch and discarded.
            var scratch: [1]u8 = undefined;
            const full = filled == buffer.len;
            const target: []u8 = if (full) scratch[0..] else buffer[filled..];
            const result = host.vtable.read(host.context, handle, target);
            const count = result catch |err| switch (err) {
                error.Interrupted => {
                    retries += 1;
                    if (retries > constants.eintr_retries_max) return error.IoFailed;
                    continue;
                },
                else => return err,
            };
            retries = 0;
            calls += 1;
            assert(count <= target.len);
            if (count == 0) return filled;
            if (full) return error.FileTooLarge;
            filled += count;
        }
        return error.Stalled;
    }
};

/// A NUL-terminated copy of a caller path, on the caller's stack, so the vtable can pass
/// sentinel-terminated slices to syscalls without allocating.
const PathZ = struct {
    storage: [constants.path_bytes_max + 1]u8,

    fn init(path_z: *PathZ, path: []const u8) Error![:0]const u8 {
        if (path.len == 0) return error.InvalidPath;
        if (path.len > constants.path_bytes_max) return error.PathTooLong;
        // An embedded NUL would silently shorten the path the kernel sees.
        if (std.mem.indexOfScalar(u8, path, 0) != null) return error.InvalidPath;
        @memcpy(path_z.storage[0..path.len], path);
        path_z.storage[path.len] = 0;
        const result: [:0]const u8 = path_z.storage[0..path.len :0];
        assert(result.len == path.len);
        assert(result[result.len] == 0);
        return result;
    }
};

const repeat = @import("test_util.zig").repeat;

test "Text round-trips and bounds its length" {
    // Goal: Text keeps exactly the bytes given, up to the field size minus the NUL.
    const text = Text.from_slice("6.18.44");
    try std.testing.expectEqualStrings("6.18.44", text.slice());
    const empty = Text.from_slice("");
    try std.testing.expectEqual(@as(usize, 0), empty.slice().len);
    const longest = Text.from_slice(repeat('a', constants.uname_field_bytes - 1));
    try std.testing.expectEqual(@as(usize, constants.uname_field_bytes - 1), longest.slice().len);
}

test "PathZ refuses empty, over-long and NUL-containing paths" {
    // Goal: the boundary where a path becomes invalid is exact, and refusals are errors.
    var path_z: PathZ = undefined;
    try std.testing.expectError(error.InvalidPath, path_z.init(""));
    try std.testing.expectError(error.InvalidPath, path_z.init("/proc/self\x00/status"));
    const longest = repeat('/', constants.path_bytes_max);
    const accepted = try path_z.init(longest);
    try std.testing.expectEqual(@as(usize, constants.path_bytes_max), accepted.len);
    const too_long = repeat('/', constants.path_bytes_max + 1);
    try std.testing.expectError(error.PathTooLong, path_z.init(too_long));
}
