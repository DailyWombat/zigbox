//! The simulated `Host`: an in-memory model of files, `uname` and probe results, driven by a
//! seeded PRNG that injects faults. Every run is reproducible from its seed. No allocation:
//! file contents are borrowed from the caller (fixtures are comptime or stack data).
//!
//! Faults modelled so far: open, read and write errors, short reads and writes, EINTR, and a
//! one-shot failure at the Nth host call (the "crash at any step" hook). Malformed /proc
//! contents are simply fixtures with malformed bytes. Slice 2 adds fixtures; the hooks here
//! are the mechanism.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const host = @import("host.zig");

pub const File = struct {
    path: []const u8,
    content: []const u8,
    mode: u32 = 0o100644,
    /// False models a file that exists but cannot be opened (EACCES).
    readable: bool = true,
};

/// Probabilities are per thousand calls so that a seed alone fixes the whole schedule. 1000
/// means "always"; 0 (the default) means "never".
pub const Faults = struct {
    open_error_per_mille: u16 = 0,
    read_error_per_mille: u16 = 0,
    short_read_per_mille: u16 = 0,
    write_error_per_mille: u16 = 0,
    short_write_per_mille: u16 = 0,
    interrupt_per_mille: u16 = 0,
    /// One-shot: the call whose zero-based index equals this fails with `fail_call_error`,
    /// whatever its kind. Lets a test walk a failure across every step of a sequence.
    fail_call_index: ?u32 = null,
    fail_call_error: host.Error = error.IoFailed,
};

pub const Probes = struct {
    userns: host.ProbeOutcome = .ok,
    overlay: host.ProbeOutcome = .ok,
};

const OpenFile = struct {
    file_index: u32,
    offset: u32,
};

pub const HostSim = struct {
    prng: std.Random.Xoshiro256,
    faults: Faults,
    files: []const File,
    uname_value: host.Uname,
    probes: Probes,
    open_files: [constants.sim_open_files_max]?OpenFile,
    call_count: u32,
    stdout_buffer: [constants.sim_output_bytes_max]u8,
    stdout_len: u32,
    stderr_buffer: [constants.sim_output_bytes_max]u8,
    stderr_len: u32,

    /// Initialises in place: the output buffers make this struct large.
    pub fn init(sim: *HostSim, seed: u64, files: []const File) void {
        assert(files.len <= constants.sim_files_max);
        for (files) |file| assert(file.path.len > 0);
        sim.prng = std.Random.Xoshiro256.init(seed);
        sim.faults = .{};
        sim.files = files;
        sim.uname_value = .{
            .release = host.Text.from_slice("6.8.0-sim"),
            .machine = host.Text.from_slice("x86_64"),
        };
        sim.probes = .{};
        sim.open_files = @splat(null);
        sim.call_count = 0;
        sim.stdout_len = 0;
        sim.stderr_len = 0;
        assert(sim.open_count() == 0);
        assert(sim.stdout().len == 0);
    }

    pub fn interface(sim: *HostSim) host.Host {
        return .{ .context = sim, .vtable = &vtable };
    }

    pub fn stdout(sim: *const HostSim) []const u8 {
        assert(sim.stdout_len <= sim.stdout_buffer.len);
        return sim.stdout_buffer[0..sim.stdout_len];
    }

    pub fn stderr(sim: *const HostSim) []const u8 {
        assert(sim.stderr_len <= sim.stderr_buffer.len);
        return sim.stderr_buffer[0..sim.stderr_len];
    }

    /// Number of handles opened and not closed. Tests assert this is zero after every
    /// operation, including those that failed.
    pub fn open_count(sim: *const HostSim) u32 {
        var count: u32 = 0;
        for (sim.open_files) |slot| {
            if (slot != null) count += 1;
        }
        assert(count <= constants.sim_open_files_max);
        return count;
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

    fn from_context(context: *anyopaque) *HostSim {
        const sim: *HostSim = @ptrCast(@alignCast(context));
        assert(sim.stdout_len <= constants.sim_output_bytes_max);
        assert(sim.stderr_len <= constants.sim_output_bytes_max);
        return sim;
    }

    /// Counts the call and applies the one-shot fault. Every vtable entry starts here.
    fn begin_call(sim: *HostSim) host.Error!void {
        const index = sim.call_count;
        assert(index < std.math.maxInt(u32));
        sim.call_count += 1;
        if (sim.faults.fail_call_index) |fail_index| {
            if (fail_index == index) return sim.faults.fail_call_error;
        }
    }

    fn roll(sim: *HostSim, per_mille: u16) bool {
        assert(per_mille <= 1000);
        // Always draw, even when the probability is zero, so that enabling one fault kind does
        // not shift the random stream of the others.
        const draw = sim.prng.random().uintLessThan(u16, 1000);
        return draw < per_mille;
    }

    fn random_error(sim: *HostSim) host.Error {
        const choices = [_]host.Error{ error.IoFailed, error.OutOfMemory, error.AccessDenied };
        const chosen = choices[sim.prng.random().uintLessThan(usize, choices.len)];
        assert(chosen != error.Interrupted); // Interrupts have their own, retried, path.
        assert(chosen != error.NotFound); // A random error must not mimic an absent file.
        return chosen;
    }

    fn open_read(context: *anyopaque, path: [:0]const u8) host.Error!host.Handle {
        const sim = from_context(context);
        assert(path.len > 0);
        assert(path[path.len] == 0);
        try sim.begin_call();
        if (sim.roll(sim.faults.interrupt_per_mille)) return error.Interrupted;
        if (sim.roll(sim.faults.open_error_per_mille)) return sim.random_error();

        for (sim.files, 0..) |file, file_index| {
            if (!std.mem.eql(u8, file.path, path)) continue;
            if (!file.readable) return error.AccessDenied;
            for (&sim.open_files, 0..) |*slot, slot_index| {
                if (slot.* != null) continue;
                slot.* = .{ .file_index = @intCast(file_index), .offset = 0 };
                return @intCast(slot_index);
            }
            return error.OutOfMemory; // Out of simulated descriptors (EMFILE-like).
        }
        return error.NotFound;
    }

    fn read(context: *anyopaque, handle: host.Handle, buffer: []u8) host.Error!u32 {
        const sim = from_context(context);
        assert(buffer.len > 0);
        assert(handle < constants.sim_open_files_max);
        const open_file = &(sim.open_files[handle] orelse unreachable); // Pair with close().
        try sim.begin_call();
        if (sim.roll(sim.faults.interrupt_per_mille)) return error.Interrupted;
        if (sim.roll(sim.faults.read_error_per_mille)) return sim.random_error();

        const content = sim.files[open_file.file_index].content;
        assert(open_file.offset <= content.len);
        const remaining: u32 = @intCast(content.len - open_file.offset);
        var count: u32 = @min(remaining, @as(u32, @intCast(buffer.len)));
        if (sim.roll(sim.faults.short_read_per_mille) and count > 1) {
            count = sim.prng.random().intRangeAtMost(u32, 1, count - 1);
        }
        const start = open_file.offset;
        @memcpy(buffer[0..count], content[start..][0..count]);
        open_file.offset += count;
        return count;
    }

    fn close(context: *anyopaque, handle: host.Handle) void {
        const sim = from_context(context);
        assert(handle < constants.sim_open_files_max);
        // Closing a handle twice, or one never opened, is a programmer error.
        assert(sim.open_files[handle] != null);
        sim.open_files[handle] = null;
    }

    fn write(context: *anyopaque, stream: host.Stream, bytes: []const u8) host.Error!u32 {
        const sim = from_context(context);
        assert(bytes.len > 0);
        try sim.begin_call();
        if (sim.roll(sim.faults.interrupt_per_mille)) return error.Interrupted;
        if (sim.roll(sim.faults.write_error_per_mille)) return error.NoSpace;

        var count: u32 = @intCast(bytes.len);
        if (sim.roll(sim.faults.short_write_per_mille) and count > 1) {
            count = sim.prng.random().intRangeAtMost(u32, 1, count - 1);
        }
        assert(count > 0);
        assert(count <= bytes.len);
        const buffer, const length = switch (stream) {
            .stdout => .{ &sim.stdout_buffer, &sim.stdout_len },
            .stderr => .{ &sim.stderr_buffer, &sim.stderr_len },
        };
        if (length.* + count > buffer.len) return error.NoSpace;
        @memcpy(buffer[length.*..][0..count], bytes[0..count]);
        length.* += count;
        return count;
    }

    fn uname(context: *anyopaque) host.Error!host.Uname {
        const sim = from_context(context);
        try sim.begin_call();
        assert(sim.uname_value.release.len > 0);
        assert(sim.uname_value.machine.len > 0);
        return sim.uname_value;
    }

    fn stat_mode(context: *anyopaque, path: [:0]const u8) host.Error!u32 {
        const sim = from_context(context);
        assert(path.len > 0);
        try sim.begin_call();
        for (sim.files) |file| {
            if (std.mem.eql(u8, file.path, path)) return file.mode;
        }
        return error.NotFound;
    }

    fn probe(context: *anyopaque, kind: host.ProbeKind) host.Error!host.ProbeOutcome {
        const sim = from_context(context);
        try sim.begin_call();
        return switch (kind) {
            .userns => sim.probes.userns,
            .overlay => sim.probes.overlay,
        };
    }
};

const fixture_files = [_]File{
    .{ .path = "/proc/sys/user/max_user_namespaces", .content = "15000\n" },
    .{ .path = "/etc/shadow", .content = "secret", .readable = false },
    .{ .path = "/sys/fs/cgroup", .content = "", .mode = 0o040755 },
};

test "sim serves a file, a missing file and an unreadable file" {
    // Goal: the model answers the three basic cases the way the real kernel does.
    var sim: HostSim = undefined;
    sim.init(1, &fixture_files);
    const subject = sim.interface();
    var buffer: [64]u8 = undefined;

    const content = try subject.read_file("/proc/sys/user/max_user_namespaces", &buffer);
    try std.testing.expectEqualStrings("15000\n", content);
    try std.testing.expectError(error.NotFound, subject.read_file("/nope", &buffer));
    try std.testing.expectError(error.AccessDenied, subject.read_file("/etc/shadow", &buffer));
    try std.testing.expectEqual(@as(u32, 0), sim.open_count());
}

test "sim empty file reads as zero bytes and exact-fit file is not too large" {
    // Goal: both edges of the size limit. An empty file succeeds with length 0; a file of
    // exactly buffer.len succeeds; one byte more is FileTooLarge.
    const files = [_]File{
        .{ .path = "/empty", .content = "" },
        .{ .path = "/exact", .content = "12345678" },
        .{ .path = "/over", .content = "123456789" },
    };
    var sim: HostSim = undefined;
    sim.init(2, &files);
    const subject = sim.interface();
    var buffer: [8]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 0), (try subject.read_file("/empty", &buffer)).len);
    try std.testing.expectEqualStrings("12345678", try subject.read_file("/exact", &buffer));
    try std.testing.expectError(error.FileTooLarge, subject.read_file("/over", &buffer));
    try std.testing.expectEqual(@as(u32, 0), sim.open_count());
}

test "short reads still deliver the whole file" {
    // Goal: the shared read loop in host.zig reassembles short reads. Method: every read is
    // short for many seeds; content must always come back whole.
    const text = "the quick brown fox jumps over the lazy dog";
    const files = [_]File{.{ .path = "/text", .content = text }};
    var sim: HostSim = undefined;
    for (0..200) |seed| {
        sim.init(seed, &files);
        sim.faults.short_read_per_mille = 1000;
        var buffer: [128]u8 = undefined;
        try std.testing.expectEqualStrings(text, try sim.interface().read_file("/text", &buffer));
        try std.testing.expectEqual(@as(u32, 0), sim.open_count());
    }
}

test "interrupts are retried, and endless interrupts give up with an error" {
    // Goal: EINTR below the retry bound is invisible; at 1000 per mille it is IoFailed and
    // the handle is still closed (open() itself is interrupted here, so none is opened).
    const files = [_]File{.{ .path = "/text", .content = "abc" }};
    var sim: HostSim = undefined;
    var buffer: [16]u8 = undefined;

    sim.init(3, &files);
    sim.faults.interrupt_per_mille = 300;
    for (0..100) |_| {
        const got = sim.interface().read_file("/text", &buffer) catch |err| {
            try std.testing.expectEqual(error.IoFailed, err); // Retries exhausted is legal.
            continue;
        };
        try std.testing.expectEqualStrings("abc", got);
    }

    sim.init(4, &files);
    sim.faults.interrupt_per_mille = 1000;
    try std.testing.expectError(error.IoFailed, sim.interface().read_file("/text", &buffer));
    try std.testing.expectEqual(@as(u32, 0), sim.open_count());
}

test "a read error mid-file propagates and still closes the handle" {
    // Goal: an operating error is reported, never turned into a partial success, and nothing
    // leaks. Method: fail the second host call (the first read) with each error kind.
    const files = [_]File{.{ .path = "/text", .content = "abc" }};
    var sim: HostSim = undefined;
    var buffer: [16]u8 = undefined;
    const kinds = [_]host.Error{ error.IoFailed, error.OutOfMemory, error.AccessDenied };
    for (kinds) |kind| {
        sim.init(5, &files);
        sim.faults.fail_call_index = 1;
        sim.faults.fail_call_error = kind;
        try std.testing.expectError(kind, sim.interface().read_file("/text", &buffer));
        try std.testing.expectEqual(@as(u32, 0), sim.open_count());
    }
}

test "walking a one-shot failure across every call leaves no handle open" {
    // Goal: crash-at-any-step. Method: fail call 0, 1, 2, ... of a read; once the index is past
    // the last call the read succeeds, and in every case no handle leaks.
    const files = [_]File{.{ .path = "/text", .content = "abcdef" }};
    var sim: HostSim = undefined;
    var buffer: [16]u8 = undefined;
    var succeeded = false;
    for (0..8) |index| {
        sim.init(6, &files);
        sim.faults.fail_call_index = @intCast(index);
        if (sim.interface().read_file("/text", &buffer)) |got| {
            try std.testing.expectEqualStrings("abcdef", got);
            succeeded = true;
        } else |_| {}
        try std.testing.expectEqual(@as(u32, 0), sim.open_count());
    }
    try std.testing.expect(succeeded);
}

test "write_all reassembles short writes and reports a full sink" {
    // Goal: output arrives whole despite short writes, and a sink that fills up is NoSpace.
    var sim: HostSim = undefined;
    sim.init(7, &fixture_files);
    sim.faults.short_write_per_mille = 1000;
    try sim.interface().write_all(.stdout, "hello, world\n");
    try sim.interface().write_all(.stderr, "oops\n");
    try std.testing.expectEqualStrings("hello, world\n", sim.stdout());
    try std.testing.expectEqualStrings("oops\n", sim.stderr());

    sim.stdout_len = constants.sim_output_bytes_max - 2;
    try std.testing.expectError(error.NoSpace, sim.interface().write_all(.stdout, "abc"));
}

test "uname, stat_mode and probe answer from the model" {
    // Goal: the remaining vtable entries return what the fixture says, and absent paths fail.
    var sim: HostSim = undefined;
    sim.init(8, &fixture_files);
    sim.probes.userns = .denied;
    const subject = sim.interface();
    try std.testing.expectEqualStrings("6.8.0-sim", (try subject.uname()).release.slice());
    try std.testing.expectEqual(@as(u32, 0o040755), try subject.stat_mode("/sys/fs/cgroup"));
    try std.testing.expectError(error.NotFound, subject.stat_mode("/missing"));
    try std.testing.expectEqual(host.ProbeOutcome.denied, try subject.probe(.userns));
    try std.testing.expectEqual(host.ProbeOutcome.ok, try subject.probe(.overlay));
}

test "the same seed reproduces the same fault schedule" {
    // Goal: determinism, the property every fuzzer depends on. Method: two sims, one seed,
    // same faults; record the outcome of 50 reads and compare.
    const files = [_]File{.{ .path = "/text", .content = "0123456789" }};
    var first: HostSim = undefined;
    var second: HostSim = undefined;
    first.init(99, &files);
    second.init(99, &files);
    first.faults = .{ .read_error_per_mille = 300, .short_read_per_mille = 500 };
    second.faults = first.faults;
    var buffer_first: [16]u8 = undefined;
    var buffer_second: [16]u8 = undefined;
    for (0..50) |_| {
        const got_first = first.interface().read_file("/text", &buffer_first);
        const got_second = second.interface().read_file("/text", &buffer_second);
        if (got_first) |bytes| {
            try std.testing.expectEqualStrings(bytes, try got_second);
        } else |err| {
            try std.testing.expectError(err, got_second);
        }
    }
}
