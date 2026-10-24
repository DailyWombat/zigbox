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
    /// Directory under which the overlay probe makes its scratch directory.
    scratch_parent: [:0]const u8 = "/tmp",
    probe_timeout_ms: u32 = constants.probe_timeout_ms,
    /// Test hook: replaces the body of the probe child, to exercise timeout, signal and
    /// exit-code handling without depending on what the host kernel allows.
    child_hook: ?*const fn () noreturn = null,

    pub fn interface(self: *HostReal) host.Host {
        return .{ .context = self, .vtable = &vtable };
    }

    const vtable: host.VTable = .{
        .open_read = open_read,
        .read = read,
        .close = close,
        .write = write,
        .uname = uname,
        .stat = stat,
        .read_capability = read_capability,
        .seccomp_mode = seccomp_mode,
        .is_terminal = is_terminal,
        .uid = uid,
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
        assert(handle <= std.math.maxInt(i32)); // A descriptor, as open_read produced it.
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

    fn stat(context: *anyopaque, path: [:0]const u8) host.Error!host.Stat {
        _ = from_context(context);
        assert(path.len > 0);
        const mask: linux.STATX = .{ .TYPE = true, .MODE = true, .UID = true };
        var buffer: linux.Statx = undefined;
        try check(linux.statx(linux.AT.FDCWD, path.ptr, 0, mask, &buffer));
        // The kernel must honour the mask for these fields; a clear bit would mean garbage.
        assert(buffer.mask.TYPE);
        assert(buffer.mask.MODE);
        assert(buffer.mask.UID);
        return .{ .mode = buffer.mode, .uid = buffer.uid };
    }

    fn read_capability(
        context: *anyopaque,
        path: [:0]const u8,
        buffer: []u8,
    ) host.Error!u32 {
        _ = from_context(context);
        assert(path.len > 0);
        assert(buffer.len > 0);
        const result = linux.getxattr(path.ptr, "security.capability", buffer.ptr, buffer.len);
        if (linux.errno(result) == .OPNOTSUPP) return error.NoData; // Filesystem without xattrs.
        try check(result);
        assert(result <= buffer.len);
        return @intCast(result);
    }

    fn seccomp_mode(context: *anyopaque) host.Error!u32 {
        _ = from_context(context);
        const result = linux.prctl(@backingInt(linux.PR.GET_SECCOMP), 0, 0, 0, 0);
        try check(result);
        assert(result <= std.math.maxInt(u32));
        assert(result <= 2);
        return @intCast(result);
    }

    fn is_terminal(context: *anyopaque, stream: host.Stream) bool {
        _ = from_context(context);
        const descriptor: i32 = switch (stream) {
            .stdout => linux.STDOUT_FILENO,
            .stderr => linux.STDERR_FILENO,
        };
        var attributes: linux.termios = undefined;
        return linux.errno(linux.tcgetattr(descriptor, &attributes)) == .SUCCESS;
    }

    fn uid(context: *anyopaque) u32 {
        _ = from_context(context);
        return linux.getuid();
    }

    fn probe(context: *anyopaque, kind: host.ProbeKind) host.Error!host.ProbeOutcome {
        const self = from_context(context);
        assert(self.probe_timeout_ms >= constants.probe_poll_ms);
        assert(self.scratch_parent.len > 0);
        return probe_run(self, kind);
    }

    /// Converts a raw syscall return value into an error, or passes success through.
    fn check(result: usize) host.Error!void {
        const code = linux.errno(result);
        if (code == .SUCCESS) return;
        assert(code != .SUCCESS);
        assert(@backingInt(code) != 0);
        return switch (code) {
            .INTR => error.Interrupted,
            .AGAIN => error.WouldBlock,
            .NOENT, .NOTDIR => error.NotFound,
            .ACCES, .PERM => error.AccessDenied,
            .NOSPC => error.NoSpace,
            .NOMEM => error.OutOfMemory,
            .NAMETOOLONG => error.PathTooLong,
            .NOSYS => error.Unsupported,
            .NODATA => error.NoData,
            .RANGE => error.FileTooLarge,
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

// ---- Probes ----------------------------------------------------------------------------------
//
// A probe forks a child that tries the operation and reports through its exit code, so a crash,
// hang or kernel oddity cannot touch the caller. The child never returns into the caller's
// code: it ends with exit_group, so no deferred cleanup of the parent runs in it. The parent
// bounds the wait, kills and reaps on timeout, and removes the scratch directory on every path.

/// The unprivileged identity probes run as when the caller is root. Root can create user
/// namespaces even where ordinary users cannot, so probing as root would wrongly pass.
const nobody_id: u32 = 65534;

const child_exit_ok: u8 = 0;
const child_exit_refused_namespace: u8 = 10;
const child_exit_refused_mount: u8 = 11;
/// The namespace exists, but writing setgroups/uid_map/gid_map was refused.
const child_exit_refused_map: u8 = 13;
const child_exit_failed: u8 = 12;

const scratch_names = [_][:0]const u8{ "work/work", "work", "upper", "lower", "merged" };

/// A scratch directory for the overlay probe: `root` plus fixed subdirectories made by the child.
const Scratch = struct {
    root: [constants.probe_scratch_bytes_max + 1]u8,
    root_len: u32,
    created: bool,

    /// `give_to` is set only when the caller is root: the unprivileged child then needs to own the
    /// directory. An ordinary caller already owns what it creates (and may not chown to a group
    /// it is not in).
    fn create(scratch: *Scratch, parent: []const u8, give_to: ?u32) host.Error!void {
        scratch.created = false;
        scratch.root_len = 0;
        if (parent.len == 0) return error.InvalidPath;
        if (parent.len > constants.probe_scratch_parent_bytes_max) return error.PathTooLong;
        const process: u32 = @intCast(linux.getpid());
        for (0..constants.probe_dir_attempts_max) |attempt| {
            const formatted = std.fmt.bufPrintSentinel(&scratch.root, "{s}/zbx-doctor-{d}-{d}", .{
                parent, process, attempt,
            }, 0) catch return error.PathTooLong;
            const result = linux.mkdir(formatted.ptr, 0o700);
            if (linux.errno(result) == .EXIST) continue;
            try HostReal.check(result);
            scratch.root_len = @intCast(formatted.len);
            scratch.created = true;
            if (give_to) |owner| try HostReal.check(linux.chown(formatted.ptr, owner, owner));
            assert(scratch.root_len > parent.len);
            assert(scratch.root[scratch.root_len] == 0);
            return;
        }
        return error.IoFailed;
    }

    fn join(scratch: *const Scratch, buffer: []u8, name: []const u8) [:0]const u8 {
        assert(scratch.created);
        assert(name.len > 0);
        const root = scratch.root[0..scratch.root_len];
        // Cannot fail: root is at most probe_scratch_bytes_max and buffers are sized for it.
        const joined = std.fmt.bufPrintSentinel(buffer, "{s}/{s}", .{ root, name }, 0);
        // Cannot fail: same bound as above.
        const result = joined catch unreachable;
        assert(result.len > root.len);
        return result;
    }

    /// Removes everything the child may have made, then the root. Missing entries are fine.
    fn remove(scratch: *const Scratch) void {
        if (!scratch.created) return;
        assert(scratch.root_len > 0);
        var buffer: [constants.probe_scratch_bytes_max + 16]u8 = undefined;
        for (scratch_names) |name| {
            _ = linux.rmdir(scratch.join(&buffer, name).ptr);
        }
        _ = linux.rmdir(scratch.root[0..scratch.root_len :0].ptr);
    }
};

fn probe_run(self: *HostReal, kind: host.ProbeKind) host.Error!host.ProbeOutcome {
    const caller = linux.getuid();
    const give_to: ?u32 = if (caller == 0) nobody_id else null;
    var scratch: Scratch = undefined;
    scratch.created = false;
    // Registered before create(): a failure after the directory exists (chown) must still
    // remove it.
    defer scratch.remove();
    if (kind == .overlay) try scratch.create(self.scratch_parent, give_to);

    var options: [3 * constants.probe_scratch_bytes_max + 64]u8 = undefined;
    const options_text = overlay_options(&options, &scratch);

    const forked = linux.fork();
    try HostReal.check(forked);
    if (forked == 0) child_main(self, kind, &scratch, options_text, caller == 0);
    const child: i32 = @intCast(forked);
    assert(child > 0);
    assert(scratch.created == (kind == .overlay));
    return wait_for_child(child, kind, self.probe_timeout_ms);
}

/// The overlay mount data, built in the parent so the child allocates and formats nothing.
fn overlay_options(buffer: []u8, scratch: *const Scratch) [:0]const u8 {
    if (!scratch.created) return "";
    const root = scratch.root[0..scratch.root_len];
    // userxattr: a mount made from a user namespace must keep its metadata in user.* xattrs.
    const format = "userxattr,lowerdir={s}/lower,upperdir={s}/upper,workdir={s}/work";
    // Cannot fail: the buffer holds three roots plus the fixed text, by construction above.
    const formatted = std.fmt.bufPrintSentinel(buffer, format, .{ root, root, root }, 0);
    // Cannot fail: same bound as above.
    const result = formatted catch unreachable;
    assert(std.mem.startsWith(u8, result, "userxattr,"));
    assert(result.len > 3 * root.len);
    return result;
}

/// Runs in the forked child and never returns.
fn child_main(
    self: *const HostReal,
    kind: host.ProbeKind,
    scratch: *const Scratch,
    options: [:0]const u8,
    drop_privileges: bool,
) noreturn {
    if (drop_privileges) {
        if (!drop_to_nobody()) linux.exit_group(child_exit_failed);
    }
    if (self.child_hook) |hook| hook();
    assert(scratch.created == (kind == .overlay));
    if (kind == .overlay) assert(options.len > 0);

    // The ids to map are read here, before the namespace exists: inside an unmapped user
    // namespace getuid() and getgid() return the overflow id (65534), not the caller's.
    const uid = linux.getuid();
    const gid = linux.getgid();
    assert(uid != 0); // Root was dropped to an unprivileged id above, or never was root.
    // A caller that changed its ids is not dumpable, which makes /proc/self/*_map root-owned.
    const dumpable = linux.prctl(@backingInt(linux.PR.SET_DUMPABLE), 1, 0, 0, 0);
    if (linux.errno(dumpable) != .SUCCESS) linux.exit_group(child_exit_failed);

    const flags: usize = switch (kind) {
        .userns => linux.CLONE.NEWUSER,
        .overlay => linux.CLONE.NEWUSER | linux.CLONE.NEWNS,
    };
    const unshared = linux.errno(linux.unshare(flags));
    if (unshared != .SUCCESS) {
        linux.exit_group(refusal_exit(unshared, child_exit_refused_namespace));
    }
    // Map the caller's single id to root inside, as zbx itself will. A process with no mapping
    // can create the namespace but not do anything useful in it (overlay mounts are refused).
    if (!map_single_ids(uid, gid)) linux.exit_group(child_exit_refused_map);
    if (kind == .userns) linux.exit_group(child_exit_ok);

    // Keep the mount from propagating back to the caller's namespace.
    const private = linux.mount(null, "/", null, linux.MS.REC | linux.MS.PRIVATE, 0);
    if (linux.errno(private) != .SUCCESS) linux.exit_group(child_exit_refused_mount);
    linux.exit_group(overlay_mount(scratch, options));
}

/// Writes `/proc/self/{setgroups,gid_map,uid_map}` so that `uid` and `gid` (the ids the process
/// had before it entered the namespace) map to 0 inside. A map may only name ids the caller owns.
fn map_single_ids(uid: u32, gid: u32) bool {
    var line: [32]u8 = undefined;
    if (!write_proc("/proc/self/setgroups", "deny")) return false;
    const gid_line = std.fmt.bufPrint(&line, "0 {d} 1\n", .{gid}) catch return false;
    if (!write_proc("/proc/self/gid_map", gid_line)) return false;
    const uid_line = std.fmt.bufPrint(&line, "0 {d} 1\n", .{uid}) catch return false;
    return write_proc("/proc/self/uid_map", uid_line);
}

fn write_proc(path: [:0]const u8, bytes: []const u8) bool {
    assert(bytes.len > 0);
    assert(std.mem.startsWith(u8, path, "/proc/self/")); // Only our own process's files.
    const opened = linux.open(path.ptr, .{ .ACCMODE = .WRONLY, .CLOEXEC = true }, 0);
    if (linux.errno(opened) != .SUCCESS) return false;
    const descriptor: i32 = @intCast(opened);
    const written = linux.write(descriptor, bytes.ptr, bytes.len);
    _ = linux.close(descriptor);
    return linux.errno(written) == .SUCCESS and written == bytes.len;
}

/// Creates the overlay directories and mounts. Returns the child's exit code.
fn overlay_mount(scratch: *const Scratch, options: [:0]const u8) u8 {
    assert(scratch.created);
    assert(options.len > 0);
    var buffer: [constants.probe_scratch_bytes_max + 16]u8 = undefined;
    const directories = [_][:0]const u8{ "lower", "upper", "work", "merged" };
    for (directories) |name| {
        const made = linux.errno(linux.mkdir(scratch.join(&buffer, name).ptr, 0o700));
        if (made != .SUCCESS) return child_exit_failed;
    }
    const target = scratch.join(&buffer, "merged");
    const data = @intFromPtr(options.ptr);
    const mounted = linux.errno(linux.mount("overlay", target.ptr, "overlay", 0, data));
    if (mounted == .SUCCESS) return child_exit_ok;
    return refusal_exit(mounted, child_exit_refused_mount);
}

/// Errors that mean "this system says no" map to `refusal`; anything else is a probe failure.
fn refusal_exit(code: linux.E, refusal: u8) u8 {
    assert(code != .SUCCESS);
    const result: u8 = switch (code) {
        .PERM, .ACCES, .NOSPC, .INVAL, .NODEV, .NOSYS, .OPNOTSUPP => refusal,
        else => child_exit_failed,
    };
    assert(result != child_exit_ok); // A refusal is never reported as success.
    return result;
}

fn drop_to_nobody() bool {
    const no_groups = [_]linux.gid_t{};
    if (linux.errno(linux.setgroups(0, &no_groups)) != .SUCCESS) return false;
    if (linux.errno(linux.setresgid(nobody_id, nobody_id, nobody_id)) != .SUCCESS) return false;
    if (linux.errno(linux.setresuid(nobody_id, nobody_id, nobody_id)) != .SUCCESS) return false;
    // Changing ids made the process undumpable, which makes its /proc/self files root-owned
    // and unwritable for the uid_map step; make it dumpable again.
    const dumpable = linux.prctl(@backingInt(linux.PR.SET_DUMPABLE), 1, 0, 0, 0);
    if (linux.errno(dumpable) != .SUCCESS) return false;
    // Dropping the user id must also have dropped every capability; check, do not assume.
    return linux.getuid() == nobody_id and linux.geteuid() == nobody_id;
}

fn sleep_poll_interval() void {
    const interval: linux.timespec = .{
        .sec = 0,
        .nsec = @intCast(constants.probe_poll_ms * std.time.ns_per_ms),
    };
    _ = linux.nanosleep(&interval, null);
}

/// Polls for the child with a bounded number of steps; on timeout kills and reaps it.
fn wait_for_child(child: i32, kind: host.ProbeKind, timeout_ms: u32) host.ProbeOutcome {
    assert(child > 0);
    assert(timeout_ms >= constants.probe_poll_ms);
    const polls = @divExact(timeout_ms, constants.probe_poll_ms);
    var status: i32 = 0;
    for (0..polls + 1) |_| {
        const result = linux.wait4(child, &status, linux.W.NOHANG, null);
        if (result == child) return classify_status(@bitCast(status), kind);
        if (linux.errno(result) == .CHILD) return .failed; // Reaped elsewhere: cannot happen.
        sleep_poll_interval();
    }
    _ = linux.kill(child, .KILL);
    for (0..constants.probe_reap_polls_max) |_| {
        if (linux.wait4(child, &status, linux.W.NOHANG, null) == child) return .timed_out;
        sleep_poll_interval();
    }
    return .timed_out; // Unreapable (uninterruptible sleep): reported, and the zombie is harmless.
}

fn classify_status(status: u32, kind: host.ProbeKind) host.ProbeOutcome {
    if (linux.W.IFSIGNALED(status)) return .signaled;
    if (!linux.W.IFEXITED(status)) return .failed;
    return switch (linux.W.EXITSTATUS(status)) {
        child_exit_ok => .ok,
        child_exit_refused_namespace => if (kind == .userns) .denied else .setup_denied,
        child_exit_refused_map => .map_denied,
        child_exit_refused_mount => .denied,
        else => .failed,
    };
}

// ---- Probe tests -----------------------------------------------------------------------------

fn hook_sleep_forever() noreturn {
    const interval: linux.timespec = .{ .sec = 1, .nsec = 0 };
    while (true) _ = linux.nanosleep(&interval, null);
}

fn hook_kill_self() noreturn {
    _ = linux.kill(linux.getpid(), .KILL);
    linux.exit_group(0);
}

fn hook_exit_ok() noreturn {
    linux.exit_group(child_exit_ok);
}

fn hook_exit_namespace() noreturn {
    linux.exit_group(child_exit_refused_namespace);
}

fn hook_exit_map() noreturn {
    linux.exit_group(child_exit_refused_map);
}

fn hook_exit_mount() noreturn {
    linux.exit_group(child_exit_refused_mount);
}

/// Exits 0 only if the child is not root: proves privileges were dropped before the hook ran.
fn hook_exit_ok_if_unprivileged() noreturn {
    linux.exit_group(if (linux.getuid() == 0) 1 else child_exit_ok);
}

fn hook_exit_other() noreturn {
    linux.exit_group(77);
}

/// True if no child of this process remains, reaped or not (wait4 says ECHILD).
fn no_children_left() bool {
    var status: i32 = 0;
    const result = linux.wait4(-1, &status, linux.W.NOHANG, null);
    return linux.errno(result) == .CHILD;
}

test "probe child outcomes map from exit status, signal and timeout, and are all reaped" {
    // Goal: every way a probe child can end becomes the right outcome and leaves no zombie.
    // Method: replace the child body with hooks (so the answer does not depend on this
    // kernel), use a short timeout for the hanging child.
    const Case = struct {
        hook: *const fn () noreturn,
        kind: host.ProbeKind,
        expected: host.ProbeOutcome,
    };
    const cases = [_]Case{
        .{ .hook = hook_exit_ok, .kind = .userns, .expected = .ok },
        .{ .hook = hook_exit_namespace, .kind = .userns, .expected = .denied },
        .{ .hook = hook_exit_namespace, .kind = .overlay, .expected = .setup_denied },
        .{ .hook = hook_exit_mount, .kind = .overlay, .expected = .denied },
        .{ .hook = hook_exit_map, .kind = .userns, .expected = .map_denied },
        .{ .hook = hook_exit_map, .kind = .overlay, .expected = .map_denied },
        .{ .hook = hook_exit_other, .kind = .userns, .expected = .failed },
        .{ .hook = hook_kill_self, .kind = .userns, .expected = .signaled },
        .{ .hook = hook_sleep_forever, .kind = .userns, .expected = .timed_out },
    };
    for (cases) |case| {
        var real: HostReal = .{ .child_hook = case.hook, .probe_timeout_ms = 50 };
        const outcome = try real.interface().probe(case.kind);
        try std.testing.expectEqual(case.expected, outcome);
        try std.testing.expect(no_children_left());
    }
}

test "the probe child runs unprivileged even when the caller is root" {
    // Goal: root can create user namespaces where ordinary users cannot, so a probe run as root
    // would pass wrongly. Method: the hook runs after the privilege drop and reports whether the
    // child is still uid 0. When this test runs as an ordinary user the child never was root.
    var real: HostReal = .{ .child_hook = hook_exit_ok_if_unprivileged, .probe_timeout_ms = 1000 };
    try std.testing.expectEqual(host.ProbeOutcome.ok, try real.interface().probe(.userns));
    try std.testing.expect(no_children_left());
}

/// Forks a process that becomes `uid`:`gid` (dumpable, as a normal login is), runs the real
/// probe there, and returns its outcome. Null if it could not be run. Needs root to drop ids.
fn probe_as(uid: u32, gid: u32, kind: host.ProbeKind) ?host.ProbeOutcome {
    const forked = linux.fork();
    if (linux.errno(forked) != .SUCCESS) return null;
    if (forked == 0) {
        const no_groups = [_]linux.gid_t{};
        var ok = linux.errno(linux.setgroups(0, &no_groups)) == .SUCCESS;
        ok = ok and linux.errno(linux.setresgid(gid, gid, gid)) == .SUCCESS;
        ok = ok and linux.errno(linux.setresuid(uid, uid, uid)) == .SUCCESS;
        const dumpable = linux.prctl(@backingInt(linux.PR.SET_DUMPABLE), 1, 0, 0, 0);
        if (!ok or linux.errno(dumpable) != .SUCCESS) linux.exit_group(99);
        var real: HostReal = .{ .probe_timeout_ms = 2000 };
        const outcome = real.interface().probe(kind) catch linux.exit_group(98);
        linux.exit_group(@intCast(@backingInt(outcome)));
    }
    var status: i32 = 0;
    if (linux.wait4(@intCast(forked), &status, 0, null) != forked) return null;
    const bits: u32 = @bitCast(status);
    if (!linux.W.IFEXITED(bits)) return null;
    const code = linux.W.EXITSTATUS(bits);
    if (code >= std.meta.fieldNames(host.ProbeOutcome).len) return null;
    return @fromBackingInt(@intCast(code));
}

test "the real probe works for an ordinary user whose ids are neither root nor 65534" {
    // Goal: regression for reading getuid()/getgid() after unshare, which returns the overflow
    // id 65534 and maps an id the caller does not own (EPERM). The old tests ran as root, which
    // is dropped to 65534, the one id for which that bug is invisible. Method: run the real
    // probe as uid 4242 and gid 4343 (different from each other, root and 65534). It must agree
    // with the probe run as nobody; if this kernel refuses the probe for nobody too, skip.
    if (linux.getuid() != 0) return error.SkipZigTest; // Dropping ids needs root.
    const kinds = [_]host.ProbeKind{ .userns, .overlay };
    for (kinds) |kind| {
        const baseline = probe_as(65534, 65534, kind) orelse return error.SkipZigTest;
        if (baseline != .ok) return error.SkipZigTest;
        const other = probe_as(4242, 4343, kind) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqual(host.ProbeOutcome.ok, other);
    }
    try std.testing.expect(no_children_left());
}

test "the overlay probe leaves its scratch directory empty and removable" {
    // Goal: cleanup on every path. Method: point the scratch parent at a fresh directory, run
    // the overlay probe for real (whatever this kernel answers) and with each hook, then rmdir
    // the parent: it only succeeds if nothing was left behind.
    var name_buffer: [64]u8 = undefined;
    const format = "/tmp/zbx-test-{d}";
    const parent = try std.fmt.bufPrintSentinel(&name_buffer, format, .{linux.getpid()}, 0);
    try HostReal.check(linux.mkdir(parent.ptr, 0o755));
    defer _ = linux.rmdir(parent.ptr);

    var real: HostReal = .{ .scratch_parent = parent, .probe_timeout_ms = 2000 };
    _ = try real.interface().probe(.overlay);
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.rmdir(parent.ptr)));
    try HostReal.check(linux.mkdir(parent.ptr, 0o755));

    const hooks = [_]*const fn () noreturn{ hook_exit_ok, hook_kill_self, hook_sleep_forever };
    for (hooks) |hook| {
        real = .{ .scratch_parent = parent, .probe_timeout_ms = 50, .child_hook = hook };
        _ = try real.interface().probe(.overlay);
        try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.rmdir(parent.ptr)));
        try HostReal.check(linux.mkdir(parent.ptr, 0o755));
    }
    try std.testing.expect(no_children_left());
}

test "the real userns probe answers with a defined outcome" {
    // Goal: the unhooked probe runs end to end on this machine. The answer depends on the
    // kernel, so only its shape is asserted: not a hang, not a leak.
    var real: HostReal = .{ .probe_timeout_ms = 2000 };
    const outcome = try real.interface().probe(.userns);
    try std.testing.expect(outcome != .timed_out);
    try std.testing.expect(no_children_left());
}

test "real stat reports owner and type, capability read reports absence" {
    // Goal: stat returns the mode and owner of a root-owned directory; a file without the
    // xattr gives NoData rather than success; seccomp and uid answer.
    var real: HostReal = .{};
    const subject = real.interface();
    const result = try subject.stat("/proc");
    try std.testing.expectEqual(@as(u32, std.posix.S.IFDIR), result.mode & std.posix.S.IFMT);
    try std.testing.expectEqual(@as(u32, 0), result.uid);
    try std.testing.expectError(error.NotFound, subject.stat("/zigbox-does-not-exist"));

    var buffer: [constants.capability_bytes_max]u8 = undefined;
    try std.testing.expectError(error.NoData, subject.read_capability("/proc/self/stat", &buffer));
    try std.testing.expectError(error.NotFound, subject.read_capability("/zigbox-nope", &buffer));
    try std.testing.expectEqual(linux.getuid(), subject.uid());
    const mode = try subject.seccomp_mode();
    try std.testing.expect(mode <= 2);
}
