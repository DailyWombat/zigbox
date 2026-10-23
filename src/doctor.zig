//! `zbx doctor`: tells, truthfully, whether this machine can run Zigbox.
//!
//! Three phases (docs/briefs/M0-doctor.md):
//!   gather    reads raw facts through the `Host` into a fixed-size `Facts`. No policy: it records
//!             what each read returned, including the error, and nothing else.
//!   evaluate  a pure function from `Facts` to `Report`. Every question of policy (what counts as
//!             ok, which fix to name) is decided here, by the `evaluate_*` functions.
//!   render    a pure function from `Report` to text.
//!
//! Status and exit code:
//!   ok    the requirement is met.
//!   FAIL  the requirement is not met, or could not be checked. A failed read, a probe that
//!         could not run and a malformed file are all FAIL with the reason: a fault is never
//!         reported as ok, and never as warn. A FAIL always carries a one-line fix.
//!   warn  the requirement is demonstrably met by a direct test, yet a related setting says it
//!         should not be. Today that is one situation: the user-namespace probe succeeded but
//!         a sysctl (`kernel.unprivileged_userns_clone=0` or
//!         `kernel.apparmor_restrict_unprivileged_userns=1`) says unconfined users are refused,
//!         which happens when this process runs under an AppArmor profile that allows it. A warn
//!         has no fix line, because nothing has to be fixed for this process.
//!   The exit code is 0 if no check is FAIL, 1 otherwise. A warn does not change it.
//!
//! Running as root proves nothing about ordinary users, so nothing here lets uid 0 pass:
//! probes run in a child that drops to an unprivileged id first (host_real.zig), the subid
//! check needs a range for the real uid or user name whoever that is, and file owners and
//! modes are read from the files, not inferred from the caller.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const host_mod = @import("host.zig");
const parse = @import("parse.zig");
const text_util = @import("text.zig");

const Host = host_mod.Host;

pub const Status = enum { ok, fail, warn };

pub const CheckId = enum { kernel, userns, cgroup, overlay, subid, seccomp };

pub const Detail = text_util.Bounded(constants.detail_bytes_max);
pub const Fix = text_util.Bounded(constants.fix_bytes_max);

pub const Check = struct {
    id: CheckId,
    status: Status,
    detail: Detail,
    fix: Fix,

    fn start(check: *Check, id: CheckId) void {
        check.id = id;
        check.status = .ok;
        check.detail = .{};
        check.fix = .{};
        assert(check.detail.len == 0);
        assert(check.fix.len == 0);
    }

    fn pass(check: *Check, comptime format: []const u8, args: anytype) void {
        assert(check.fix.len == 0); // A passing check never carries a fix.
        check.status = .ok;
        check.detail.print(format, args);
        assert(check.detail.len > 0);
    }

    fn warning(check: *Check, comptime format: []const u8, args: anytype) void {
        assert(check.fix.len == 0); // A warning has nothing to fix.
        check.status = .warn;
        check.detail.print(format, args);
        assert(check.detail.len > 0);
    }

    /// Sets the detail only; follow with `fix_with`.
    fn problem(check: *Check, comptime format: []const u8, args: anytype) void {
        assert(check.fix.len == 0); // The fix is added after the problem is stated.
        check.status = .fail;
        check.detail.print(format, args);
        assert(check.detail.len > 0);
    }

    fn fix_with(check: *Check, comptime format: []const u8, args: anytype) void {
        assert(check.status == .fail);
        check.fix.print(format, args);
        assert(check.fix.len > 0);
    }
};

pub const Report = struct {
    checks: [constants.doctor_checks_count]Check,

    pub fn exit_code(report: *const Report) u8 {
        // The checks are always in the fixed order the renderer and the fuzzers rely on.
        assert(report.checks[0].id == .kernel);
        assert(report.checks[report.checks.len - 1].id == .seccomp);
        for (report.checks) |check| {
            if (check.status == .fail) return constants.exit_failed;
        }
        return constants.exit_ok;
    }

    /// Structural invariants every report must satisfy, whatever the host looked like.
    pub fn validate(report: *const Report) void {
        for (report.checks, 0..) |check, index| {
            assert(@backingInt(check.id) == index);
            assert(check.detail.len > 0);
            switch (check.status) {
                .ok, .warn => assert(check.fix.len == 0),
                .fail => assert(check.fix.len > 0),
            }
        }
    }
};

// ---- Facts ---------------------------------------------------------------------------------

/// One file read: the bytes and length on success, the error otherwise.
fn Slot(comptime capacity: u32) type {
    return struct {
        const Self = @This();
        bytes: [capacity]u8 = undefined,
        len: u32 = 0,
        err: ?host_mod.Error = null,
        attempted: bool = false,

        fn reset(slot: *Self) void {
            slot.len = 0;
            slot.err = null;
            slot.attempted = false;
        }

        fn load(slot: *Self, host: Host, path: []const u8) void {
            assert(path.len > 0);
            slot.reset();
            slot.attempted = true;
            const content = host.read_file(path, &slot.bytes) catch |err| {
                slot.err = err;
                return;
            };
            slot.len = @intCast(content.len);
            assert(slot.len <= capacity);
            assert(slot.err == null);
        }

        fn text(slot: *const Self) []const u8 {
            assert(slot.attempted);
            assert(slot.err == null);
            return slot.bytes[0..slot.len];
        }
    };
}

const ProbeFact = struct {
    outcome: host_mod.ProbeOutcome = .ok,
    err: ?host_mod.Error = null,

    /// True if the probe ran and gave exactly this outcome.
    fn is(fact: ProbeFact, outcome: host_mod.ProbeOutcome) bool {
        if (fact.err != null) return false;
        return fact.outcome == outcome;
    }

    fn run(fact: *ProbeFact, host: Host, kind: host_mod.ProbeKind) void {
        fact.err = null;
        fact.outcome = host.probe(kind) catch |err| {
            fact.err = err;
            // A probe never reads a file, so it cannot report the size-limit error.
            assert(err != error.FileTooLarge);
            return;
        };
        assert(fact.err == null);
    }
};

/// One `stat` of a path: the result or the error.
const StatFact = struct {
    stat: host_mod.Stat = .{ .mode = 0, .uid = 0 },
    err: ?host_mod.Error = null,
    attempted: bool = false,
};

/// A candidate location of newuidmap or newgidmap.
const Binary = struct {
    stat: host_mod.Stat = .{ .mode = 0, .uid = 0 },
    stat_err: ?host_mod.Error = null,
    capability: [constants.capability_bytes_max]u8 = undefined,
    capability_len: u32 = 0,
    capability_err: ?host_mod.Error = null,

    fn load(binary: *Binary, host: Host, path: []const u8) void {
        binary.* = .{};
        binary.stat = host.stat(path) catch |err| {
            binary.stat_err = err;
            return;
        };
        const bytes = host.read_capability(path, &binary.capability) catch |err| {
            binary.capability_err = err;
            return;
        };
        binary.capability_len = @intCast(bytes.len);
        assert(binary.capability_len <= constants.capability_bytes_max);
        assert(binary.capability_err == null);
    }
};

const binary_directories = [constants.binary_candidates_count][]const u8{
    "/usr/bin/",
    "/bin/",
    "/usr/local/bin/",
};
const program_names = [2][]const u8{ "newuidmap", "newgidmap" };

pub const Facts = struct {
    uname: ?host_mod.Uname,
    uname_err: ?host_mod.Error,

    max_user_namespaces: Slot(constants.sysctl_bytes_max),
    unprivileged_userns_clone: Slot(constants.sysctl_bytes_max),
    apparmor_restrict: Slot(constants.sysctl_bytes_max),
    probe_userns: ProbeFact,

    cgroup_root: Slot(constants.cgroup_list_bytes_max),
    /// `user@UID.service` below /sys/fs/cgroup: the cgroup systemd delegates to the user.
    cgroup_user: StatFact,
    cgroup_controllers: Slot(constants.cgroup_list_bytes_max),

    probe_overlay: ProbeFact,

    uid: u32,
    passwd: Slot(constants.passwd_bytes_max),
    subuid: Slot(constants.subid_bytes_max),
    subgid: Slot(constants.subid_bytes_max),
    binaries: [2][constants.binary_candidates_count]Binary,

    status: Slot(constants.status_bytes_max),
    seccomp: ?u32,
    seccomp_err: ?host_mod.Error,

    /// Clears every flag and result; the byte buffers are left as they are. Facts is large, so
    /// it is initialised in place rather than by assigning a struct value.
    pub fn reset(facts: *Facts) void {
        facts.uname = null;
        facts.uname_err = null;
        facts.max_user_namespaces.reset();
        facts.unprivileged_userns_clone.reset();
        facts.apparmor_restrict.reset();
        facts.probe_userns = .{};
        facts.cgroup_root.reset();
        facts.cgroup_user = .{};
        facts.cgroup_controllers.reset();
        facts.probe_overlay = .{};
        facts.uid = 0;
        facts.passwd.reset();
        facts.subuid.reset();
        facts.subgid.reset();
        facts.binaries = @splat(@splat(.{}));
        facts.status.reset();
        facts.seccomp = null;
        facts.seccomp_err = null;
    }
};

// ---- Gather --------------------------------------------------------------------------------

pub fn gather(host: Host, facts: *Facts) void {
    for (std.enums.values(CheckId)) |id| gather_one(host, facts, id);
    // Every check's facts were gathered, whatever the reads returned.
    assert(facts.cgroup_user.attempted);
    assert(facts.passwd.attempted);
    if (facts.seccomp_err == null) assert(facts.seccomp != null);
}

/// Gathers the facts one check needs. Public so tests can attribute injected faults to checks.
pub fn gather_one(host: Host, facts: *Facts, id: CheckId) void {
    switch (id) {
        .kernel => gather_kernel(host, facts),
        .userns => gather_userns(host, facts),
        .cgroup => gather_cgroup(host, facts),
        .overlay => facts.probe_overlay.run(host, .overlay),
        .subid => gather_subid(host, facts),
        .seccomp => gather_seccomp(host, facts),
    }
    // Each id ran its own gather step, not a neighbour's.
    switch (id) {
        .kernel => if (facts.uname_err == null) assert(facts.uname != null),
        .userns => assert(facts.max_user_namespaces.attempted),
        .cgroup => assert(facts.cgroup_user.attempted),
        .overlay => {}, // The probe fact holds either an outcome or an error; both are valid.
        .subid => assert(facts.subgid.attempted),
        .seccomp => assert(facts.status.attempted),
    }
}

fn gather_kernel(host: Host, facts: *Facts) void {
    facts.uname_err = null;
    facts.uname = host.uname() catch |err| {
        facts.uname_err = err;
        return;
    };
    assert(facts.uname != null);
    assert(facts.uname_err == null);
}

fn gather_userns(host: Host, facts: *Facts) void {
    facts.max_user_namespaces.load(host, "/proc/sys/user/max_user_namespaces");
    facts.unprivileged_userns_clone.load(host, "/proc/sys/kernel/unprivileged_userns_clone");
    facts.apparmor_restrict.load(host, "/proc/sys/kernel/apparmor_restrict_unprivileged_userns");
    facts.probe_userns.run(host, .userns);
    assert(facts.max_user_namespaces.attempted);
    assert(facts.apparmor_restrict.attempted);
}

/// Where systemd keeps the cgroup it delegates to a user: the user manager's service cgroup.
fn user_manager_path(buffer: []u8, uid: u32) []const u8 {
    assert(buffer.len >= 100); // The longest path is 86 bytes plus two ten-digit uids.
    const format = "/sys/fs/cgroup/user.slice/user-{d}.slice/user@{d}.service";
    // Cannot fail: a u32 has at most ten digits, and the buffers passed in are far larger.
    const path = std.fmt.bufPrint(buffer, format, .{ uid, uid }) catch unreachable;
    assert(path.len > "/sys/fs/cgroup/".len);
    assert(std.mem.endsWith(u8, path, ".service"));
    return path;
}

fn gather_cgroup(host: Host, facts: *Facts) void {
    facts.uid = host.uid();
    facts.cgroup_root.load(host, "/sys/fs/cgroup/cgroup.controllers");
    facts.cgroup_controllers.reset();
    facts.cgroup_user = .{ .attempted = true };
    var buffer: [160]u8 = undefined;
    const directory = user_manager_path(&buffer, facts.uid);
    facts.cgroup_user.stat = host.stat(directory) catch |err| {
        facts.cgroup_user.err = err;
        return;
    };
    // The controllers file is only read where the directory exists; evaluate reports why not.
    var file_buffer: [192]u8 = undefined;
    const file = std.fmt.bufPrint(&file_buffer, "{s}/cgroup.controllers", .{directory});
    // Cannot fail: the directory path is under 160 bytes, so the file path fits 192.
    facts.cgroup_controllers.load(host, file catch unreachable);
    assert(facts.cgroup_root.attempted);
    assert(facts.cgroup_controllers.attempted);
}

fn gather_subid(host: Host, facts: *Facts) void {
    facts.uid = host.uid();
    assert(facts.binaries.len == program_names.len);
    facts.passwd.load(host, "/etc/passwd");
    facts.subuid.load(host, "/etc/subuid");
    facts.subgid.load(host, "/etc/subgid");
    for (program_names, 0..) |name, program| {
        for (binary_directories, 0..) |directory, candidate| {
            var buffer: [64]u8 = undefined;
            const joined = std.fmt.bufPrint(&buffer, "{s}{s}", .{ directory, name });
            // Cannot fail: directory and program names are short constants.
            const path = joined catch unreachable;
            facts.binaries[program][candidate].load(host, path);
        }
    }
    assert(facts.passwd.attempted);
    assert(facts.subuid.attempted);
}

fn gather_seccomp(host: Host, facts: *Facts) void {
    facts.status.load(host, "/proc/self/status");
    facts.seccomp_err = null;
    facts.seccomp = host.seccomp_mode() catch |err| {
        facts.seccomp_err = err;
        return;
    };
    assert(facts.status.attempted);
    assert(facts.seccomp_err == null);
}

// ---- Evaluate ------------------------------------------------------------------------------

pub fn evaluate(facts: *const Facts, report: *Report) void {
    // The facts must have been gathered; a zero uid with no passwd attempt means they were not.
    assert(facts.passwd.attempted);
    assert(facts.status.attempted);
    for (std.enums.values(CheckId), 0..) |id, index| {
        const check = &report.checks[index];
        check.start(id);
        switch (id) {
            .kernel => evaluate_kernel(facts, check),
            .userns => evaluate_userns(facts, check),
            .cgroup => evaluate_cgroup(facts, check),
            .overlay => evaluate_overlay(facts, check),
            .subid => evaluate_subid(facts, check),
            .seccomp => evaluate_seccomp(facts, check),
        }
    }
    report.validate();
}

fn error_reason(err: host_mod.Error) []const u8 {
    const reason: []const u8 = switch (err) {
        error.NotFound => "not found",
        error.AccessDenied => "permission denied",
        error.Interrupted => "interrupted",
        error.WouldBlock => "would block",
        error.NoSpace => "no space",
        error.OutOfMemory => "out of memory",
        error.PathTooLong, error.InvalidPath => "invalid path",
        error.FileTooLarge => "larger than the size limit",
        error.Stalled => "made no progress",
        error.Unsupported => "not supported by this kernel",
        error.NoData => "no such attribute",
        error.IoFailed => "input/output error",
    };
    assert(reason.len > 0);
    assert(reason.len < 40); // One short phrase inside a sentence.
    return reason;
}

/// A read that failed. `path` is shown to the user; the fix is the same for every file.
fn read_failed(check: *Check, path: []const u8, err: host_mod.Error) void {
    assert(check.detail.len == 0);
    assert(check.status == .ok);
    check.problem("cannot read {s}: {s}", .{ path, error_reason(err) });
    check.fix_with("retry; if it persists, check the permissions and health of {s}", .{path});
    assert(check.status == .fail);
    assert(check.fix.len > 0);
}

fn probe_problem(check: *Check, name: []const u8, fact: ProbeFact) void {
    assert(check.detail.len == 0);
    assert(check.status == .ok);
    if (fact.err == null) assert(fact.outcome != .ok);
    if (fact.err) |err| {
        check.problem("the {s} probe could not run: {s}", .{ name, error_reason(err) });
        check.fix_with("retry; if it persists, check process limits (ulimit -u) and memory", .{});
        return;
    }
    switch (fact.outcome) {
        .timed_out => check.problem("the {s} probe did not finish in {d} ms and was killed", .{
            name, constants.probe_timeout_ms,
        }),
        .signaled => check.problem("the {s} probe child was killed by a signal", .{name}),
        else => check.problem("the {s} probe child failed unexpectedly", .{name}),
    }
    check.fix_with("retry; if it repeats, check dmesg and the audit log for the cause", .{});
}

// kernel

/// 5.15 is the oldest kernel the project supports. Overlayfs mounts inside user namespaces
/// arrived in 5.11 (per the 5.11 release notes), and 5.15 is the oldest long-term-support
/// kernel that has them, so it is the oldest one still widely deployed with the feature.
fn evaluate_kernel(facts: *const Facts, check: *Check) void {
    assert(check.detail.len == 0);
    assert(check.status == .ok);
    if (facts.uname_err == null) assert(facts.uname != null); // gather_kernel ran.
    if (facts.uname_err) |err| {
        check.problem("cannot read the kernel release: {s}", .{error_reason(err)});
        check.fix_with("retry; uname(2) failing means the process is heavily restricted", .{});
        return;
    }
    const names = facts.uname.?;
    var storage: [constants.uname_field_bytes]u8 = undefined;
    const release = text_util.sanitise(&storage, names.release.slice());
    const version = parse.parse_kernel_release(names.release.slice()) catch {
        check.problem("unrecognised kernel release '{s}'", .{release});
        check.fix_with(
            "run a Linux kernel 5.15 or newer; this release string is not parseable",
            .{},
        );
        return;
    };
    const minimum = [2]u32{ constants.kernel_major_min, constants.kernel_minor_min };
    if (kernel_at_least(version, minimum)) {
        var machine_storage: [constants.uname_field_bytes]u8 = undefined;
        const machine = text_util.sanitise(&machine_storage, names.machine.slice());
        check.pass("{s} {s} (minimum {d}.{d})", .{ release, machine, minimum[0], minimum[1] });
        return;
    }
    check.problem("kernel {s} is older than {d}.{d}", .{ release, minimum[0], minimum[1] });
    check.fix_with("upgrade to Linux {d}.{d} or newer (overlayfs in user namespaces)", .{
        minimum[0], minimum[1],
    });
}

fn kernel_at_least(version: parse.KernelVersion, minimum: [2]u32) bool {
    assert(version.major <= 999_999_999); // The parser accepts at most nine digits.
    assert(minimum[1] < 1000);
    if (version.major > minimum[0]) return true;
    if (version.major < minimum[0]) return false;
    return version.minor >= minimum[1];
}

// userns

/// The sysctl values that bear on user namespaces; `null` for a sysctl the kernel lacks.
const UsernsSysctls = struct {
    max_user_namespaces: u32,
    clone: ?u32,
    restrict: ?u32,
};

/// Reads a sysctl slot that must exist. Reports a failure on `check` and returns null.
fn required_sysctl(check: *Check, slot: anytype, path: []const u8, missing_fix: []const u8) ?u32 {
    assert(slot.attempted);
    assert(path.len > 0);
    if (slot.err) |err| {
        if (err == error.NotFound) {
            check.problem("{s} does not exist", .{path});
            check.fix_with("{s}", .{missing_fix});
        } else {
            read_failed(check, path, err);
        }
        return null;
    }
    return parse.parse_sysctl_uint(slot.text()) catch {
        check.problem("{s} holds something other than a number", .{path});
        check.fix_with("check the file; the kernel only ever writes a decimal number", .{});
        return null;
    };
}

/// Reads a sysctl that older or other kernels do not have: absence is an answer, any other
/// failure is not.
fn optional_sysctl(check: *Check, slot: anytype, path: []const u8) error{Failed}!?u32 {
    assert(slot.attempted);
    assert(path.len > 0);
    if (slot.err) |err| {
        if (err == error.NotFound) return null;
        read_failed(check, path, err);
        return error.Failed;
    }
    return parse.parse_sysctl_uint(slot.text()) catch {
        check.problem("{s} holds something other than a number", .{path});
        check.fix_with("check the file; the kernel only ever writes a decimal number", .{});
        return error.Failed;
    };
}

fn evaluate_userns(facts: *const Facts, check: *Check) void {
    assert(check.detail.len == 0);
    assert(check.status == .ok);
    assert(facts.max_user_namespaces.attempted); // gather_userns ran.
    assert(facts.unprivileged_userns_clone.attempted);
    assert(facts.apparmor_restrict.attempted);
    const missing = "use a kernel built with CONFIG_USER_NS=y";
    const max_path = "/proc/sys/user/max_user_namespaces";
    const clone_path = "/proc/sys/kernel/unprivileged_userns_clone";
    const restrict_path = "/proc/sys/kernel/apparmor_restrict_unprivileged_userns";
    const max = required_sysctl(check, facts.max_user_namespaces, max_path, missing) orelse return;
    const clone = optional_sysctl(check, facts.unprivileged_userns_clone, clone_path) catch return;
    const restrict = optional_sysctl(check, facts.apparmor_restrict, restrict_path) catch return;
    const sysctls: UsernsSysctls = .{
        .max_user_namespaces = max,
        .clone = clone,
        .restrict = restrict,
    };
    userns_verdict(check, sysctls, facts.probe_userns);
}

fn userns_verdict(check: *Check, sysctls: UsernsSysctls, probe: ProbeFact) void {
    assert(check.detail.len == 0);
    assert(check.status == .ok);
    const probe_ran = probe.err == null;
    const probe_ok = probe_ran and probe.outcome == .ok;
    if (sysctls.max_user_namespaces == 0) {
        check.problem("user.max_user_namespaces is 0, so no user namespace can be created", .{});
        check.fix_with("sudo sysctl -w user.max_user_namespaces=15000", .{});
        return;
    }
    assert(sysctls.max_user_namespaces != 0); // The zero case returned above.
    if (sysctls.clone == 0) {
        if (probe_ok) return restricted_but_working(check, "kernel.unprivileged_userns_clone=0");
        check.problem("kernel.unprivileged_userns_clone is 0 (unprivileged refused)", .{});
        check.fix_with("sudo sysctl -w kernel.unprivileged_userns_clone=1", .{});
        return;
    }
    if (sysctls.restrict) |restrict| {
        if (restrict != 0) return userns_restricted(check, probe_ok);
    }
    if (!probe_ok) return userns_probe_verdict(check, probe);
    check.pass("user.max_user_namespaces={d}, unshare(CLONE_NEWUSER) works", .{
        sysctls.max_user_namespaces,
    });
}

fn userns_restricted(check: *Check, probe_ok: bool) void {
    assert(check.detail.len == 0);
    assert(check.status == .ok);
    const setting = "kernel.apparmor_restrict_unprivileged_userns=1";
    if (probe_ok) return restricted_but_working(check, setting);
    check.problem("AppArmor restricts unprivileged user namespaces", .{});
    check.fix_with("sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0", .{});
}

fn restricted_but_working(check: *Check, setting: []const u8) void {
    assert(check.detail.len == 0);
    assert(check.status == .ok);
    check.warning("unshare works for this process, but {s} refuses unconfined users", .{setting});
}

/// The sysctls say yes but the probe said otherwise: the interesting case.
fn userns_probe_verdict(check: *Check, probe: ProbeFact) void {
    assert(check.detail.len == 0);
    assert(check.status == .ok);
    if (probe.is(.denied)) {
        check.problem("sysctls allow it, but unshare(CLONE_NEWUSER) was refused", .{});
        check.fix_with("check LSM policy (AppArmor/SELinux) and seccomp filters; see dmesg", .{});
        return;
    }
    if (probe.is(.map_denied)) return map_denied(check);
    assert(!probe.is(.ok)); // Only reached when the probe did not succeed.
    probe_problem(check, "user namespace", probe);
}

/// The namespace was created, but writing setgroups/gid_map/uid_map was refused.
fn map_denied(check: *Check) void {
    assert(check.status == .ok);
    assert(check.fix.len == 0);
    check.problem("a user namespace can be created, but writing its id map was refused", .{});
    check.fix_with(
        "the mapped id must be one this user owns; check LSM policy (AppArmor/SELinux) and dmesg",
        .{},
    );
}

// cgroup

const required_controllers = [_]parse.Controller{ .cpu, .memory, .pids };

const delegate_fix = "create /etc/systemd/system/user@.service.d/delegate.conf containing " ++
    "[Service] and Delegate=cpu cpuset io memory pids, then sudo systemctl daemon-reload " ++
    "and log in again";

/// What zbx will rely on (M2 creates its scope under the systemd user manager) is the cgroup
/// systemd delegates to the user: `user@UID.service`. It must exist, belong to the user, and
/// offer cpu, memory and pids. The process's own cgroup (an ssh session scope, say) is not the
/// one that matters, so /proc/self/cgroup is not consulted.
fn evaluate_cgroup(facts: *const Facts, check: *Check) void {
    assert(check.detail.len == 0);
    assert(check.status == .ok);
    assert(facts.cgroup_root.attempted); // gather_cgroup ran.
    assert(facts.cgroup_user.attempted);
    if (facts.cgroup_root.err) |err| {
        const root_file = "/sys/fs/cgroup/cgroup.controllers";
        if (err != error.NotFound) return read_failed(check, root_file, err);
        check.problem("cgroup v2 is not mounted at /sys/fs/cgroup (cgroup v1 or hybrid host)", .{});
        const fix = "boot with systemd.unified_cgroup_hierarchy=1 or use a cgroup v2 distro";
        check.fix_with(fix, .{});
        return;
    }
    var buffer: [160]u8 = undefined;
    const directory = user_manager_path(&buffer, facts.uid);
    if (facts.cgroup_user.err) |err| {
        if (err != error.NotFound) return read_failed(check, directory, err);
        check.problem("no systemd user manager for uid {d}: {s} does not exist", .{
            facts.uid, directory,
        });
        check.fix_with("log in through a systemd (logind) session, or run: {s}", .{
            "sudo loginctl enable-linger $(id -un)",
        });
        return;
    }
    if (!cgroup_owned_directory(check, facts, directory)) return;
    if (facts.cgroup_controllers.err) |err| {
        var file_buffer: [192]u8 = undefined;
        // Cannot fail: the directory path is under 160 bytes, so the file path fits 192.
        const format = "{s}/cgroup.controllers";
        const formatted = std.fmt.bufPrint(&file_buffer, format, .{directory});
        const file = formatted catch unreachable; // Same bound as above.
        return read_failed(check, file, err);
    }
    const offered = parse.parse_controller_list(facts.cgroup_controllers.text()) catch {
        check.problem("cgroup.controllers of the user manager is malformed", .{});
        check.fix_with("check the file; the kernel writes space-separated lowercase names", .{});
        return;
    };
    cgroup_verdict(check, facts.uid, offered);
}

/// True if the user manager's cgroup is a directory owned by the user; otherwise reports.
fn cgroup_owned_directory(check: *Check, facts: *const Facts, directory: []const u8) bool {
    assert(check.status == .ok);
    assert(facts.cgroup_user.attempted);
    assert(directory.len > 0);
    assert(facts.cgroup_user.err == null);
    const stat = facts.cgroup_user.stat;
    if (stat.mode & std.posix.S.IFMT != std.posix.S.IFDIR) {
        check.problem("{s} is not a directory", .{directory});
        check.fix_with("{s}", .{delegate_fix});
        return false;
    }
    if (stat.uid == facts.uid) return true;
    check.problem("{s} is owned by uid {d}, not by uid {d}: it is not delegated to this user", .{
        directory, stat.uid, facts.uid,
    });
    check.fix_with("{s}", .{delegate_fix});
    return false;
}

fn cgroup_verdict(check: *Check, uid: u32, offered: parse.ControllerSet) void {
    assert(check.detail.len == 0);
    assert(check.status == .ok);
    var missing: Detail = .{};
    for (required_controllers) |controller| {
        if (!offered.has(controller)) missing.print(" {s}", .{@tagName(controller)});
    }
    if (missing.len > 0) {
        check.problem("the cgroup delegated to uid {d} lacks controllers:{s}", .{
            uid, missing.slice(),
        });
        check.fix_with("{s}", .{delegate_fix});
        return;
    }
    check.detail.print("cgroup v2, user@{d}.service delegated to uid {d}:", .{ uid, uid });
    append_controllers(&check.detail, offered);
    check.status = .ok;
}

fn append_controllers(detail: *Detail, set: parse.ControllerSet) void {
    assert(detail.len > 0); // Called after the sentence it extends.
    if (set.is_empty()) detail.print(" none", .{});
    for (std.enums.values(parse.Controller)) |controller| {
        if (set.has(controller)) detail.print(" {s}", .{@tagName(controller)});
    }
    if (set.unknown > 0) detail.print(" +{d} other", .{set.unknown});
    if (detail.truncated) assert(detail.len == constants.detail_bytes_max);
}

// overlay

fn evaluate_overlay(facts: *const Facts, check: *Check) void {
    assert(check.detail.len == 0);
    assert(check.status == .ok);
    const probe = facts.probe_overlay;
    if (probe.is(.ok)) {
        check.pass("overlayfs mounts inside a user and mount namespace", .{});
        return;
    }
    if (probe.is(.denied)) {
        check.problem("an overlayfs mount inside a user namespace was refused", .{});
        check.fix_with(
            "use Linux 5.11 or newer with overlayfs (CONFIG_OVERLAY_FS, modprobe overlay)",
            .{},
        );
        return;
    }
    if (probe.is(.map_denied)) return map_denied(check);
    if (probe.is(.setup_denied)) {
        check.problem("could not enter the user and mount namespaces the probe needs", .{});
        check.fix_with("fix the userns check first; overlay needs the same permission", .{});
        return;
    }
    assert(!probe.is(.ok)); // Every success and named refusal returned above.
    if (probe.err == null) assert(probe.outcome != .denied);
    probe_problem(check, "overlay", probe);
}

// subid

const Program = enum(u1) { newuidmap, newgidmap };

const BinaryState = union(enum) {
    /// Privileged by setuid root (true) or by file capabilities (false).
    privileged: bool,
    /// Present but neither setuid root nor carrying the capability.
    unprivileged,
    missing,
    fault: host_mod.Error,
};

fn binary_state(facts: *const Facts, program: Program) BinaryState {
    const row = &facts.binaries[@backingInt(program)];
    // Faults first, over every candidate: a failed look at any of them is never ignored just
    // because another candidate turned out to be fine.
    for (row) |*binary| {
        if (binary.stat_err) |err| {
            if (err != error.NotFound) return .{ .fault = err };
        } else if (binary.capability_err) |err| {
            if (err != error.NoData) return .{ .fault = err };
        }
    }
    var found_unprivileged = false;
    for (row) |*binary| {
        if (binary.stat_err) |err| {
            assert(err == error.NotFound); // The fault scan above returned any other.
            continue;
        }
        if (binary.capability_err) |err| assert(err == error.NoData);
        const privilege = candidate_privilege(binary, program);
        if (privilege) |by_setuid| return .{ .privileged = by_setuid };
        found_unprivileged = true;
    }
    return if (found_unprivileged) .unprivileged else .missing;
}

/// null if the candidate is not privileged; otherwise whether it is by setuid root.
fn candidate_privilege(binary: *const Binary, program: Program) ?bool {
    assert(binary.stat_err == null); // Only called for candidates that exist.
    assert(binary.capability_len <= constants.capability_bytes_max);
    const regular = binary.stat.mode & std.posix.S.IFMT == std.posix.S.IFREG;
    if (!regular) return null;
    const setuid_bit = binary.stat.mode & 0o4000 != 0;
    if (setuid_bit) {
        if (binary.stat.uid == 0) return true;
    }
    if (binary.capability_err != null) return null;
    const bits = parse.decode_capability(binary.capability[0..binary.capability_len]) catch {
        return null;
    };
    if (bits.root_id != 0) return null; // Applies only inside a namespace, not on the host.
    const has = if (program == .newuidmap) bits.setuid else bits.setgid;
    return if (has) false else null;
}

fn evaluate_subid(facts: *const Facts, check: *Check) void {
    assert(check.detail.len == 0);
    assert(check.status == .ok);
    assert(facts.subuid.attempted); // gather_subid ran.
    assert(facts.subgid.attempted);
    // Failed reads come first: a fault must never be answered from partial information.
    if (facts.passwd.err) |err| {
        if (err != error.NotFound) return read_failed(check, "/etc/passwd", err);
    }
    const files = [2]struct { path: []const u8, slot: *const Slot(constants.subid_bytes_max) }{
        .{ .path = "/etc/subuid", .slot = &facts.subuid },
        .{ .path = "/etc/subgid", .slot = &facts.subgid },
    };
    for (files) |file| {
        if (file.slot.err) |err| {
            if (err != error.NotFound) return read_failed(check, file.path, err);
        }
    }
    const user = lookup_user(facts);
    var ranges: [2]parse.SubidRanges = undefined;
    for (files, 0..) |file, index| {
        const content = if (file.slot.err == null) file.slot.text() else "";
        ranges[index] = parse.parse_subid(content, user.name, facts.uid);
    }
    subid_verdict(facts, check, user, ranges);
}

const UserLookup = struct {
    name: ?[]const u8,
    /// True if /etc/passwd was readable (so a missing name means "no entry").
    passwd_present: bool,
};

fn lookup_user(facts: *const Facts) UserLookup {
    assert(facts.passwd.attempted);
    if (facts.passwd.err != null) return .{ .name = null, .passwd_present = false };
    const found = parse.parse_passwd_name(facts.passwd.text(), facts.uid);
    if (found.name) |name| assert(name.len > 0);
    return .{ .name = found.name, .passwd_present = true };
}

fn user_label(user: UserLookup, uid: u32, buffer: *Detail) void {
    assert(buffer.len == 0);
    if (user.name) |name| {
        var storage: [constants.user_name_bytes_max]u8 = undefined;
        buffer.print("{s} (uid {d})", .{ text_util.sanitise(&storage, name), uid });
    } else {
        buffer.print("uid {d} (no passwd entry, matched by uid only)", .{uid});
    }
    assert(buffer.len > 0);
}

/// What is wrong with the subid setup, collected so that one run names every problem.
const SubidProblems = struct {
    ranges: bool = false,
    missing: bool = false,
    unprivileged: bool = false,

    fn any(problems: SubidProblems) bool {
        if (problems.ranges) return true;
        if (problems.missing) return true;
        return problems.unprivileged;
    }
};

fn subid_verdict(
    facts: *const Facts,
    check: *Check,
    user: UserLookup,
    ranges: [2]parse.SubidRanges,
) void {
    assert(check.detail.len == 0);
    assert(check.status == .ok);
    const programs = [2]Program{ .newuidmap, .newgidmap };
    var states: [2]BinaryState = undefined;
    for (programs, 0..) |program, index| {
        states[index] = binary_state(facts, program);
        if (states[index] == .fault) {
            const name = program_names[index];
            check.problem("cannot inspect {s}: {s}", .{ name, error_reason(states[index].fault) });
            check.fix_with("retry; check the permissions of /usr/bin/{s}", .{name});
            return;
        }
    }
    var who: Detail = .{};
    user_label(user, facts.uid, &who);
    assert(who.len > 0);
    var problems: SubidProblems = .{};
    var found: Detail = .{};
    const kinds = [2][]const u8{ "subuid", "subgid" };
    for (ranges, kinds) |range, kind| {
        if (range.best_count >= constants.subid_range_min) continue;
        problems.ranges = true;
        found.print("; no {s} range of {d} ids (largest: {d})", .{
            kind, constants.subid_range_min, range.best_count,
        });
    }
    for (states, program_names) |state, name| {
        switch (state) {
            .missing => {
                problems.missing = true;
                found.print("; {s} not found", .{name});
            },
            .unprivileged => {
                problems.unprivileged = true;
                found.print(
                    "; {s} is neither setuid root nor has a usable file capability",
                    .{name},
                );
            },
            else => {},
        }
    }
    if (problems.any()) {
        check.problem("{s}{s}", .{ who.slice(), found.slice() });
        subid_fixes(check, user, problems);
        return;
    }
    check.pass("{s}: subuid {d} ids, subgid {d} ids;", .{
        who.slice(), ranges[0].best_count, ranges[1].best_count,
    });
    for (states, program_names, 0..) |state, name, index| {
        const how = if (state.privileged) "setuid root" else "file capability";
        const lead = if (index == 0) " " else ", ";
        check.detail.print("{s}{s}: {s}", .{ lead, name, how });
    }
}

fn subid_fixes(check: *Check, user: UserLookup, problems: SubidProblems) void {
    assert(problems.any());
    var name_storage: [constants.user_name_bytes_max]u8 = undefined;
    const owner = if (user.name) |name| text_util.sanitise(&name_storage, name) else "$(id -un)";
    const command = "$(command -v newuidmap newgidmap)";
    var first = true;
    if (problems.ranges) {
        const usermod = "sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535";
        check.fix_with("{s} {s}", .{ usermod, owner });
        first = false;
    }
    if (problems.missing) {
        const lead = if (first) "" else "; ";
        const install = "install uidmap (apt install uidmap / dnf install shadow-utils)";
        check.fix.print("{s}{s}", .{ lead, install });
        first = false;
    }
    if (problems.unprivileged) {
        const lead = if (first) "" else "; ";
        check.fix.print("{s}sudo chown root: {s} && sudo chmod u+s {s}", .{
            lead, command, command,
        });
    }
    assert(check.fix.len > 0);
}

// seccomp

fn evaluate_seccomp(facts: *const Facts, check: *Check) void {
    assert(check.detail.len == 0);
    assert(check.status == .ok);
    assert(facts.status.attempted); // gather_seccomp ran.
    if (facts.seccomp_err == null) assert(facts.seccomp != null);
    if (facts.status.err) |err| return read_failed(check, "/proc/self/status", err);
    if (facts.seccomp_err) |err| {
        check.problem("prctl(PR_GET_SECCOMP) failed: {s}", .{error_reason(err)});
        check.fix_with("use a kernel built with CONFIG_SECCOMP=y", .{});
        return;
    }
    const from_status = parse.parse_seccomp_status(facts.status.text()) catch {
        check.problem("no usable Seccomp: line in /proc/self/status", .{});
        check.fix_with("use a kernel built with CONFIG_SECCOMP=y and CONFIG_SECCOMP_FILTER=y", .{});
        return;
    };
    const from_prctl = facts.seccomp.?;
    if (from_status != from_prctl) {
        check.problem("/proc/self/status says seccomp mode {d} but prctl says {d}", .{
            from_status, from_prctl,
        });
        check.fix_with("retry; the two views of this process must agree", .{});
        return;
    }
    const mode = switch (from_status) {
        0 => "disabled for this process",
        1 => "strict",
        else => "filter",
    };
    check.pass("seccomp is supported (current mode: {s})", .{mode});
}

// ---- Render --------------------------------------------------------------------------------

const Style = struct {
    label: []const u8,
    color: []const u8,
};

fn style_of(status: Status) Style {
    const style: Style = switch (status) {
        .ok => .{ .label = "ok  ", .color = "\x1b[32m" },
        .fail => .{ .label = "FAIL", .color = "\x1b[31m" },
        .warn => .{ .label = "warn", .color = "\x1b[33m" },
    };
    assert(style.label.len == 4); // The columns after the label line up.
    return style;
}

/// Renders the report, one line per check. Colour only when asked (stdout is a terminal).
pub fn render(report: *const Report, color: bool, buffer: []u8) []const u8 {
    assert(buffer.len > 0);
    report.validate();
    var writer = std.Io.Writer.fixed(buffer);
    for (report.checks) |check| render_line(&writer, check, color);
    const output = writer.buffered();
    assert(output.len > 0);
    assert(output[output.len - 1] == '\n');
    return output;
}

fn render_line(writer: *std.Io.Writer, check: Check, color: bool) void {
    assert(check.detail.len > 0);
    if (check.status == .fail) assert(check.fix.len > 0);
    const style = style_of(check.status);
    // Cannot fail: constants.zig asserts, at comptime, that six maximal lines fit the buffer.
    if (color) writer.writeAll(style.color) catch unreachable;
    writer.writeAll(style.label) catch unreachable; // Same.
    if (color) writer.writeAll("\x1b[0m") catch unreachable; // Same.
    const line = .{ @tagName(check.id), check.detail.slice() };
    writer.print(" {s}  {s}", line) catch unreachable; // Same.
    if (check.status == .fail) {
        writer.print(" \u{2014} fix: {s}", .{check.fix.slice()}) catch unreachable; // Same.
    }
    writer.writeAll("\n") catch unreachable; // Same.
}

// ---- Entry point ---------------------------------------------------------------------------

/// Runs the doctor against `host` and prints the report to stdout. Returns the exit code.
pub fn run(host: Host) u8 {
    var facts: Facts = undefined;
    facts.reset();
    gather(host, &facts);
    var report: Report = undefined;
    evaluate(&facts, &report);

    var buffer: [constants.output_bytes_max]u8 = undefined;
    const output = render(&report, host.is_terminal(.stdout), &buffer);
    assert(output.len > 0);
    host.write_all(.stdout, output) catch return constants.exit_failed;
    assert(output.len <= buffer.len);
    return report.exit_code();
}

// ---- Tests ---------------------------------------------------------------------------------

const testing = std.testing;
const HostSim = @import("host_sim.zig").HostSim;
const fixtures = @import("doctor_fixtures.zig");

/// Runs the whole doctor against a fixture and returns the exit code; output stays in `target`.
fn run_fixture(target: *HostSim, fixture: *const fixtures.Fixture) u8 {
    target.init(7, fixture.files);
    fixture.apply(target);
    const code = run(target.interface());
    assert(target.open_count() == 0);
    return code;
}

test "snapshot: every fixture's full report and exit code" {
    // Goal: the user-visible report for each simulated host is exactly the checked-in text
    // (src/testdata/doctor/NAME.txt), and the exit code is 0 exactly when nothing is FAIL.
    // Method: run the whole doctor (gather, evaluate, render, write) against the simulator.
    @setEvalBranchQuota(100_000);
    var target: HostSim = undefined;
    inline for (fixtures.all) |fixture| {
        const expected = @embedFile("testdata/doctor/" ++ fixture.name ++ ".txt");
        const code = run_fixture(&target, &fixture);
        try testing.expectEqualStrings(expected, target.stdout());
        try testing.expectEqual(@as(usize, 0), target.stderr().len);
        const has_fail = std.mem.indexOf(u8, expected, "FAIL ") != null;
        try testing.expectEqual(@as(u8, @intFromBool(has_fail)), code);
    }
}

test "the healthy fixtures pass and warn does not change the exit code" {
    // Goal: pin which fixtures exit 0, so a changed policy cannot flip one unnoticed.
    const passing = [_][]const u8{
        "ubuntu_2404",                    "fedora_40",
        "restricted_but_working",         "subid_by_uid",
        "no_passwd_entry",                "kernel_exactly_minimum",
        "kernel_newer_major_lower_minor",
    };
    var target: HostSim = undefined;
    for (fixtures.all) |fixture| {
        const expect_pass = for (passing) |name| {
            if (std.mem.eql(u8, name, fixture.name)) break true;
        } else false;
        const code = run_fixture(&target, &fixture);
        try testing.expectEqual(expect_pass, code == constants.exit_ok);
    }
}

test "uid 0 gets no free pass: root is judged like anyone else" {
    // Goal: a root user on a healthy host still fails subid (root has no subuid range), and
    // without a user manager it also fails cgroup. Method: gather and evaluate, then compare the
    // status of every check.
    const cases = [_]struct { name: []const u8, failing: []const CheckId }{
        .{ .name = "ubuntu_2404_as_root", .failing = &.{.subid} },
        .{ .name = "ubuntu_2404_as_root_no_manager", .failing = &.{ .cgroup, .subid } },
    };
    var target: HostSim = undefined;
    var facts: Facts = undefined;
    var report: Report = undefined;
    for (cases) |case| {
        for (fixtures.all) |fixture| {
            if (!std.mem.eql(u8, fixture.name, case.name)) continue;
            target.init(1, fixture.files);
            fixture.apply(&target);
            facts.reset();
            gather(target.interface(), &facts);
            evaluate(&facts, &report);
            for (report.checks) |check| {
                const listed = std.mem.indexOfScalar(CheckId, case.failing, check.id) != null;
                try testing.expectEqual(if (listed) Status.fail else Status.ok, check.status);
            }
        }
    }
}

test "colour is applied only when asked and does not change the text" {
    // Goal: with colour the report is the plain report plus escape sequences; without it there
    // is no escape byte at all.
    var target: HostSim = undefined;
    const fixture = fixtures.all[1]; // ubuntu_2404_restricted: ok and FAIL lines.
    target.init(1, fixture.files);
    fixture.apply(&target);
    target.terminal = true;
    _ = run(target.interface());
    const coloured = target.stdout();
    try testing.expect(std.mem.indexOf(u8, coloured, "\x1b[31mFAIL\x1b[0m") != null);
    try testing.expect(std.mem.indexOf(u8, coloured, "\x1b[32mok  \x1b[0m") != null);

    var plain_sim: HostSim = undefined;
    _ = run_fixture(&plain_sim, &fixture);
    try testing.expect(std.mem.indexOfScalar(u8, plain_sim.stdout(), 0x1b) == null);
    var stripped: [constants.output_bytes_max]u8 = undefined;
    var length: usize = 0;
    var index: usize = 0;
    while (index < coloured.len) : (index += 1) {
        if (coloured[index] == 0x1b) {
            while (coloured[index] != 'm') index += 1;
            continue;
        }
        stripped[length] = coloured[index];
        length += 1;
    }
    try testing.expectEqualStrings(plain_sim.stdout(), stripped[0..length]);
}

test "a failed read at every step of the healthy host is a FAIL, never ok" {
    // Goal: crash at any step. Method: fail host call 0, 1, 2, ... of the healthy Ubuntu run
    // with each error kind; whatever the failing call was (a read, a stat, a probe, the final
    // write), the exit code is 1, the report is well formed, and no handle leaks.
    const kinds = [_]host_mod.Error{ error.IoFailed, error.AccessDenied, error.OutOfMemory };
    const fixture = fixtures.all[0];
    var target: HostSim = undefined;
    var calls_total: u32 = 0;
    for (kinds) |kind| {
        for (0..64) |index| {
            target.init(3, fixture.files);
            fixture.apply(&target);
            target.faults.fail_call_index = @intCast(index);
            target.faults.fail_call_error = kind;
            const code = run(target.interface());
            try testing.expectEqual(@as(u32, 0), target.open_count());
            const injected = target.hard_errors_injected;
            if (injected == 0) {
                calls_total = @max(calls_total, @as(u32, @intCast(index)));
                try testing.expectEqual(constants.exit_ok, code);
            } else {
                try testing.expectEqual(constants.exit_failed, code);
            }
        }
    }
    try testing.expect(calls_total >= 30); // The healthy run makes dozens of calls.
}

test "gather is exactly the per-check gather steps in order" {
    // Goal: the fuzzers drive gather_one per check; this pins that doing so equals gather().
    var target_a: HostSim = undefined;
    var target_b: HostSim = undefined;
    const fixture = fixtures.all[0];
    target_a.init(5, fixture.files);
    fixture.apply(&target_a);
    target_b.init(5, fixture.files);
    fixture.apply(&target_b);
    var facts_a: Facts = undefined;
    var facts_b: Facts = undefined;
    facts_a.reset();
    facts_b.reset();
    gather(target_a.interface(), &facts_a);
    for (std.enums.values(CheckId)) |id| gather_one(target_b.interface(), &facts_b, id);
    var report_a: Report = undefined;
    var report_b: Report = undefined;
    evaluate(&facts_a, &report_a);
    evaluate(&facts_b, &report_b);
    for (report_a.checks, report_b.checks) |a, b| {
        try testing.expectEqualStrings(a.detail.slice(), b.detail.slice());
    }
    try testing.expectEqual(target_a.call_count, target_b.call_count);
}
