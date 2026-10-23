//! Simulated hosts for the doctor: real-world contents of the files it reads, one per scenario.
//! Used by the snapshot tests (each fixture's full report is checked in as text) and by the
//! doctor simulation fuzzer. The contents follow what the named systems write; where a value
//! is a stand-in (an id, a cgroup name) it is plausible, not copied from a particular machine.

const std = @import("std");
const host = @import("host.zig");
const sim = @import("host_sim.zig");

const File = sim.File;

/// A binary under /usr/bin: its mode, owner and (optionally) its file capability.
pub const Binary = struct {
    mode: u32 = 0o104755,
    uid: u32 = 0,
    capability: ?[]const u8 = null,
};

pub const Spec = struct {
    name: []const u8,
    kernel: []const u8 = "6.8.0-45-generic",
    machine: []const u8 = "x86_64",
    uid: u32 = 1000,
    max_user_namespaces: ?[]const u8 = "63488\n",
    unprivileged_userns_clone: ?[]const u8 = null,
    apparmor_restrict: ?[]const u8 = "0\n",
    cgroup_root: ?[]const u8 = "cpuset cpu io memory hugetlb pids rdma misc\n",
    /// The user manager's cgroup directory (user@UID.service): whether it exists, its mode,
    /// and its owner (null means the fixture's user).
    cgroup_user: bool = true,
    cgroup_user_mode: u32 = 0o040755,
    cgroup_user_owner: ?u32 = null,
    cgroup_controllers: ?[]const u8 = "cpuset cpu io memory pids\n",
    passwd: ?[]const u8 =
        "root:x:0:0:root:/root:/bin/bash\n" ++
        "alice:x:1000:1000:Alice,,,:/home/alice:/bin/bash\n",
    subuid: ?[]const u8 = "alice:100000:65536\n",
    subgid: ?[]const u8 = "alice:100000:65536\n",
    subuid_readable: bool = true,
    newuidmap: ?Binary = .{},
    newgidmap: ?Binary = .{},
    status: ?[]const u8 = default_status,
    seccomp: host.Error!u32 = 0,
    probes: sim.Probes = .{},
};

pub const default_status =
    "Name:\tzbx\nUmask:\t0022\nState:\tR (running)\nTgid:\t4242\nUid:\t1000\t1000\t1000\t1000\n" ++
    "Seccomp:\t0\nSeccomp_filters:\t0\nSpeculation_Store_Bypass:\tthread vulnerable\n";

pub const Fixture = struct {
    name: []const u8,
    files: []const File,
    uid: u32,
    kernel: []const u8,
    machine: []const u8,
    seccomp: host.Error!u32,
    probes: sim.Probes,

    /// Points `host_sim` at this fixture.
    pub fn apply(fixture: *const Fixture, target: *sim.HostSim) void {
        target.files = fixture.files;
        target.uid_value = fixture.uid;
        target.uname_value = .{
            .release = host.Text.from_slice(fixture.kernel),
            .machine = host.Text.from_slice(fixture.machine),
        };
        target.seccomp_result = fixture.seccomp;
        target.probes = fixture.probes;
    }
};

const files_max = 40;

/// A tiny comptime list of files, so a Spec can leave any of them out.
const FileList = struct {
    items: [files_max]File = undefined,
    len: u32 = 0,

    fn add(list: *FileList, path: []const u8, content: ?[]const u8) void {
        const present = content orelse return;
        list.items[list.len] = .{ .path = path, .content = present };
        list.len += 1;
    }

    fn add_binary(list: *FileList, path: []const u8, binary: ?Binary) void {
        const present = binary orelse return;
        list.items[list.len] = .{
            .path = path,
            .content = "",
            .mode = present.mode,
            .uid = present.uid,
            .capability = present.capability,
        };
        list.len += 1;
    }
};

pub fn build(comptime spec: Spec) Fixture {
    const final = comptime blk: {
        var list: FileList = .{};
        const root = "/sys/fs/cgroup";
        list.add("/proc/sys/user/max_user_namespaces", spec.max_user_namespaces);
        list.add("/proc/sys/kernel/unprivileged_userns_clone", spec.unprivileged_userns_clone);
        list.add("/proc/sys/kernel/apparmor_restrict_unprivileged_userns", spec.apparmor_restrict);
        list.add(root ++ "/cgroup.controllers", spec.cgroup_root);
        const directory = std.fmt.comptimePrint(
            root ++ "/user.slice/user-{d}.slice/user@{d}.service",
            .{ spec.uid, spec.uid },
        );
        if (spec.cgroup_user) {
            list.add_binary(directory, .{
                .mode = spec.cgroup_user_mode,
                .uid = spec.cgroup_user_owner orelse spec.uid,
            });
        }
        list.add(directory ++ "/cgroup.controllers", spec.cgroup_controllers);
        list.add("/etc/passwd", spec.passwd);
        list.add("/etc/subuid", spec.subuid);
        list.add("/etc/subgid", spec.subgid);
        list.add_binary("/usr/bin/newuidmap", spec.newuidmap);
        list.add_binary("/usr/bin/newgidmap", spec.newgidmap);
        list.add("/proc/self/status", spec.status);
        if (!spec.subuid_readable) {
            for (list.items[0..list.len]) |*file| {
                if (std.mem.eql(u8, file.path, "/etc/subuid")) file.readable = false;
            }
        }
        const copy = list;
        break :blk copy;
    };
    return .{
        .name = spec.name,
        .files = final.items[0..final.len],
        .uid = spec.uid,
        .kernel = spec.kernel,
        .machine = spec.machine,
        .seccomp = spec.seccomp,
        .probes = spec.probes,
    };
}

const zero_pairs = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

// Capability xattrs as `setcap cap_setuid=ep` / `cap_setgid=ep` write them (revision 2).
const cap_setuid_ep = "\x01\x00\x00\x02\x80\x00\x00\x00" ++ zero_pairs;
const cap_setgid_ep = "\x01\x00\x00\x02\x40\x00\x00\x00" ++ zero_pairs;
const cap_setuid_namespaced =
    "\x01\x00\x00\x03\x80\x00\x00\x00" ++ zero_pairs ++ "\xe8\x03\x00\x00";

pub const all = [_]Fixture{
    build(.{ .name = "ubuntu_2404" }),
    // Ubuntu 24.04 as installed: the AppArmor restriction is on, so the probe is refused.
    build(.{
        .name = "ubuntu_2404_restricted",
        .apparmor_restrict = "1\n",
        .probes = .{ .userns = .denied, .overlay = .setup_denied },
    }),
    build(.{
        .name = "fedora_40",
        .kernel = "6.8.5-301.fc40.x86_64",
        .apparmor_restrict = null,
        .cgroup_controllers = "cpu memory pids\n",
        .subuid = "alice:524288:65536\n",
        .subgid = "alice:524288:65536\n",
        .newuidmap = .{ .mode = 0o100755, .capability = cap_setuid_ep },
        .newgidmap = .{ .mode = 0o100755, .capability = cap_setgid_ep },
        .seccomp = 2,
        .status = "Name:\tzbx\nSeccomp:\t2\nSeccomp_filters:\t1\n",
    }),
    // This kind of container: root, cgroup v1/hybrid, no uidmap, a range only for another user.
    build(.{
        .name = "container_cgroup_v1",
        .kernel = "6.18.44-fc-v153",
        .uid = 0,
        .apparmor_restrict = null,
        .max_user_namespaces = "64280\n",
        .cgroup_root = null,
        .cgroup_user = false,
        .cgroup_controllers = null,
        .passwd = "root:x:0:0:root:/root:/bin/bash\nubuntu:x:1000:1000::/home/ubuntu:/bin/bash\n",
        .subuid = "ubuntu:100000:65536\n",
        .subgid = "ubuntu:100000:65536\n",
        .newuidmap = null,
        .newgidmap = null,
    }),
    // A root user on a healthy cgroup v2 host still has no subuid range: uid 0 never passes.
    build(.{
        .name = "ubuntu_2404_as_root",
        .uid = 0,
    }),
    // Root without a user manager (the usual case: root has no logind user session).
    build(.{ .name = "ubuntu_2404_as_root_no_manager", .uid = 0, .cgroup_user = false }),
    build(.{
        .name = "userns_disabled",
        .max_user_namespaces = "0\n",
        .probes = .{ .userns = .denied, .overlay = .setup_denied },
    }),
    build(.{ .name = "userns_missing", .max_user_namespaces = null }),
    build(.{
        .name = "debian_clone_off",
        .unprivileged_userns_clone = "0\n",
        .apparmor_restrict = null,
        .probes = .{ .userns = .denied, .overlay = .setup_denied },
    }),
    // The sysctls say yes and the probe says no: seccomp or an LSM is in the way.
    build(.{
        .name = "probe_denied_sysctls_ok",
        .probes = .{ .userns = .denied, .overlay = .setup_denied },
    }),
    // The sysctl restricts, yet this process (under an AppArmor profile) can unshare.
    build(.{ .name = "restricted_but_working", .apparmor_restrict = "1\n" }),
    build(.{ .name = "old_kernel", .kernel = "5.4.0-150-generic" }),
    build(.{ .name = "odd_kernel", .kernel = "banana" }),
    // The delegated cgroup offers io and cpuset but not cpu or memory.
    build(.{ .name = "cgroup_missing_controllers", .cgroup_controllers = "cpuset io pids\n" }),
    // Only cpu is missing: systemd does not delegate cpu by default on some releases.
    build(.{ .name = "cgroup_cpu_missing", .cgroup_controllers = "cpuset io memory pids\n" }),
    build(.{ .name = "cgroup_user_manager_missing", .cgroup_user = false }),
    build(.{ .name = "cgroup_dir_not_owned", .cgroup_user_owner = 0 }),
    build(.{ .name = "cgroup_not_a_directory", .cgroup_user_mode = 0o100644 }),
    // The directory exists but its controllers file cannot be found.
    build(.{ .name = "cgroup_controllers_file_missing", .cgroup_controllers = null }),
    build(.{ .name = "cgroup_controllers_malformed", .cgroup_controllers = "cpu  memory\n" }),
    build(.{
        .name = "userns_map_denied",
        .probes = .{ .userns = .map_denied, .overlay = .map_denied },
    }),
    build(.{ .name = "overlay_denied", .probes = .{ .overlay = .denied } }),
    build(.{ .name = "probe_timeout", .probes = .{ .userns = .timed_out, .overlay = .timed_out } }),
    build(.{ .name = "probe_signaled", .probes = .{ .userns = .signaled, .overlay = .signaled } }),
    build(.{
        .name = "probe_cannot_fork",
        .probes = .{ .userns_error = error.OutOfMemory, .overlay_error = error.OutOfMemory },
    }),
    build(.{ .name = "subid_missing_entry", .subuid = "bob:100000:65536\n" }),
    build(.{
        .name = "subid_by_uid",
        .subuid = "1000:100000:65536\n",
        .subgid = "1000:100000:65536\n",
    }),
    build(.{ .name = "subid_too_small", .subgid = "alice:100000:1000\n" }),
    build(.{ .name = "subid_files_absent", .subuid = null, .subgid = null }),
    build(.{
        .name = "no_passwd_entry",
        .uid = 1001,
        .subuid = "1001:100000:65536\n",
        .subgid = "1001:100000:65536\n",
    }),
    build(.{ .name = "no_passwd_entry_name_only", .uid = 1001, .subuid = "carol:100000:65536\n" }),
    build(.{ .name = "subuid_unreadable", .subuid_readable = false }),
    build(.{ .name = "newuidmap_plain", .newuidmap = .{ .mode = 0o100755 } }),
    build(.{ .name = "newuidmap_missing", .newuidmap = null }),
    build(.{ .name = "newgidmap_wrong_owner", .newgidmap = .{ .mode = 0o104755, .uid = 1000 } }),
    build(.{
        .name = "newuidmap_namespaced_cap",
        .newuidmap = .{ .mode = 0o100755, .capability = cap_setuid_namespaced },
    }),
    build(.{ .name = "seccomp_absent", .status = "Name:\tzbx\n", .seccomp = error.Unsupported }),
    build(.{ .name = "seccomp_disagree", .seccomp = 2 }),
    // Kernel version boundaries: exactly the minimum, a minor just below it, and a newer major
    // whose minor number is lower than the minimum's.
    build(.{ .name = "kernel_exactly_minimum", .kernel = "5.15.0" }),
    build(.{ .name = "kernel_just_below", .kernel = "5.14.21-generic" }),
    build(.{ .name = "kernel_newer_major_lower_minor", .kernel = "6.0.1" }),
};

test "every fixture has a distinct name and fits the simulator" {
    // Goal: names key the snapshot files; file lists must fit sim limits.
    for (all, 0..) |fixture, index| {
        try std.testing.expect(fixture.files.len <= @import("constants.zig").sim_files_max);
        for (all[index + 1 ..]) |other| {
            try std.testing.expect(!std.mem.eql(u8, fixture.name, other.name));
        }
    }
}
