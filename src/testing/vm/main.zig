//! The M0 demo, run in a real Ubuntu 24.04 VM:
//!   1. `zbx doctor` on the fresh VM: every check ok, exit 0, with what it detected.
//!   2. With user namespaces disabled by sysctl, the userns check FAILs with a fix, exit 1;
//!      the sysctls are restored and doctor is ok again.
//!   3. `file zbx` reports a statically linked ELF; both release binaries (x86_64 and aarch64)
//!      are checked here, in Zig, to be static ELF files under 2 MiB.
//! Run it with `zig build demo-m0` (KVM) or `zig build demo-m0 -Daccel=tcg` (software
//! emulation, slow). See docs/DEMO.md.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;
const checks = @import("checks.zig");
const cloud_init = @import("cloud_init.zig");
const image = @import("image.zig");
const limits = @import("limits.zig");
const session_mod = @import("session.zig");

const Session = session_mod.Session;

const Options = struct {
    accel: []const u8 = "auto",
    zbx_x86_64: []const u8 = "",
    zbx_aarch64: []const u8 = "",
    cache_dir: []const u8 = ".zig-cache/zbx-vm",
    delegate_dropin: bool = false,
    /// Development aids: keep the overlay after the run, and boot an existing, already
    /// provisioned overlay instead of making a new one.
    keep_overlay: bool = false,
    reuse_overlay: bool = false,
};

pub fn main(init: std.process.Init) !u8 {
    var buffer: [4096]u8 = undefined;
    var file_writer: Io.File.Writer = .init(.stdout(), init.io, &buffer);
    const out = &file_writer.interface;
    defer out.flush() catch {};
    const options = parse_options(init) catch |err| {
        try out.print("demo-m0: bad arguments ({s}); see docs/DEMO.md\n", .{@errorName(err)});
        return 2;
    };
    const started = session_mod.now_ms();
    const code = demo(init, out, options) catch |err| {
        // The no-KVM message is already the whole story: one line, no stack of noise.
        if (err == error.NoKvm) return 1;
        try out.print("\ndemo-m0: FAILED ({s})\n", .{@errorName(err)});
        return 1;
    };
    try out.print("\ndemo-m0: PASSED in {d} s\n", .{(session_mod.now_ms() - started) / 1000});
    return code;
}

fn parse_options(init: std.process.Init) !Options {
    var options: Options = .{};
    var arguments = init.minimal.args.iterate();
    _ = arguments.next();
    while (arguments.next()) |name| {
        if (std.mem.eql(u8, name, "--delegate-dropin")) {
            options.delegate_dropin = true;
            continue;
        }
        if (std.mem.eql(u8, name, "--keep-overlay")) {
            options.keep_overlay = true;
            continue;
        }
        if (std.mem.eql(u8, name, "--reuse-overlay")) {
            options.reuse_overlay = true;
            options.keep_overlay = true;
            continue;
        }
        const value = arguments.next() orelse return error.MissingValue;
        if (std.mem.eql(u8, name, "--accel")) {
            options.accel = value;
        } else if (std.mem.eql(u8, name, "--zbx-x86_64")) {
            options.zbx_x86_64 = value;
        } else if (std.mem.eql(u8, name, "--zbx-aarch64")) {
            options.zbx_aarch64 = value;
        } else if (std.mem.eql(u8, name, "--cache-dir")) {
            options.cache_dir = value;
        } else {
            return error.UnknownOption;
        }
    }
    if (options.zbx_x86_64.len == 0 or options.zbx_aarch64.len == 0) return error.MissingBinary;
    return options;
}

/// Opens /dev/kvm read-write: usable means the accelerator will work.
fn kvm_usable(io: Io) bool {
    const options: Io.Dir.OpenFileOptions = .{ .mode = .read_write };
    const file = Io.Dir.openFileAbsolute(io, "/dev/kvm", options) catch return false;
    file.close(io);
    return true;
}

const AccelError = error{ BadAccel, NoKvm };

pub fn choose_accel(requested: []const u8, kvm_available: bool) AccelError!session_mod.Accel {
    if (std.mem.eql(u8, requested, "tcg")) return .tcg;
    if (std.mem.eql(u8, requested, "kvm")) return if (kvm_available) .kvm else error.NoKvm;
    if (!std.mem.eql(u8, requested, "auto")) return error.BadAccel;
    return if (kvm_available) .kvm else error.NoKvm;
}

fn demo(init: std.process.Init, out: *Io.Writer, options: Options) !u8 {
    const io = init.io;
    const accel = choose_accel(options.accel, kvm_usable(io)) catch |err| switch (err) {
        error.NoKvm => {
            try out.print("demo-m0: /dev/kvm is not usable here; for software emulation " ++
                "(slow) add -Daccel=tcg\n", .{});
            return error.NoKvm;
        },
        error.BadAccel => return error.BadAccel,
    };
    const binary = try check_binaries(init, out, options);
    const base = try image.ensure(init, options.cache_dir, out);
    const arena = init.arena.allocator();
    const overlay_format = "{s}/overlay-demo-m0.qcow2";
    const overlay = try std.fmt.allocPrint(arena, overlay_format, .{options.cache_dir});
    if (!options.reuse_overlay) try image.make_overlay(init, base, overlay);
    defer if (!options.keep_overlay) Io.Dir.cwd().deleteFile(io, overlay) catch {};

    const user_data = if (options.delegate_dropin)
        cloud_init.user_data_with_delegate
    else
        cloud_init.user_data;
    var session: Session = undefined;
    try session.start(init, out, overlay, accel, .{ .user_data = user_data, .binary = binary });
    defer session.deinit();
    var timer = Timer.start();
    try provision(&session, out, &timer, options.reuse_overlay);
    try install_binary(&session, out, &timer);
    try step_doctor_ok(&session, out, &timer);
    try step_userns_fails(&session, out, &timer);
    try step_static(&session, out, &timer);
    try session.shutdown();
    return 0;
}

const Timer = struct {
    began: u64,

    fn start() Timer {
        return .{ .began = session_mod.now_ms() };
    }

    fn lap(timer: *Timer, out: *Io.Writer, name: []const u8) !void {
        const now = session_mod.now_ms();
        try out.print("\ndemo-m0: [{s}] done in {d} s\n", .{ name, (now - timer.began) / 1000 });
        timer.began = now;
    }
};

/// Reads both release binaries and checks them: static ELF for the right machine, under
/// 2 MiB. Returns the x86_64 binary, which is the one the guest runs.
fn check_binaries(init: std.process.Init, out: *Io.Writer, options: Options) ![]const u8 {
    const arena = init.arena.allocator();
    const pairs = [_]struct { path: []const u8, machine: checks.Machine }{
        .{ .path = options.zbx_x86_64, .machine = .x86_64 },
        .{ .path = options.zbx_aarch64, .machine = .aarch64 },
    };
    var first: []const u8 = "";
    for (pairs) |pair| {
        const limit: Io.Limit = .limited(limits.elf_bytes_max);
        const bytes = try Io.Dir.cwd().readFileAlloc(init.io, pair.path, arena, limit);
        checks.check_static_elf(bytes, pair.machine) catch |err| {
            try out.print("demo-m0: {s} is not a static {s} ELF under 2 MiB: {s}\n", .{
                pair.path, @tagName(pair.machine), @errorName(err),
            });
            return err;
        };
        try out.print("demo-m0: {s}: static {s} ELF, {d} bytes (limit {d})\n", .{
            pair.path, @tagName(pair.machine), bytes.len, limits.binary_bytes_max,
        });
        if (first.len == 0) first = bytes;
    }
    return first;
}

fn provision(session: *Session, out: *Io.Writer, timer: *Timer, reuse: bool) !void {
    try out.print("\ndemo-m0: booting and provisioning the guest (cloud-init)...\n", .{});
    // A reused overlay is already provisioned: cloud-init does not run again.
    const boot_s = limits.boot_timeout_kvm_s;
    const ready = if (reuse) 0 else try session.wait_for(cloud_init.ready_marker, 0, boot_s);
    _ = try session.wait_for("root@zigbox-demo:~#", ready, limits.command_timeout_kvm_s);
    try session.send("stty -echo; bind 'set enable-bracketed-paste off'; PS1=''\n");
    // The first command's output still contains the echo of the line above; discard it.
    _ = try session.run("true", limits.command_timeout_kvm_s);
    // Wait for the guest to finish booting, so late service chatter (cloud-init prints key
    // fingerprints, for one) cannot land in the middle of a command's output.
    const settle = "cloud-init status --wait; systemctl is-system-running --wait; true";
    _ = try session.run(settle, limits.boot_timeout_kvm_s);
    const probe = try session.run("echo shell-ok", limits.command_timeout_kvm_s);
    if (!std.mem.eql(u8, probe.output, "shell-ok")) return error.ShellNotReady;
    try timer.lap(out, "boot and provision");
}

fn show(out: *Io.Writer, title: []const u8, result: Session.Result) !void {
    try out.print("\ndemo-m0: $ {s}   (exit {d})\n{s}\n", .{ title, result.status, result.output });
}

fn install_binary(session: *Session, out: *Io.Writer, timer: *Timer) !void {
    const command = try std.fmt.allocPrint(
        session.scratch_allocator(),
        "curl -fsS -o /home/demo/zbx http://10.0.2.2:{d}/zbx && " ++
            "chown demo:demo /home/demo/zbx && chmod 755 /home/demo/zbx && ls -l /home/demo/zbx",
        .{session.server.port},
    );
    const result = try session.run(command, limits.command_timeout_kvm_s);
    try show(out, "install zbx", result);
    if (result.status != 0) return error.InstallFailed;
    const manager = "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service";
    const gather = "uname -r; id demo; " ++
        "sysctl kernel.apparmor_restrict_unprivileged_userns user.max_user_namespaces; " ++
        "systemctl is-active user@1000.service; cat " ++ manager ++ "/cgroup.controllers; " ++
        "stat -c '%U %a' " ++ manager;
    const facts = try session.run(gather, limits.command_timeout_kvm_s);
    try show(out, "guest facts", facts);
    try timer.lap(out, "install");
}

const doctor_as_demo = "runuser -u demo -- /home/demo/zbx doctor";

fn step_doctor_ok(session: *Session, out: *Io.Writer, timer: *Timer) !void {
    try out.print("\ndemo-m0: STEP 1: zbx doctor on the fresh VM, as user demo\n", .{});
    const result = try session.run(doctor_as_demo, limits.command_timeout_kvm_s);
    try show(out, doctor_as_demo, result);
    checks.check_all_ok(result.output, result.status) catch |err| {
        try out.print("demo-m0: STEP 1 FAILED: expected six `ok` lines and exit 0 ({s})\n", .{
            @errorName(err),
        });
        return err;
    };
    try timer.lap(out, "step 1");
}

/// Copies a short sysctl value (digits) into `storage`, refusing anything else.
fn copy_value(storage: []u8, value: ?[]const u8) ![]const u8 {
    const text = std.mem.trim(u8, value orelse return error.BadSysctl, " \r");
    if (text.len == 0 or text.len > storage.len) return error.BadSysctl;
    for (text) |byte| {
        if (!std.ascii.isDigit(byte)) return error.BadSysctl;
    }
    @memcpy(storage[0..text.len], text);
    return storage[0..text.len];
}

const Case = struct {
    title: []const u8,
    set: []const u8,
    fix_contains: []const u8,
};

fn step_userns_fails(session: *Session, out: *Io.Writer, timer: *Timer) !void {
    try out.print("\ndemo-m0: STEP 2: disable user namespaces by sysctl; the userns check " ++
        "must FAIL with a fix\n", .{});
    const read_sysctls = "sysctl -n kernel.apparmor_restrict_unprivileged_userns; " ++
        "sysctl -n user.max_user_namespaces";
    const original = try session.run(read_sysctls, limits.command_timeout_kvm_s);
    // `original.output` lives in the session's scratch buffer, which the next command
    // overwrites: copy the two values out before running anything else.
    var apparmor_storage: [16]u8 = undefined;
    var maximum_storage: [16]u8 = undefined;
    var values = std.mem.splitScalar(u8, original.output, '\n');
    const apparmor = try copy_value(&apparmor_storage, values.next());
    const maximum = try copy_value(&maximum_storage, values.next());
    const cases = [_]Case{
        .{
            .title = "AppArmor restriction on",
            .set = "kernel.apparmor_restrict_unprivileged_userns=1",
            .fix_contains = "apparmor_restrict_unprivileged_userns=0",
        },
        .{
            .title = "user.max_user_namespaces=0 (the restriction is still on)",
            .set = "user.max_user_namespaces=0",
            .fix_contains = "user.max_user_namespaces",
        },
    };
    for (cases) |case| {
        try expect_userns_failure(session, out, case);
    }
    var restore_buffer: [160]u8 = undefined;
    const restore_format = "sysctl -w kernel.apparmor_restrict_unprivileged_userns={s} " ++
        "user.max_user_namespaces={s}";
    const restore = try std.fmt.bufPrint(&restore_buffer, restore_format, .{ apparmor, maximum });
    try show(out, restore, try session.run(restore, limits.command_timeout_kvm_s));
    const again = try session.run(doctor_as_demo, limits.command_timeout_kvm_s);
    try show(out, doctor_as_demo ++ "   (after restoring the sysctls)", again);
    checks.check_all_ok(again.output, again.status) catch |err| {
        try out.print("demo-m0: STEP 2 FAILED: doctor is not ok after restoring ({s})\n", .{
            @errorName(err),
        });
        return err;
    };
    try timer.lap(out, "step 2");
}

fn expect_userns_failure(session: *Session, out: *Io.Writer, case: Case) !void {
    var command_buffer: [200]u8 = undefined;
    const command = try std.fmt.bufPrint(&command_buffer, "sysctl -w {s}", .{case.set});
    try out.print("\ndemo-m0: case: {s}\n", .{case.title});
    try show(out, command, try session.run(command, limits.command_timeout_kvm_s));
    const result = try session.run(doctor_as_demo, limits.command_timeout_kvm_s);
    try show(out, doctor_as_demo, result);
    const verdict = checks.check_fails_with_fix(
        result.output,
        result.status,
        "userns",
        case.fix_contains,
    );
    verdict catch |err| {
        try out.print("demo-m0: STEP 2 FAILED: with `{s}` the userns check must be " ++
            "`FAIL ... \u{2014} fix: ...{s}...` and the exit code 1 ({s})\n", .{
            case.set, case.fix_contains, @errorName(err),
        });
        return err;
    };
}

fn step_static(session: *Session, out: *Io.Writer, timer: *Timer) !void {
    try out.print("\ndemo-m0: STEP 3: file zbx\n", .{});
    const result = try session.run("file /home/demo/zbx", limits.command_timeout_kvm_s);
    try show(out, "file /home/demo/zbx", result);
    if (result.status != 0) return error.FileFailed;
    checks.check_file_says_static(result.output) catch |err| {
        try out.print("demo-m0: STEP 3 FAILED: `file` does not say statically linked ({s})\n", .{
            @errorName(err),
        });
        return err;
    };
    try timer.lap(out, "step 3");
}

test "accelerator choice: KVM when usable, TCG only when asked, otherwise a clear error" {
    // Goal: software emulation is never silently chosen, and KVM is never requested without it.
    try std.testing.expectEqual(session_mod.Accel.kvm, try choose_accel("auto", true));
    try std.testing.expectError(error.NoKvm, choose_accel("auto", false));
    try std.testing.expectEqual(session_mod.Accel.tcg, try choose_accel("tcg", false));
    try std.testing.expectEqual(session_mod.Accel.tcg, try choose_accel("tcg", true));
    try std.testing.expectEqual(session_mod.Accel.kvm, try choose_accel("kvm", true));
    try std.testing.expectError(error.NoKvm, choose_accel("kvm", false));
    try std.testing.expectError(error.BadAccel, choose_accel("hvf", true));
}

test {
    _ = @import("checks.zig");
    _ = @import("cloud_init.zig");
    _ = @import("http_server.zig");
    _ = @import("image.zig");
    _ = @import("session.zig");
}
