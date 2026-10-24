const std = @import("std");

/// The release targets. Both are built statically (no libc is ever linked) and in ReleaseSafe so
/// assertions stay on. See docs/STYLE.md.
const release_targets = [_]std.Target.Query{
    .{ .cpu_arch = .x86_64, .os_tag = .linux, .abi = .musl },
    .{ .cpu_arch = .aarch64, .os_tag = .linux, .abi = .musl },
};

const release_install_dirs = [_][]const u8{
    "release/x86_64-linux",
    "release/aarch64-linux",
};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // The version has one source of truth, build.zig.zon, handed to the code as an option.
    const manifest = @import("build.zig.zon");
    const options = b.addOptions();
    options.addOption([]const u8, "version", manifest.version);

    const exe = b.addExecutable(.{
        .name = "zbx",
        .root_module = zbx_module(b, options, target, optimize, null),
    });
    b.installArtifact(exe);

    add_test_step(b, options, target, optimize);
    add_tidy_step(b);
    add_fuzz_step(b, options, target);
    add_release_step(b, options);
    add_demo_step(b, options);
}

fn zbx_module(
    b: *std.Build,
    options: *std.Build.Step.Options,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    strip: ?bool,
) *std.Build.Module {
    return b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .strip = strip,
        .link_libc = false,
        .imports = &.{.{ .name = "build_options", .module = options.createModule() }},
    });
}

fn add_test_step(
    b: *std.Build,
    options: *std.Build.Step.Options,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) void {
    const test_step = b.step("test", "Run unit, snapshot and simulation tests");
    const roots = [_][]const u8{
        "src/testing/vm/main.zig",
        "src/main.zig",
        "src/tidy.zig",
        "src/fuzz.zig",
        "src/size_check.zig",
    };
    for (roots) |root| {
        const module = b.createModule(.{
            .root_source_file = b.path(root),
            .target = target,
            .optimize = optimize,
            .link_libc = false,
            .imports = &.{.{ .name = "build_options", .module = options.createModule() }},
        });
        const unit_tests = b.addTest(.{ .root_module = module });
        test_step.dependOn(&b.addRunArtifact(unit_tests).step);
    }
}

fn add_tidy_step(b: *std.Build) void {
    // Tidy is a host tool: always built for the machine running the build.
    const tidy = b.addExecutable(.{
        .name = "tidy",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/tidy.zig"),
            .target = b.graph.host,
            .optimize = .Debug,
        }),
    });
    const run = b.addRunArtifact(tidy);
    run.setCwd(b.path("."));
    // Formatting is checked alongside the mechanical rules: both must pass before review.
    const format = b.addFmt(.{ .paths = &.{ b.path("src"), b.path("build.zig") }, .check = true });
    const step = b.step("tidy", "Check formatting, line and function length, banned patterns");
    step.dependOn(&format.step);
    step.dependOn(&run.step);
}

fn add_fuzz_step(
    b: *std.Build,
    options: *std.Build.Step.Options,
    target: std.Build.ResolvedTarget,
) void {
    // Fuzzers keep assertions on regardless of the user's optimize flag: they exist to trip them.
    const fuzz = b.addExecutable(.{
        .name = "fuzz",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/fuzz.zig"),
            .target = target,
            .optimize = .ReleaseSafe,
            .link_libc = false,
            .imports = &.{.{ .name = "build_options", .module = options.createModule() }},
        }),
    });
    const run = b.addRunArtifact(fuzz);
    run.addPassthruArgs();
    const description = "Run one seeded fuzzer: zig build fuzz -- <fuzzer> [seed] [iterations]";
    const step = b.step("fuzz", description);
    step.dependOn(&run.step);
}

/// The spec's release criterion: a static binary under 2 MiB.
const release_size_limit_bytes = 2 * 1024 * 1024;

fn add_release_step(b: *std.Build, options: *std.Build.Step.Options) void {
    const description = "Cross-compile static ReleaseSafe binaries, stripped, under 2 MiB";
    const step = b.step("release", description);
    // Release binaries are stripped by default so that they meet the size limit; ReleaseSafe
    // stays, so assertions still fire, only without symbolised stack traces. -Dstrip=false builds
    // the debug-info variant (about 3.7 MB) for diagnosing a crash, and skips the size gate.
    const strip_help = "Strip debug info from release binaries (default true)";
    const strip = b.option(bool, "strip", strip_help) orelse true;

    const checker = b.addExecutable(.{
        .name = "size_check",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/size_check.zig"),
            .target = b.graph.host,
            .optimize = .Debug,
        }),
    });
    const check = b.addRunArtifact(checker);
    check.addArg(b.fmt("{d}", .{release_size_limit_bytes}));

    for (release_targets, release_install_dirs) |query, install_dir| {
        const exe = b.addExecutable(.{
            .name = "zbx",
            .root_module = zbx_module(b, options, b.resolveTargetQuery(query), .ReleaseSafe, strip),
        });
        const install = b.addInstallArtifact(exe, .{
            .dest_dir = .{ .override = .{ .custom = install_dir } },
        });
        step.dependOn(&install.step);
        check.addFileArg(exe.getEmittedBin());
    }
    if (strip) step.dependOn(&check.step);
}

/// `zig build demo-m0`: the milestone demo in a real Ubuntu VM. It always uses the stripped
/// ReleaseSafe binaries, the ones that ship. -Daccel=kvm|tcg|auto chooses the accelerator:
/// auto means KVM and fails with a one-line message if /dev/kvm is unusable; tcg (software
/// emulation, much slower) must be asked for explicitly.
fn add_demo_step(b: *std.Build, options: *std.Build.Step.Options) void {
    const Accel = enum { auto, kvm, tcg };
    const accel_help = "VM accelerator for demo-m0: auto (default), kvm, tcg";
    const accel = b.option(Accel, "accel", accel_help) orelse .auto;
    const dropin_help = "demo-m0: provision a Delegate= drop-in for user managers";
    const dropin = b.option(bool, "delegate-dropin", dropin_help) orelse false;
    const keep_help = "demo-m0: keep the VM disk overlay (development)";
    const keep = b.option(bool, "keep-overlay", keep_help) orelse false;
    const reuse_help = "demo-m0: boot the kept, provisioned overlay (development)";
    const reuse = b.option(bool, "reuse-overlay", reuse_help) orelse false;

    const vm = b.addExecutable(.{
        .name = "vm",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/testing/vm/main.zig"),
            .target = b.graph.host,
            .optimize = .ReleaseSafe,
        }),
    });
    const run = b.addRunArtifact(vm);
    run.setCwd(b.path("."));
    run.addArgs(&.{ "--accel", @tagName(accel) });
    if (dropin) run.addArg("--delegate-dropin");
    if (keep) run.addArg("--keep-overlay");
    if (reuse) run.addArg("--reuse-overlay");
    const flags = [_][]const u8{ "--zbx-x86_64", "--zbx-aarch64" };
    for (release_targets, flags) |query, flag| {
        const exe = b.addExecutable(.{
            .name = "zbx",
            .root_module = zbx_module(b, options, b.resolveTargetQuery(query), .ReleaseSafe, true),
        });
        run.addArg(flag);
        run.addFileArg(exe.getEmittedBin());
    }
    const step = b.step("demo-m0", "Run the M0 demo in a real Ubuntu 24.04 VM (see docs/DEMO.md)");
    step.dependOn(&run.step);
}
