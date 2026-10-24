//! Seeded fuzz runner: `zig build fuzz -- <fuzzer> [seed] [iterations]`.
//!
//! The seed is printed first, before any fuzzing, so that a crash (a failed assertion) can be
//! replayed exactly: `zig build fuzz -- <fuzzer> <seed>`. Without a seed the runner draws one
//! from the OS and prints it. Each iteration derives its own seed from the master seed with
//! SplitMix64, so the whole run is a pure function of (fuzzer, seed, iterations).

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const host = @import("host.zig");
const cli = @import("cli.zig");
const doctor = @import("doctor.zig");
const fixtures = @import("doctor_fixtures.zig");
const parse_fuzz = @import("fuzz_parse.zig");
const text_util = @import("text.zig");
const HostSim = @import("host_sim.zig").HostSim;
const sim_file = @import("host_sim.zig").File;
const Faults = @import("host_sim.zig").Faults;

const Fuzzer = struct {
    name: []const u8,
    run_iteration: *const fn (seed: u64) void,
};

const fuzzers = [_]Fuzzer{
    .{ .name = "host_read", .run_iteration = fuzz_host_read },
    .{ .name = "host_write", .run_iteration = fuzz_host_write },
    .{ .name = "cli", .run_iteration = fuzz_cli },
    .{ .name = "text", .run_iteration = fuzz_text },
    .{ .name = "doctor", .run_iteration = fuzz_doctor },
    .{ .name = "parse_sysctl", .run_iteration = parse_fuzz.fuzz_parse_sysctl },
    .{ .name = "parse_kernel", .run_iteration = parse_fuzz.fuzz_parse_kernel },
    .{ .name = "parse_controllers", .run_iteration = parse_fuzz.fuzz_parse_controllers },
    .{ .name = "parse_subid", .run_iteration = parse_fuzz.fuzz_parse_subid },
    .{ .name = "parse_passwd", .run_iteration = parse_fuzz.fuzz_parse_passwd },
    .{ .name = "parse_seccomp", .run_iteration = parse_fuzz.fuzz_parse_seccomp },
    .{ .name = "parse_capability", .run_iteration = parse_fuzz.fuzz_parse_capability },
};

const content_bytes_max: u32 = 300;

/// Faults at random strengths, with 0 and 1000 (never and always) over-represented because the
/// extremes are where loops and bounds break.
fn random_per_mille(random: std.Random) u16 {
    const per_mille: u16 = switch (random.uintLessThan(u8, 4)) {
        0 => 0,
        1 => 1000,
        else => random.uintLessThan(u16, 1001),
    };
    assert(per_mille <= 1000);
    return per_mille;
}

fn random_faults(random: std.Random) Faults {
    const interrupt_per_mille = random.uintLessThan(u16, 400);
    assert(interrupt_per_mille < 1000); // Always-interrupted is covered by a unit test.
    return .{
        .open_error_per_mille = random_per_mille(random),
        .read_error_per_mille = random_per_mille(random),
        .short_read_per_mille = random_per_mille(random),
        .write_error_per_mille = random_per_mille(random),
        .short_write_per_mille = random_per_mille(random),
        .interrupt_per_mille = interrupt_per_mille,
    };
}

/// Errors a one-shot injected failure may use. `FileTooLarge`, `Stalled` and the path errors are
/// excluded because only real conditions may produce them.
fn random_injected_error(random: std.Random) host.Error {
    const choices = [_]host.Error{
        error.IoFailed, error.OutOfMemory, error.AccessDenied, error.NotFound,
        error.NoSpace,  error.WouldBlock,  error.Unsupported,  error.Interrupted,
    };
    return choices[random.uintLessThan(usize, choices.len)];
}

/// Property: a read either returns exactly the file's bytes or fails with an operating error.
/// It never returns a truncated or altered success, never livelocks, never leaks a handle.
/// A one-shot failure is injected at a random early call (or not at all), so the failure
/// walks across open, first read, later reads and the EOF probe.
fn fuzz_host_read(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();

    var content: [content_bytes_max]u8 = undefined;
    const content_len = random.uintAtMost(u32, content_bytes_max);
    random.bytes(content[0..content_len]);
    const files = [_]sim_file{.{ .path = "/fuzz", .content = content[0..content_len] }};

    var sim: HostSim = undefined;
    sim.init(random.int(u64), &files);
    sim.faults = random_faults(random);
    if (random.boolean()) sim.faults.fail_call_index = random.uintLessThan(u32, 8);
    sim.faults.fail_call_error = random_injected_error(random);

    var buffer: [content_bytes_max]u8 = undefined;
    const buffer_len = random.intRangeAtMost(u32, 1, content_bytes_max);
    const result = sim.interface().read_file("/fuzz", buffer[0..buffer_len]);

    assert(sim.open_count() == 0);
    if (result) |bytes| {
        assert(content_len <= buffer_len); // Negative space: too-large files never succeed.
        assert(std.mem.eql(u8, bytes, content[0..content_len]));
    } else |err| switch (err) {
        error.FileTooLarge => assert(content_len > buffer_len),
        error.Stalled, error.InvalidPath, error.PathTooLong => unreachable, // Not producible.
        else => {},
    }
}

/// Property: write_all delivers every byte in order or fails; whatever reached the sink is
/// always a prefix of the message.
fn fuzz_host_write(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();

    var message: [content_bytes_max]u8 = undefined;
    const message_len = random.uintAtMost(u32, content_bytes_max);
    random.bytes(message[0..message_len]);

    var sim: HostSim = undefined;
    sim.init(random.int(u64), &.{});
    sim.faults = random_faults(random);

    const result = sim.interface().write_all(.stdout, message[0..message_len]);
    assert(std.mem.startsWith(u8, message[0..message_len], sim.stdout()));
    assert(sim.stderr().len == 0);
    if (result) |_| {
        assert(sim.stdout().len == message_len);
    } else |err| switch (err) {
        error.NoSpace, error.IoFailed => {},
        else => unreachable,
    }
}

fn only_write_faults(faults: Faults) Faults {
    return .{
        .write_error_per_mille = faults.write_error_per_mille,
        .short_write_per_mille = faults.short_write_per_mille,
    };
}

/// Arguments for one CLI fuzz case, replayable: both runs get an identical copy.
const FuzzArgs = struct {
    items: [constants.args_count_max + 3][]const u8,
    count: u32,
    index: u32,

    pub fn next(args: *FuzzArgs) ?[]const u8 {
        if (args.index == args.count) return null;
        defer args.index += 1;
        return args.items[args.index];
    }
};

/// Builds a program name followed by random arguments: known words, short random bytes, and
/// (sometimes) over-limit lengths and counts. `short` and `long` back the slices.
fn random_args(
    random: std.Random,
    short: *[constants.args_count_max + 2][16]u8,
    long: *[constants.arg_bytes_max + 8]u8,
) FuzzArgs {
    const words = [_][]const u8{ "doctor", "help", "--help", "--version", "version", "", "-" };
    @memset(long, random.int(u8));
    var args: FuzzArgs = .{ .items = undefined, .count = 1, .index = 0 };
    args.items[0] = "zbx";
    const many = random.uintLessThan(u8, 8) == 0;
    const wanted = if (many)
        random.uintAtMost(u32, constants.args_count_max + 2)
    else
        random.uintAtMost(u32, 3);
    for (0..wanted) |slot| {
        // Long arguments are refused first, so the many-arguments case avoids them to reach
        // the count limit.
        const kind = if (many) random.uintLessThan(u8, 6) else random.uintLessThan(u8, 8);
        const argument: []const u8 = switch (kind) {
            0...3 => words[random.uintLessThan(usize, words.len)],
            4...5 => blk: {
                random.bytes(&short[slot]);
                break :blk short[slot][0..random.uintAtMost(u32, short[slot].len)];
            },
            // Exactly at, one over and a little over the argument limit.
            else => long[0 .. constants.arg_bytes_max - 1 + random.uintAtMost(u32, 9)],
        };
        args.items[args.count] = argument;
        args.count += 1;
    }
    assert(args.count <= args.items.len);
    return args;
}

/// Property, comparing a fault-free run with a faulted run of the same arguments:
/// exit codes stay in {0,1,2}; no handle leaks; whatever reached each stream under faults is a
/// prefix of the fault-free output; if the output arrived complete the exit code is the
/// fault-free one, otherwise it is exit_failed (a write failed). Goes through
/// `run_from_iterator`, so argument collection and its limits are fuzzed too.
fn fuzz_cli(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();

    var short: [constants.args_count_max + 2][16]u8 = undefined;
    var long: [constants.arg_bytes_max + 8]u8 = undefined;
    const args = random_args(random, &short, &long);

    var reference: HostSim = undefined;
    reference.init(1, &.{});
    var reference_args = args;
    const reference_code = cli.run_from_iterator(reference.interface(), &reference_args);

    var faulted: HostSim = undefined;
    faulted.init(random.int(u64), &.{});
    faulted.faults = random_faults(random);
    if (random.boolean()) faulted.faults.fail_call_index = random.uintLessThan(u32, 3);
    faulted.faults.fail_call_error = random_injected_error(random);
    // The doctor reads the host, so read faults change what it reports (that is the doctor
    // fuzzer's subject); here only the output path is faulted for it.
    const runs_doctor = args.count > 1 and std.mem.eql(u8, args.items[1], "doctor");
    if (runs_doctor) faulted.faults = only_write_faults(faulted.faults);
    var faulted_args = args;
    const faulted_code = cli.run_from_iterator(faulted.interface(), &faulted_args);

    assert(reference_code <= constants.exit_usage);
    assert(faulted_code <= constants.exit_usage);
    assert(reference.open_count() == 0);
    assert(faulted.open_count() == 0);
    assert(std.mem.startsWith(u8, reference.stdout(), faulted.stdout()));
    assert(std.mem.startsWith(u8, reference.stderr(), faulted.stderr()));
    if (reference_code == constants.exit_usage) {
        assert(reference.stdout().len == 0);
        assert(std.mem.count(u8, reference.stderr(), "\n") == 1);
    }
    const complete = faulted.stdout().len == reference.stdout().len and
        faulted.stderr().len == reference.stderr().len;
    if (complete) {
        assert(faulted_code == reference_code);
    } else {
        assert(faulted_code == constants.exit_failed);
    }
}

/// An independent statement of "printable" (space to tilde), so a wrong `is_printable` is caught.
fn is_printable_reference(byte: u8) bool {
    return byte >= 0x20 and byte <= 0x7e;
}

/// Property: sanitised text is printable ASCII, fits the storage, equals the input when the
/// input is already printable and short enough, and a Bounded string never exceeds its capacity.
fn fuzz_text(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();
    var input: [96]u8 = undefined;
    const length = random.uintAtMost(usize, input.len);
    random.bytes(input[0..length]);
    if (random.boolean()) {
        for (input[0..length]) |*byte| byte.* = 0x20 + byte.* % 0x5f;
    }
    var storage: [32]u8 = undefined;
    const clean = text_util.sanitise(&storage, input[0..length]);
    assert(clean.len <= storage.len);
    for (clean) |byte| assert(is_printable_reference(byte));
    if (length <= storage.len) {
        assert(clean.len == length);
        const printable = for (input[0..length]) |byte| {
            if (!is_printable_reference(byte)) break false;
        } else true;
        if (printable) assert(std.mem.eql(u8, clean, input[0..length]));
    } else {
        assert(clean.len == storage.len);
        assert(std.mem.endsWith(u8, clean, "..."));
    }

    var bounded: text_util.Bounded(24) = .{};
    for (0..random.uintAtMost(u8, 6)) |_| bounded.append_sanitised(input[0..length], 12);
    assert(bounded.len <= 24);
    for (bounded.slice()) |byte| assert(is_printable_reference(byte));
}

/// Errors a doctor fault may inject. NotFound is excluded because it is a legitimate answer
/// ("this sysctl does not exist"), indistinguishable from an injected one.
fn random_doctor_error(random: std.Random) host.Error {
    const choices = [_]host.Error{
        error.IoFailed,    error.OutOfMemory, error.AccessDenied,
        error.NoSpace,     error.WouldBlock,  error.Unsupported,
        error.Interrupted,
    };
    return choices[random.uintLessThan(usize, choices.len)];
}

/// Property, per check, comparing a fault-free run with a faulted run of the same host:
///  - if a hard error (anything but an interrupt) was injected into the check's gather, the
///    check is FAIL; a fault is never answered ok or warn;
///  - if nothing at all was injected into it, the check equals the fault-free result;
///  - every report is well formed (fails have a fix, oks have none) and the exit code is 1
///    exactly when some check is FAIL; no handle leaks.
fn fuzz_doctor(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();
    const fixture = &fixtures.all[random.uintLessThan(usize, fixtures.all.len)];

    var reference: HostSim = undefined;
    reference.init(1, fixture.files);
    fixture.apply(&reference);
    var facts: doctor.Facts = undefined;
    facts.reset();
    doctor.gather(reference.interface(), &facts);
    var expected: doctor.Report = undefined;
    doctor.evaluate(&facts, &expected);

    var faulted: HostSim = undefined;
    faulted.init(random.int(u64), fixture.files);
    fixture.apply(&faulted);
    faulted.faults = random_faults(random);
    faulted.faults.write_error_per_mille = 0;
    if (random.boolean()) faulted.faults.fail_call_index = random.uintLessThan(u32, 48);
    faulted.faults.fail_call_error = random_doctor_error(random);

    var injected: [constants.doctor_checks_count]struct { hard: u32, any: u32 } = undefined;
    facts.reset();
    for (std.enums.values(doctor.CheckId), 0..) |id, index| {
        const hard_before = faulted.hard_errors_injected;
        const interrupts_before = faulted.interrupts_injected;
        doctor.gather_one(faulted.interface(), &facts, id);
        const hard = faulted.hard_errors_injected - hard_before;
        const interrupts = faulted.interrupts_injected - interrupts_before;
        injected[index] = .{ .hard = hard, .any = hard + interrupts };
    }
    var report: doctor.Report = undefined;
    doctor.evaluate(&facts, &report);
    assert(faulted.open_count() == 0);
    check_doctor_report(&report, &expected, &injected);
}

fn check_doctor_report(
    report: *const doctor.Report,
    expected: *const doctor.Report,
    injected: anytype,
) void {
    report.validate();
    var any_fail = false;
    for (report.checks, expected.checks, injected) |check, reference, counts| {
        if (check.status == .fail) any_fail = true;
        if (counts.hard > 0) assert(check.status == .fail);
        if (counts.any == 0) {
            assert(check.status == reference.status);
            assert(std.mem.eql(u8, check.detail.slice(), reference.detail.slice()));
            assert(std.mem.eql(u8, check.fix.slice(), reference.fix.slice()));
        }
    }
    const code = report.exit_code();
    assert(code == if (any_fail) constants.exit_failed else constants.exit_ok);
}

const Parsed = struct {
    fuzzer: *const Fuzzer,
    seed: ?u64,
    iterations: u32,
};

const UsageError = error{ NoFuzzer, UnknownFuzzer, BadSeed, BadIterations, TooManyArguments };

fn parse_arguments(arguments: []const []const u8) UsageError!Parsed {
    if (arguments.len == 0) return error.NoFuzzer;
    if (arguments.len > 3) return error.TooManyArguments;
    assert(arguments.len >= 1);
    assert(arguments.len <= 3);
    const fuzzer = for (&fuzzers) |*candidate| {
        if (std.mem.eql(u8, candidate.name, arguments[0])) break candidate;
    } else return error.UnknownFuzzer;

    var seed: ?u64 = null;
    if (arguments.len >= 2) {
        seed = std.fmt.parseInt(u64, arguments[1], 0) catch return error.BadSeed;
    }
    var iterations = constants.fuzz_iterations_default;
    if (arguments.len == 3) {
        iterations = std.fmt.parseInt(u32, arguments[2], 10) catch return error.BadIterations;
        if (iterations == 0) return error.BadIterations;
        if (iterations > constants.fuzz_iterations_max) return error.BadIterations;
    }
    assert(iterations > 0);
    assert(iterations <= constants.fuzz_iterations_max);
    return .{ .fuzzer = fuzzer, .seed = seed, .iterations = iterations };
}

pub fn main(init: std.process.Init) u8 {
    var buffer: [4096]u8 = undefined;
    var file_writer: std.Io.File.Writer = .init(.stdout(), init.io, &buffer);
    const out = &file_writer.interface;

    var arguments_storage: [4][]const u8 = undefined;
    var iterator = init.minimal.args.iterate();
    _ = iterator.next();
    var count: u32 = 0;
    while (iterator.next()) |argument| {
        if (count == arguments_storage.len) break;
        arguments_storage[count] = argument;
        count += 1;
    }
    const parsed = parse_arguments(arguments_storage[0..count]) catch |err| {
        print_usage(out, err) catch {};
        return constants.exit_usage;
    };

    assert(parsed.iterations > 0);
    assert(parsed.fuzzer.name.len > 0);
    var seed = parsed.seed orelse 0;
    if (parsed.seed == null) {
        var entropy: [8]u8 = undefined;
        init.io.random(&entropy);
        seed = std.mem.readInt(u64, &entropy, .little);
    }
    // The seed goes out, and is flushed, before the first iteration can crash.
    out.print("fuzz: {s} seed={d} iterations={d}\n", .{
        parsed.fuzzer.name, seed, parsed.iterations,
    }) catch return constants.exit_failed;
    out.flush() catch return constants.exit_failed;

    var splitmix = std.Random.SplitMix64.init(seed);
    for (0..parsed.iterations) |_| {
        parsed.fuzzer.run_iteration(splitmix.next());
    }
    out.print("fuzz: {s} ok\n", .{parsed.fuzzer.name}) catch return constants.exit_failed;
    out.flush() catch return constants.exit_failed;
    return constants.exit_ok;
}

fn print_usage(out: *std.Io.Writer, err: UsageError) !void {
    assert(@errorName(err).len > 0);
    assert(fuzzers.len > 0);
    try out.print("fuzz: {s}\nusage: zig build fuzz -- <fuzzer> [seed] [iterations]\n", .{
        @errorName(err),
    });
    try out.writeAll("fuzzers:");
    for (fuzzers) |fuzzer| try out.print(" {s}", .{fuzzer.name});
    try out.writeAll("\n");
    try out.flush();
}

test "parse_arguments accepts the documented forms and refuses the rest" {
    // Goal: `<fuzzer>`, `<fuzzer> <seed>` and `<fuzzer> <seed> <iterations>` parse; hex seeds
    // work; every malformed form is a named error.
    const only_name = try parse_arguments(&.{"host_read"});
    try std.testing.expect(only_name.seed == null);
    try std.testing.expectEqual(constants.fuzz_iterations_default, only_name.iterations);

    const with_seed = try parse_arguments(&.{ "host_write", "0xff" });
    try std.testing.expectEqual(@as(?u64, 255), with_seed.seed);
    const with_all = try parse_arguments(&.{ "cli", "7", "12" });
    try std.testing.expectEqual(@as(u32, 12), with_all.iterations);

    try std.testing.expectError(error.NoFuzzer, parse_arguments(&.{}));
    try std.testing.expectError(error.UnknownFuzzer, parse_arguments(&.{"nope"}));
    try std.testing.expectError(error.BadSeed, parse_arguments(&.{ "cli", "x1" }));
    try std.testing.expectError(error.BadIterations, parse_arguments(&.{ "cli", "1", "0" }));
    const too_many = parse_arguments(&.{ "cli", "1", "2", "3" });
    try std.testing.expectError(error.TooManyArguments, too_many);
}

test "every fuzzer survives a fixed seed for a few hundred iterations" {
    // Goal: the fuzzers themselves are exercised by `zig build test`, so a broken property or a
    // regression in host.zig fails here, with a seed that reproduces it.
    for (fuzzers) |fuzzer| {
        var splitmix = std.Random.SplitMix64.init(12345);
        for (0..500) |_| fuzzer.run_iteration(splitmix.next());
    }
}
