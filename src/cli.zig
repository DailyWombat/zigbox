//! Hand-written command line parser and dispatcher. Pure with respect to the kernel: all
//! output goes through the `Host`, so snapshot tests can capture it from the simulator.
//!
//! Contract (docs/briefs/M0-doctor.md): `zbx doctor`, `zbx --version`, `zbx help`. Anything
//! else prints exactly one line to stderr and exits 2.

const std = @import("std");
const assert = std.debug.assert;
const build_options = @import("build_options");
const constants = @import("constants.zig");
const host_mod = @import("host.zig");
const doctor = @import("doctor.zig");
const text_util = @import("text.zig");

const Host = host_mod.Host;

const help_text =
    \\zbx - rootless container runtime
    \\
    \\usage: zbx <command>
    \\
    \\commands:
    \\  doctor      check that this host can run zbx
    \\  help        show this text
    \\  --version   print the version
    \\
;

const version_text = "zbx " ++ build_options.version ++ "\n";

comptime {
    // Fixed messages must fit the one buffer every message is rendered into.
    assert(help_text.len < constants.output_bytes_max);
    assert(version_text.len < constants.output_bytes_max);
    assert(help_text[help_text.len - 1] == '\n');
    assert(version_text[version_text.len - 1] == '\n');
}

pub const Command = enum { doctor, help, version };

pub const ParseError = error{
    MissingCommand,
    UnknownCommand,
    UnexpectedArgument,
};

pub const CollectError = error{
    TooManyArguments,
    ArgumentTooLong,
};

/// Maps the arguments after the program name to a command. Pure; the caller reports errors.
pub fn parse(args: []const []const u8) ParseError!Command {
    assert(args.len <= constants.args_count_max);
    if (args.len == 0) return error.MissingCommand;
    const name = args[0];
    const command = command_named(name) orelse return error.UnknownCommand;
    // None of the commands takes arguments yet.
    if (args.len > 1) return error.UnexpectedArgument;
    assert(args.len == 1);
    return command;
}

/// Exact match only: near misses such as `Help` or `version` are unknown commands.
fn command_named(name: []const u8) ?Command {
    assert(name.len <= constants.arg_bytes_max); // collect() refuses longer arguments.
    var found: ?Command = null;
    if (std.mem.eql(u8, name, "doctor")) found = .doctor;
    if (std.mem.eql(u8, name, "help")) found = .help;
    if (std.mem.eql(u8, name, "--help")) found = .help;
    if (std.mem.eql(u8, name, "--version")) found = .version;
    if (found != null) assert(name.len > 0); // The empty string is never a command.
    return found;
}

/// Copies the iterator's remaining arguments into fixed storage, refusing rather than
/// truncating when a limit is exceeded.
pub fn collect(
    storage: *[constants.args_count_max][]const u8,
    iterator: anytype,
) CollectError![]const []const u8 {
    var count: u32 = 0;
    while (iterator.next()) |argument| {
        if (count == constants.args_count_max) return error.TooManyArguments;
        if (argument.len > constants.arg_bytes_max) return error.ArgumentTooLong;
        assert(argument.len <= constants.arg_bytes_max);
        storage[count] = argument;
        count += 1;
    }
    assert(count <= constants.args_count_max);
    if (count > 0) assert(storage[count - 1].len <= constants.arg_bytes_max);
    return storage[0..count];
}

/// Entry point: skips the program name, collects, parses, runs. Returns the exit code.
pub fn run_from_iterator(host: Host, iterator: anytype) u8 {
    _ = iterator.next(); // Program name; absent only in a malformed exec, which is harmless.
    var storage: [constants.args_count_max][]const u8 = undefined;
    const args = collect(&storage, iterator) catch |err| {
        return report(host, switch (err) {
            error.TooManyArguments => "zbx: too many arguments; run 'zbx help'\n",
            error.ArgumentTooLong => "zbx: an argument is too long; run 'zbx help'\n",
        });
    };
    assert(args.len <= constants.args_count_max);
    const code = run(host, args);
    assert(code <= constants.exit_usage);
    return code;
}

pub fn run(host: Host, args: []const []const u8) u8 {
    assert(args.len <= constants.args_count_max);
    const command = parse(args) catch |err| return report_parse_error(host, err, args);
    assert(args.len == 1); // parse() accepts only a bare command name.
    switch (command) {
        .help => return emit(host, .stdout, help_text, constants.exit_ok),
        .version => return emit(host, .stdout, version_text, constants.exit_ok),
        .doctor => return doctor.run(host),
    }
}

fn report_parse_error(host: Host, err: ParseError, args: []const []const u8) u8 {
    // Only a missing command has no argument to echo.
    if (err != error.MissingCommand) assert(args.len > 0);
    if (err == error.MissingCommand) assert(args.len == 0);
    var echo_storage: [constants.arg_echo_bytes_max]u8 = undefined;
    var buffer: [constants.output_bytes_max]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    // Every message below fits the buffer: constants.zig asserts, at comptime, that it holds
    // the longest fixed prose plus two echoed arguments. So a write cannot fail.
    switch (err) {
        error.MissingCommand => {
            // Cannot fail: see above.
            writer.writeAll("zbx: missing command; run 'zbx help'\n") catch unreachable;
        },
        error.UnknownCommand => {
            const echo = text_util.sanitise(&echo_storage, args[0]);
            const format = "zbx: unknown command '{s}'; run 'zbx help'\n";
            writer.print(format, .{echo}) catch unreachable; // Cannot fail: see above.
        },
        error.UnexpectedArgument => {
            const echo = text_util.sanitise(&echo_storage, args[0]);
            const format = "zbx: '{s}' takes no arguments\n";
            writer.print(format, .{echo}) catch unreachable; // Cannot fail: see above.
        },
    }
    assert(writer.buffered().len > 0);
    return report(host, writer.buffered());
}

/// Writes one error line to stderr and returns the usage exit code.
fn report(host: Host, line: []const u8) u8 {
    assert(line.len > 0);
    assert(line[line.len - 1] == '\n');
    // Exactly one line: no newline before the final byte.
    assert(std.mem.indexOfScalar(u8, line[0 .. line.len - 1], '\n') == null);
    return emit(host, .stderr, line, constants.exit_usage);
}

/// Writes a message and returns `exit_code`. If the write itself fails there is no better
/// channel to report it on, so the exit code becomes `exit_failed`.
fn emit(host: Host, stream: host_mod.Stream, text: []const u8, exit_code: u8) u8 {
    assert(text.len > 0);
    assert(exit_code <= constants.exit_usage);
    host.write_all(stream, text) catch return constants.exit_failed;
    return exit_code;
}

const testing = std.testing;
const HostSim = @import("host_sim.zig").HostSim;
const repeat = @import("test_util.zig").repeat;

const SliceIterator = struct {
    items: []const [:0]const u8,
    index: u32 = 0,

    fn next(iterator: *SliceIterator) ?[:0]const u8 {
        if (iterator.index == iterator.items.len) return null;
        defer iterator.index += 1;
        return iterator.items[iterator.index];
    }
};

/// Runs the CLI against a fresh simulator and returns it with the exit code.
fn run_case(sim: *HostSim, args: []const [:0]const u8) !u8 {
    sim.init(1, &.{});
    var iterator: SliceIterator = .{ .items = args };
    const code = run_from_iterator(sim.interface(), &iterator);
    try testing.expectEqual(@as(u32, 0), sim.open_count());
    return code;
}

test "snapshot: help text on stdout, exit 0" {
    // Goal: the user-visible help is exactly the checked-in text. Method: compare byte for byte
    // against src/testdata/help.stdout.txt; update that file deliberately when help changes.
    var sim: HostSim = undefined;
    try testing.expectEqual(@as(u8, 0), try run_case(&sim, &.{ "zbx", "help" }));
    try testing.expectEqualStrings(@embedFile("testdata/help.stdout.txt"), sim.stdout());
    try testing.expectEqual(@as(usize, 0), sim.stderr().len);
    try testing.expectEqual(@as(u8, 0), try run_case(&sim, &.{ "zbx", "--help" }));
    try testing.expectEqualStrings(@embedFile("testdata/help.stdout.txt"), sim.stdout());
}

test "snapshot: --version prints the pinned version on stdout, exit 0" {
    // Goal: one line, "zbx <version>", where the version is build.zig.zon's.
    var sim: HostSim = undefined;
    try testing.expectEqual(@as(u8, 0), try run_case(&sim, &.{ "zbx", "--version" }));
    try testing.expectEqualStrings("zbx " ++ build_options.version ++ "\n", sim.stdout());
    try testing.expect(std.mem.startsWith(u8, sim.stdout(), "zbx 0."));
    try testing.expectEqual(@as(usize, 0), sim.stderr().len);
}

test "snapshot: unknown command is one stderr line, exit 2" {
    // Goal: the error line is exactly the checked-in text and nothing reaches stdout.
    var sim: HostSim = undefined;
    try testing.expectEqual(@as(u8, 2), try run_case(&sim, &.{ "zbx", "frobnicate" }));
    try testing.expectEqualStrings(@embedFile("testdata/unknown.stderr.txt"), sim.stderr());
    try testing.expectEqual(@as(usize, 0), sim.stdout().len);
}

test "snapshot: missing command and extra arguments are one stderr line, exit 2" {
    var sim: HostSim = undefined;
    try testing.expectEqual(@as(u8, 2), try run_case(&sim, &.{"zbx"}));
    try testing.expectEqualStrings(@embedFile("testdata/missing.stderr.txt"), sim.stderr());
    try testing.expectEqual(@as(u8, 2), try run_case(&sim, &.{ "zbx", "help", "me" }));
    try testing.expectEqualStrings(@embedFile("testdata/extra.stderr.txt"), sim.stderr());
    // Near misses of real commands are unknown, not accepted: parsing is exact.
    try testing.expectEqual(@as(u8, 2), try run_case(&sim, &.{ "zbx", "Help" }));
    try testing.expectEqual(@as(u8, 2), try run_case(&sim, &.{ "zbx", "version" }));
    try testing.expectEqual(@as(u8, 2), try run_case(&sim, &.{ "zbx", "" }));
}

test "snapshot: doctor on a host with nothing readable fails every check, exit 1" {
    // Goal: faults and absences are FAIL with a reason, never ok. The simulator here has no
    // files at all, so every check must fail; the whole report is checked in.
    var sim: HostSim = undefined;
    try testing.expectEqual(@as(u8, 1), try run_case(&sim, &.{ "zbx", "doctor" }));
    try testing.expectEqualStrings(@embedFile("testdata/doctor/empty_host.txt"), sim.stdout());
    try testing.expectEqual(@as(usize, 0), sim.stderr().len);
}

test "an echoed argument cannot inject terminal escapes or overflow the line" {
    // Goal: negative space. Control bytes and non-ASCII become '?', long text is truncated.
    var sim: HostSim = undefined;
    try testing.expectEqual(@as(u8, 2), try run_case(&sim, &.{ "zbx", "\x1b[31mred\n\xff" }));
    try testing.expectEqualStrings(
        "zbx: unknown command '?[31mred??'; run 'zbx help'\n",
        sim.stderr(),
    );

    const long = repeat('x', constants.arg_bytes_max);
    try testing.expectEqual(@as(u8, 2), try run_case(&sim, &.{ "zbx", long }));
    const expected_echo = repeat('x', constants.arg_echo_bytes_max - 3) ++ "...";
    try testing.expectEqualStrings(
        "zbx: unknown command '" ++ expected_echo ++ "'; run 'zbx help'\n",
        sim.stderr(),
    );
}

test "argument limits are refused, at the exact boundary" {
    // Goal: args_count_max arguments are accepted by collect; one more is refused; an argument
    // of arg_bytes_max bytes is accepted and one byte more is refused.
    const at_limit: [constants.args_count_max][:0]const u8 = @splat("a");
    var storage: [constants.args_count_max][]const u8 = undefined;
    var iterator: SliceIterator = .{ .items = &at_limit };
    const collected = try collect(&storage, &iterator);
    try testing.expectEqual(@as(usize, constants.args_count_max), collected.len);

    const over_limit: [constants.args_count_max + 1][:0]const u8 = @splat("a");
    iterator = .{ .items = &over_limit };
    try testing.expectError(error.TooManyArguments, collect(&storage, &iterator));

    const longest: [:0]const u8 = repeat('y', constants.arg_bytes_max);
    iterator = .{ .items = &.{longest} };
    _ = try collect(&storage, &iterator);
    const too_long: [:0]const u8 = repeat('y', constants.arg_bytes_max + 1);
    iterator = .{ .items = &.{too_long} };
    try testing.expectError(error.ArgumentTooLong, collect(&storage, &iterator));

    var sim: HostSim = undefined;
    try testing.expectEqual(@as(u8, 2), try run_case(&sim, &.{ "zbx", too_long }));
    try testing.expectEqualStrings(
        "zbx: an argument is too long; run 'zbx help'\n",
        sim.stderr(),
    );
}

test "a failing output stream is reported by exit code, not a crash" {
    // Goal: stdout closed or full must not panic. Method: fail every write; help exits 1.
    var sim: HostSim = undefined;
    sim.init(1, &.{});
    sim.faults.write_error_per_mille = 1000;
    var iterator: SliceIterator = .{ .items = &.{ "zbx", "help" } };
    try testing.expectEqual(@as(u8, 1), run_from_iterator(sim.interface(), &iterator));
}

test "output survives short writes" {
    // Goal: the help text arrives whole even when the kernel accepts one fragment at a time.
    var sim: HostSim = undefined;
    sim.init(5, &.{});
    sim.faults.short_write_per_mille = 1000;
    var iterator: SliceIterator = .{ .items = &.{ "zbx", "help" } };
    try testing.expectEqual(@as(u8, 0), run_from_iterator(sim.interface(), &iterator));
    try testing.expectEqualStrings(@embedFile("testdata/help.stdout.txt"), sim.stdout());
}
