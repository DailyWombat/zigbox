//! The demo's assertions as pure functions over bytes and text, so each can be unit-tested,
//! including with deliberately wrong input: a check that cannot fail proves nothing.

const std = @import("std");
const assert = std.debug.assert;
const limits = @import("limits.zig");

pub const CheckError = error{
    NotElf,
    NotStatic,
    WrongMachine,
    TooBig,
    Truncated,
    ReportMalformed,
    CheckNotOk,
    CheckNotFailed,
    FixMissing,
    ExitCodeWrong,
};

// ---- ELF -----------------------------------------------------------------------------------

pub const Machine = enum(u16) { x86_64 = 62, aarch64 = 183 };

const pt_dynamic: u32 = 2;
const pt_interp: u32 = 3;
const dt_needed: u64 = 1;
const dt_null: u64 = 0;

fn read_u16(bytes: []const u8, offset: usize) CheckError!u16 {
    if (offset + 2 > bytes.len) return error.Truncated;
    return std.mem.readInt(u16, bytes[offset..][0..2], .little);
}

fn read_u32(bytes: []const u8, offset: usize) CheckError!u32 {
    if (offset + 4 > bytes.len) return error.Truncated;
    return std.mem.readInt(u32, bytes[offset..][0..4], .little);
}

fn read_u64(bytes: []const u8, offset: usize) CheckError!u64 {
    if (offset + 8 > bytes.len) return error.Truncated;
    return std.mem.readInt(u64, bytes[offset..][0..8], .little);
}

/// Checks that `bytes` is a little-endian 64-bit ELF executable for `machine`, under the size
/// limit, with no interpreter (PT_INTERP) and no needed shared library (DT_NEEDED): the
/// definition of "static, no libc dependency" the milestone asks for.
pub fn check_static_elf(bytes: []const u8, machine: Machine) CheckError!void {
    if (bytes.len < 64) return error.NotElf;
    if (!std.mem.eql(u8, bytes[0..4], "\x7fELF")) return error.NotElf;
    if (bytes[4] != 2 or bytes[5] != 1) return error.NotElf; // 64-bit, little-endian.
    if (bytes.len >= limits.binary_bytes_max) return error.TooBig;
    if (try read_u16(bytes, 18) != @backingInt(machine)) return error.WrongMachine;

    const header_offset = try read_u64(bytes, 32);
    const header_size = try read_u16(bytes, 54);
    const header_count = try read_u16(bytes, 56);
    if (header_count > limits.program_headers_max) return error.NotElf;
    if (header_size < 56) return error.NotElf;
    for (0..header_count) |index| {
        const at = header_offset + index * header_size;
        if (at > bytes.len) return error.Truncated;
        const kind = try read_u32(bytes, @intCast(at));
        if (kind == pt_interp) return error.NotStatic;
        if (kind == pt_dynamic) try check_no_needed(bytes, @intCast(at));
    }
}

fn check_no_needed(bytes: []const u8, header_at: usize) CheckError!void {
    const offset = try read_u64(bytes, header_at + 8);
    const size = try read_u64(bytes, header_at + 32);
    const entries = @min(size / 16, limits.dynamic_entries_max);
    for (0..entries) |index| {
        const at = offset + index * 16;
        if (at + 16 > bytes.len) return error.Truncated;
        const tag = try read_u64(bytes, @intCast(at));
        if (tag == dt_null) return;
        if (tag == dt_needed) return error.NotStatic;
    }
}

// ---- The doctor report ---------------------------------------------------------------------

pub const check_names = [_][]const u8{
    "kernel", "userns", "cgroup", "overlay", "subid", "seccomp",
};

/// One parsed line of a doctor report.
pub const Line = struct {
    ok: bool,
    name: []const u8,
    text: []const u8,
};

/// Parses `ok   <name>  <detail>` / `FAIL <name>  <detail> — fix: <fix>` lines into `out`,
/// requiring exactly the six checks in order. Anything else is `ReportMalformed`.
pub fn parse_report(output: []const u8, out: *[check_names.len]Line) CheckError!void {
    var lines = std.mem.splitScalar(u8, output, '\n');
    var count: usize = 0;
    while (lines.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, "\r");
        if (line.len == 0) continue;
        if (count == check_names.len) return error.ReportMalformed;
        const ok = std.mem.startsWith(u8, line, "ok   ");
        const warn = std.mem.startsWith(u8, line, "warn ");
        const fail = std.mem.startsWith(u8, line, "FAIL ");
        if (!ok and !warn and !fail) return error.ReportMalformed;
        const rest = line[5..];
        const name = check_names[count];
        if (!std.mem.startsWith(u8, rest, name)) return error.ReportMalformed;
        if (!std.mem.startsWith(u8, rest[name.len..], "  ")) return error.ReportMalformed;
        out[count] = .{ .ok = ok or warn, .name = name, .text = line };
        count += 1;
    }
    if (count != check_names.len) return error.ReportMalformed;
}

/// Demo step 1: every check is `ok` and the exit code is 0.
pub fn check_all_ok(output: []const u8, exit_code: u8) CheckError!void {
    var report: [check_names.len]Line = undefined;
    try parse_report(output, &report);
    for (report) |line| {
        if (!std.mem.startsWith(u8, line.text, "ok   ")) return error.CheckNotOk;
    }
    if (exit_code != 0) return error.ExitCodeWrong;
}

/// Demo step 2: the named check is FAIL with a non-empty fix line, and the exit code is 1.
/// `fix_contains` (if given) must appear in the fix, to tie the fix to the cause.
pub fn check_fails_with_fix(
    output: []const u8,
    exit_code: u8,
    name: []const u8,
    fix_contains: ?[]const u8,
) CheckError!void {
    var report: [check_names.len]Line = undefined;
    try parse_report(output, &report);
    for (report) |line| {
        if (!std.mem.eql(u8, line.name, name)) continue;
        if (!std.mem.startsWith(u8, line.text, "FAIL ")) return error.CheckNotFailed;
        const marker = " \u{2014} fix: ";
        const at = std.mem.indexOf(u8, line.text, marker) orelse return error.FixMissing;
        const fix = line.text[at + marker.len ..];
        if (fix.len == 0) return error.FixMissing;
        if (fix_contains) |needle| {
            if (std.mem.indexOf(u8, fix, needle) == null) return error.FixMissing;
        }
        if (exit_code != 1) return error.ExitCodeWrong;
        return;
    }
    return error.ReportMalformed;
}

/// `file` must describe a statically linked ELF executable.
pub fn check_file_says_static(file_output: []const u8) CheckError!void {
    if (std.mem.indexOf(u8, file_output, "ELF 64-bit") == null) return error.NotElf;
    if (std.mem.indexOf(u8, file_output, "statically linked") == null) return error.NotStatic;
    if (std.mem.indexOf(u8, file_output, "dynamically linked") != null) return error.NotStatic;
}

// ---- Tests ---------------------------------------------------------------------------------

const testing = std.testing;

const good_report =
    "ok   kernel  6.8.0-45-generic x86_64 (minimum 5.15)\n" ++
    "ok   userns  user.max_user_namespaces=63488, unshare(CLONE_NEWUSER) works\n" ++
    "ok   cgroup  cgroup v2, user@1000.service delegated to uid 1000: cpu memory pids\n" ++
    "ok   overlay  overlayfs mounts inside a user and mount namespace\n" ++
    "ok   subid  demo (uid 1000): subuid 65536 ids, subgid 65536 ids\n" ++
    "ok   seccomp  seccomp is supported (current mode: disabled for this process)\n";

const userns_failed_report =
    "ok   kernel  6.8.0-45-generic x86_64 (minimum 5.15)\n" ++
    "FAIL userns  user.max_user_namespaces is 0 \u{2014} fix: " ++
    "sudo sysctl -w user.max_user_namespaces=15000\n" ++
    "ok   cgroup  c\nok   overlay  o\nok   subid  s\nok   seccomp  s\n";

test "step 1: a report with every check ok and exit 0 passes" {
    // Goal: the positive case, then each way it can be wrong must be refused.
    try check_all_ok(good_report, 0);
    try testing.expectError(error.ExitCodeWrong, check_all_ok(good_report, 1));
    try testing.expectError(error.CheckNotOk, check_all_ok(userns_failed_report, 0));
    try testing.expectError(error.ReportMalformed, check_all_ok("", 0));
    try testing.expectError(error.ReportMalformed, check_all_ok(good_report ++ good_report, 0));
    const warned = "warn kernel  x\n" ++ good_report[good_report.len - 0 ..];
    try testing.expectError(error.ReportMalformed, check_all_ok(warned, 0));
}

test "step 2: the named check must FAIL with a fix, and the exit code must be 1" {
    // Goal: a report that says ok for the check (the bug the demo exists to catch) fails the
    // demo, as do a missing fix, a wrong fix, a wrong exit code and a different check failing.
    try check_fails_with_fix(userns_failed_report, 1, "userns", "user.max_user_namespaces");
    try testing.expectError(
        error.CheckNotFailed,
        check_fails_with_fix(good_report, 1, "userns", null),
    );
    try testing.expectError(
        error.ExitCodeWrong,
        check_fails_with_fix(userns_failed_report, 0, "userns", null),
    );
    try testing.expectError(
        error.FixMissing,
        check_fails_with_fix(userns_failed_report, 1, "userns", "apparmor"),
    );
    try testing.expectError(
        error.CheckNotFailed,
        check_fails_with_fix(userns_failed_report, 1, "cgroup", null),
    );
    const no_fix = "ok   kernel  k\nFAIL userns  broken\nok   cgroup  c\n" ++
        "ok   overlay  o\nok   subid  s\nok   seccomp  s\n";
    try testing.expectError(error.FixMissing, check_fails_with_fix(no_fix, 1, "userns", null));
}

/// A minimal 64-bit little-endian ELF with one program header of `kind`.
fn elf_with(buffer: *[512]u8, machine: u16, kind: u32) []const u8 {
    @memset(buffer, 0);
    @memcpy(buffer[0..4], "\x7fELF");
    buffer[4] = 2;
    buffer[5] = 1;
    std.mem.writeInt(u16, buffer[18..20], machine, .little);
    std.mem.writeInt(u64, buffer[32..40], 64, .little);
    std.mem.writeInt(u16, buffer[54..56], 56, .little);
    std.mem.writeInt(u16, buffer[56..58], 1, .little);
    std.mem.writeInt(u32, buffer[64..68], kind, .little);
    return buffer[0..512];
}

test "ELF: a plain static executable passes; interpreter, needed libs, wrong machine fail" {
    // Goal: PT_LOAD-only passes; PT_INTERP (a dynamic loader) and a DT_NEEDED entry both mean
    // dynamically linked; the machine must match; garbage and truncation are errors.
    var buffer: [512]u8 = undefined;
    try check_static_elf(elf_with(&buffer, 62, 1), .x86_64);
    const plain = elf_with(&buffer, 62, 1);
    try testing.expectError(error.WrongMachine, check_static_elf(plain, .aarch64));
    const interpreted = elf_with(&buffer, 62, pt_interp);
    try testing.expectError(error.NotStatic, check_static_elf(interpreted, .x86_64));

    // A PT_DYNAMIC segment at offset 128 with a DT_NEEDED entry, then with only DT_NULL.
    const with_dynamic = elf_with(&buffer, 183, pt_dynamic);
    std.mem.writeInt(u64, buffer[72..80], 128, .little); // p_offset
    std.mem.writeInt(u64, buffer[96..104], 32, .little); // p_filesz
    std.mem.writeInt(u64, buffer[128..136], dt_needed, .little);
    try testing.expectError(error.NotStatic, check_static_elf(with_dynamic, .aarch64));
    std.mem.writeInt(u64, buffer[128..136], dt_null, .little);
    try check_static_elf(with_dynamic, .aarch64);

    const text = "not an elf at all, just text, padded out to a length that is long enough!!";
    try testing.expectError(error.NotElf, check_static_elf(text, .x86_64));
    try testing.expectError(error.NotElf, check_static_elf("short", .x86_64));
    try testing.expectError(error.Truncated, check_static_elf(buffer[0..100], .aarch64));
}

test "ELF: a binary at or over 2 MiB is too big" {
    // Goal: the boundary of the milestone's size limit, exact.
    var header: [512]u8 = undefined;
    _ = elf_with(&header, 62, 1);
    const big = try testing.allocator.alloc(u8, limits.binary_bytes_max);
    defer testing.allocator.free(big);
    @memcpy(big[0..512], &header);
    @memset(big[512..], 0);
    try testing.expectError(error.TooBig, check_static_elf(big, .x86_64));
    try check_static_elf(big[0 .. big.len - 1], .x86_64);
}

test "file output: only an ELF that is statically linked passes" {
    const static_line = "/home/demo/zbx: ELF 64-bit LSB executable, x86-64, statically linked";
    try check_file_says_static(static_line);
    try testing.expectError(
        error.NotStatic,
        check_file_says_static("zbx: ELF 64-bit LSB pie executable, dynamically linked"),
    );
    try testing.expectError(error.NotElf, check_file_says_static("zbx: ASCII text"));
}
