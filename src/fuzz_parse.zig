//! Fuzzers for the pure parsers in parse.zig. Each iteration builds an input (random bytes,
//! a mutated valid sample, or a concatenation of samples), runs the parser, and compares it
//! with an independent reference reading of the same format written here in a different style
//! (explicit scanning and state machines instead of the parser's helper calls).
//!
//! Property: the parser accepts exactly the inputs the reference accepts, with equal values,
//! and never crashes on any input, including truncated, oversized, NUL-containing and
//! non-UTF-8 ones.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const parse = @import("parse.zig");

const input_bytes_max = 2048;

const interesting = "0123456789:\n \t-+_.~#/\x00\xff\x1b,=abcxyzACPU\x80";

// ---- Input generation ----------------------------------------------------------------------

/// Applies one to four random edits to `buffer[0..length]`; returns the new length.
fn mutate(random: std.Random, buffer: *[input_bytes_max]u8, length_in: usize) usize {
    var length = length_in;
    const edits = random.intRangeAtMost(u8, 1, 4);
    for (0..edits) |_| {
        switch (random.uintLessThan(u8, 6)) {
            0 => if (length > 0) {
                buffer[random.uintLessThan(usize, length)] = pick_interesting(random);
            },
            1 => if (length < input_bytes_max) {
                const at = random.uintAtMost(usize, length);
                @memmove(buffer[at + 1 .. length + 1], buffer[at..length]);
                buffer[at] = interesting[random.uintLessThan(usize, interesting.len)];
                length += 1;
            },
            2 => if (length > 0) {
                const at = random.uintLessThan(usize, length);
                @memmove(buffer[at .. length - 1], buffer[at + 1 .. length]);
                length -= 1;
            },
            3 => length = random.uintAtMost(usize, length), // Truncate.
            4 => if (length > 0 and length * 2 <= input_bytes_max) {
                @memcpy(buffer[length .. length * 2], buffer[0..length]); // Duplicate.
                length *= 2;
            },
            else => if (length > 0) {
                buffer[random.uintLessThan(usize, length)] = random.int(u8);
            },
        }
    }
    assert(length <= input_bytes_max);
    return length;
}

/// Builds one input: pure noise, a valid sample (sometimes several joined), mutated or not.
fn make_input(
    random: std.Random,
    samples: []const []const u8,
    buffer: *[input_bytes_max]u8,
) []const u8 {
    var length: usize = 0;
    const style = random.uintLessThan(u8, 8);
    if (style == 0) {
        length = random.uintAtMost(usize, 64);
        for (buffer[0..length]) |*byte| {
            byte.* = if (random.boolean()) pick_interesting(random) else random.int(u8);
        }
        return buffer[0..length];
    }
    const pieces: usize = if (style < 3) 1 else random.intRangeAtMost(usize, 1, 4);
    for (0..pieces) |_| {
        const sample = samples[random.uintLessThan(usize, samples.len)];
        if (length + sample.len > input_bytes_max) break;
        @memcpy(buffer[length..][0..sample.len], sample);
        length += sample.len;
    }
    if (style != 1) length = mutate(random, buffer, length);
    return buffer[0..length];
}

// ---- Reference readings --------------------------------------------------------------------

fn pick_interesting(random: std.Random) u8 {
    return interesting[random.uintLessThan(usize, interesting.len)];
}

fn is_digit(byte: u8) bool {
    return byte >= '0' and byte <= '9';
}

/// Canonical decimal number: 1..digits_max digits, no leading zero except "0".
fn ref_number(text: []const u8, digits_max: usize) ?u64 {
    if (text.len == 0 or text.len > digits_max) return null;
    if (text[0] == '0' and text.len > 1) return null;
    for (text) |byte| {
        if (!is_digit(byte)) return null;
    }
    return std.fmt.parseInt(u64, text, 10) catch null;
}

fn ref_u32(text: []const u8) ?u32 {
    const value = ref_number(text, 10) orelse return null;
    if (value > std.math.maxInt(u32)) return null;
    return @intCast(value);
}

fn ref_sysctl(text: []const u8) ?u32 {
    var body = text;
    if (body.len > 0 and body[body.len - 1] == '\n') body = body[0 .. body.len - 1];
    return ref_u32(body);
}

fn ref_kernel(text: []const u8) ?parse.KernelVersion {
    if (text.len == 0 or text.len > 64) return null;
    var end: usize = 0;
    while (end < text.len and (is_digit(text[end]) or text[end] == '.')) end += 1;
    if (end < text.len) {
        if (std.mem.indexOfScalar(u8, "-+_~", text[end]) == null) return null;
        for (text[end..]) |byte| {
            if (byte <= 0x20 or byte >= 0x7f) return null;
        }
    }
    var numbers: [3]u32 = .{ 0, 0, 0 };
    var count: usize = 0;
    var parts = std.mem.splitScalar(u8, text[0..end], '.');
    while (parts.next()) |part| {
        if (count == 3) return null;
        const value = ref_number(part, 9) orelse return null;
        numbers[count] = @intCast(value);
        count += 1;
    }
    if (count < 2) return null;
    return .{ .major = numbers[0], .minor = numbers[1], .patch = numbers[2] };
}

const known_controllers = [_][]const u8{
    "cpuset", "cpu", "io", "memory", "hugetlb", "pids", "rdma", "misc",
};

fn ref_controllers(text: []const u8) ?struct { bits: u16, unknown: u32 } {
    if (text.len > constants.cgroup_list_bytes_max) return null;
    var body = text;
    if (body.len > 0 and body[body.len - 1] == '\n') body = body[0 .. body.len - 1];
    var bits: u16 = 0;
    var unknown: u32 = 0;
    if (body.len == 0) return .{ .bits = 0, .unknown = 0 };
    var count: u32 = 0;
    var word_start: usize = 0;
    var index: usize = 0;
    while (index <= body.len) : (index += 1) {
        if (index < body.len and body[index] != ' ') continue;
        const word = body[word_start..index];
        word_start = index + 1;
        count += 1;
        if (count > 32 or word.len == 0 or word.len > 32) return null;
        for (word) |byte| {
            if (!((byte >= 'a' and byte <= 'z') or byte == '_' or is_digit(byte))) return null;
        }
        var matched = false;
        for (known_controllers, 0..) |name, bit| {
            if (!std.mem.eql(u8, name, word)) continue;
            // The parser numbers controllers in declaration order, the same order as this list.
            const mask = @as(u16, 1) << @intCast(bit);
            if (bits & mask != 0) return null;
            bits |= mask;
            matched = true;
        }
        if (!matched) unknown += 1;
    }
    return .{ .bits = bits, .unknown = unknown };
}

fn ref_subid(text: []const u8, name: ?[]const u8, uid: u32) parse.SubidRanges {
    var result: parse.SubidRanges = .{};
    var uid_text_buffer: [16]u8 = undefined;
    const uid_text = std.fmt.bufPrint(&uid_text_buffer, "{d}", .{uid}) catch unreachable; // Fits.
    var start: usize = 0;
    while (start <= text.len) {
        const end = std.mem.indexOfScalarPos(u8, text, start, '\n') orelse text.len;
        const line = text[start..end];
        start = end + 1;
        if (line.len == 0 or line[0] == '#') continue;
        if (std.mem.count(u8, line, ":") != 2 or line.len > constants.account_line_bytes_max) {
            result.malformed_lines += 1;
            continue;
        }
        const first = std.mem.indexOfScalar(u8, line, ':').?;
        const last = std.mem.lastIndexOfScalar(u8, line, ':').?;
        const owner = line[0..first];
        const range_start = ref_u32(line[first + 1 .. last]);
        const range_count = ref_u32(line[last + 1 ..]);
        const valid = owner.len > 0 and owner.len <= constants.user_name_bytes_max and
            range_start != null and range_count != null and
            @as(u64, range_start.?) + range_count.? <= (1 << 32);
        if (!valid) {
            result.malformed_lines += 1;
            continue;
        }
        const by_name = name != null and std.mem.eql(u8, owner, name.?);
        const by_uid = std.mem.eql(u8, owner, uid_text);
        result.matched_by_name = result.matched_by_name or by_name;
        result.matched_by_uid = result.matched_by_uid or by_uid;
        if ((by_name or by_uid) and range_count.? > result.best_count) {
            result.best_count = range_count.?;
            result.best_start = range_start.?;
        }
    }
    return result;
}

fn ref_passwd(text: []const u8, uid: u32) parse.PasswdLookup {
    var result: parse.PasswdLookup = .{};
    var start: usize = 0;
    while (start <= text.len) {
        const end = std.mem.indexOfScalarPos(u8, text, start, '\n') orelse text.len;
        const line = text[start..end];
        start = end + 1;
        if (line.len == 0 or line[0] == '#') continue;
        if (!ref_passwd_line_ok(line)) {
            result.malformed_lines += 1;
            continue;
        }
        var fields = std.mem.splitScalar(u8, line, ':');
        const name = fields.next().?;
        _ = fields.next();
        const line_uid = ref_u32(fields.next().?).?;
        if (line_uid == uid and result.name == null) result.name = name;
    }
    return result;
}

fn ref_passwd_line_ok(line: []const u8) bool {
    if (line.len > constants.account_line_bytes_max) return false;
    if (std.mem.count(u8, line, ":") != 6) return false;
    var fields = std.mem.splitScalar(u8, line, ':');
    const name = fields.next().?;
    if (name.len == 0 or name.len > constants.user_name_bytes_max) return false;
    for (name) |byte| {
        if (byte <= 0x20 or byte >= 0x7f) return false;
    }
    _ = fields.next();
    return ref_u32(fields.next().?) != null and ref_u32(fields.next().?) != null;
}

fn ref_seccomp(text: []const u8) ?u32 {
    var found: ?u32 = null;
    var count: u32 = 0;
    var start: usize = 0;
    while (start <= text.len) {
        const end = std.mem.indexOfScalarPos(u8, text, start, '\n') orelse text.len;
        const line = text[start..end];
        start = end + 1;
        if (!std.mem.startsWith(u8, line, "Seccomp:")) continue;
        count += 1;
        const rest = line["Seccomp:".len..];
        const trimmed = std.mem.trimStart(u8, rest, " \t");
        const gap = rest.len - trimmed.len;
        if (gap == 0 or trimmed.len != 1) return null;
        if (trimmed[0] < '0' or trimmed[0] > '2') return null;
        found = trimmed[0] - '0';
    }
    if (count != 1) return null;
    return found;
}

fn ref_capability(bytes: []const u8) ?parse.CapabilityBits {
    if (bytes.len < 4) return null;
    const revision = bytes[3];
    const size: usize = switch (revision) {
        1 => 12,
        2 => 20,
        3 => 24,
        else => return null,
    };
    if (bytes.len != size) return null;
    const permitted = bytes[4];
    return .{
        .setuid = permitted & 0x80 != 0,
        .setgid = permitted & 0x40 != 0,
        .effective = bytes[0] & 1 == 1,
        .root_id = if (revision == 3) std.mem.readInt(u32, bytes[20..24], .little) else 0,
    };
}

/// Unwraps a parser result that the reference says must be accepted.
fn must(result: anytype) @typeInfo(@TypeOf(result)).error_union.payload {
    return result catch |err| {
        std.debug.panic("parser rejected an input the reference accepts: {s}", .{@errorName(err)});
    };
}

// ---- Fuzzers -------------------------------------------------------------------------------

const sysctl_samples = [_][]const u8{
    "0\n", "1\n", "15000\n", "63488", "4294967295\n", "007\n", "-1\n",
};
const kernel_samples = [_][]const u8{
    "6.8.0-45-generic", "6.18.44-fc-v153",       "5.15.0",         "5.4.0+",
    "5.15-rc1",         "6.8.5-301.fc40.x86_64", "4.19.0-9-amd64", "5.15.0.1",
};
const controller_samples = [_][]const u8{
    "cpuset cpu io memory hugetlb pids rdma misc\n", "cpu memory pids\n", "\n",
    "cpu future\n",                                  "pids pids\n",
};
const subid_samples = [_][]const u8{
    "alice:100000:65536\n",     "1000:200000:1000\n",       "# comment\n", "bob:1:2:3\n",
    "alice:4294901760:65536\n", "alice:4294901760:65537\n", "\n",          ":1:2\n",
};
const passwd_samples = [_][]const u8{
    "root:x:0:0:root:/root:/bin/bash\n", "alice:x:1000:1000:Alice,,,:/home/alice:/bin/bash\n",
    "broken:x:1000\n",                   "bad name:x:5:5::/h:/bin/sh\n",
    "n:x:1:1::/h:/bin/sh",
};
const seccomp_samples = [_][]const u8{
    "Name:\tzbx\nSeccomp:\t2\nSeccomp_filters:\t1\n", "Seccomp:\t0\n",
    "Seccomp: 1",                                     "Seccomp:\t3\n",
    "Seccomp:\t2\nSeccomp:\t2\n",                     "Seccomp_filters:\t1\n",
};

pub fn fuzz_parse_sysctl(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    var buffer: [input_bytes_max]u8 = undefined;
    const input = make_input(prng.random(), &sysctl_samples, &buffer);
    const got = parse.parse_sysctl_uint(input);
    if (ref_sysctl(input)) |expected| {
        assert(must(got) == expected);
    } else {
        assert(std.meta.isError(got));
    }
}

pub fn fuzz_parse_kernel(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    var buffer: [input_bytes_max]u8 = undefined;
    const input = make_input(prng.random(), &kernel_samples, &buffer);
    const got = parse.parse_kernel_release(input);
    if (ref_kernel(input)) |expected| {
        assert(std.meta.eql(must(got), expected));
    } else {
        assert(std.meta.isError(got));
    }
}

pub fn fuzz_parse_controllers(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    var buffer: [input_bytes_max]u8 = undefined;
    const input = make_input(prng.random(), &controller_samples, &buffer);
    const got = parse.parse_controller_list(input);
    if (ref_controllers(input)) |expected| {
        const value = must(got);
        assert(value.bits == expected.bits);
        assert(value.unknown == expected.unknown);
    } else {
        assert(std.meta.isError(got));
    }
}

pub fn fuzz_parse_subid(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();
    var buffer: [input_bytes_max]u8 = undefined;
    const input = make_input(random, &subid_samples, &buffer);
    const names = [_]?[]const u8{ "alice", "bob", null, "1000", "" };
    const name = names[random.uintLessThan(usize, names.len)];
    const uid = random.uintLessThan(u32, 1002);
    const got = parse.parse_subid(input, name, uid);
    const expected = ref_subid(input, name, uid);
    assert(std.meta.eql(got, expected));
    // Negative space: a range is never reported unless a line matched the user.
    if (got.best_count > 0) {
        const matched = got.matched_by_name or got.matched_by_uid;
        assert(matched);
    }
}

pub fn fuzz_parse_passwd(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();
    var buffer: [input_bytes_max]u8 = undefined;
    const input = make_input(random, &passwd_samples, &buffer);
    const uid = random.uintLessThan(u32, 1002);
    const got = parse.parse_passwd_name(input, uid);
    const expected = ref_passwd(input, uid);
    assert(got.malformed_lines == expected.malformed_lines);
    assert((got.name == null) == (expected.name == null));
    if (expected.name) |name| assert(std.mem.eql(u8, got.name.?, name));
}

pub fn fuzz_parse_seccomp(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    var buffer: [input_bytes_max]u8 = undefined;
    const input = make_input(prng.random(), &seccomp_samples, &buffer);
    const got = parse.parse_seccomp_status(input);
    if (ref_seccomp(input)) |expected| {
        assert(must(got) == expected);
    } else {
        assert(std.meta.isError(got));
    }
}

pub fn fuzz_parse_capability(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();
    var bytes: [32]u8 = undefined;
    random.bytes(&bytes);
    // Bias the revision byte and the length towards the valid layouts, where bugs hide.
    bytes[3] = if (random.boolean()) random.intRangeAtMost(u8, 0, 4) else bytes[3];
    const sizes = [_]usize{ 0, 3, 4, 11, 12, 13, 19, 20, 21, 23, 24, 25, 32 };
    const length = if (random.boolean())
        sizes[random.uintLessThan(usize, sizes.len)]
    else
        random.uintAtMost(usize, 32);
    const input = bytes[0..length];
    const got = parse.decode_capability(input);
    if (ref_capability(input)) |expected| {
        assert(std.meta.eql(must(got), expected));
    } else {
        assert(std.meta.isError(got));
    }
}
