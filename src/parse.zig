//! Pure parsers for the kernel and system files `zbx doctor` reads. Every parser takes a byte
//! slice and returns a well-formed value or an error: no host access, no allocation, no
//! assumptions about encoding or NUL bytes.
//!
//! Strictness: each parser accepts exactly the canonical form the kernel or the tools produce
//! (digits without sign or leading zeros, one newline terminator, ...). Anything else is an
//! error, because a lenient reading could make a broken host look healthy. The fuzzers compare
//! every parser with an independent reference reading of the same rules.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");

pub const Error = error{
    Empty,
    Malformed,
    TooLong,
    TooMany,
    Duplicate,
    Missing,
    Overflow,
    Unsupported,
};

// ---- Byte classes --------------------------------------------------------------------------

fn is_digit(byte: u8) bool {
    if (byte < '0') return false;
    return byte <= '9';
}

/// Printable ASCII without space: what user names and release suffixes are made of.
fn is_visible(byte: u8) bool {
    if (byte < 0x21) return false;
    return byte <= 0x7e;
}

fn is_blank(byte: u8) bool {
    if (byte == ' ') return true;
    return byte == '\t';
}

/// A cgroup v2 controller name: lowercase letters, digits and underscore.
fn is_controller_name_byte(byte: u8) bool {
    if (byte >= 'a') {
        if (byte <= 'z') return true;
    }
    if (byte == '_') return true;
    return is_digit(byte);
}

/// Blank lines and `#` comments carry no entry.
fn is_skipped_line(line: []const u8) bool {
    if (line.len == 0) return true;
    return line[0] == '#';
}

// ---- Numbers -----------------------------------------------------------------------------

/// Parses canonical decimal digits: no sign, no spaces, no leading zero unless the number is
/// exactly "0", at most `digits_max` digits.
fn parse_decimal(digits: []const u8, digits_max: u32) Error!u64 {
    assert(digits_max <= 19); // Always fits u64.
    if (digits.len == 0) return error.Empty;
    if (digits.len > digits_max) return error.TooLong;
    if (digits.len > 1) {
        if (digits[0] == '0') return error.Malformed;
    }
    var value: u64 = 0;
    for (digits) |byte| {
        if (!is_digit(byte)) return error.Malformed;
        value = value * 10 + (byte - '0');
    }
    if (digits.len == 1) assert(value < 10);
    if (digits[0] == '0') assert(digits.len == 1);
    return value;
}

fn parse_u32(digits: []const u8) Error!u32 {
    const value = try parse_decimal(digits, 10);
    assert(digits.len > 0); // An empty string is an error above, never zero.
    assert(digits.len <= 10);
    if (value > std.math.maxInt(u32)) return error.Overflow;
    return @intCast(value);
}

/// A sysctl integer file: decimal digits and at most one trailing newline.
pub fn parse_sysctl_uint(text: []const u8) Error!u32 {
    const body = if (std.mem.endsWith(u8, text, "\n")) text[0 .. text.len - 1] else text;
    assert(body.len <= text.len);
    const value = try parse_u32(body);
    // Canonical numbers have no leading zeros, so two or more digits mean at least ten.
    if (body.len > 1) assert(value >= 10);
    return value;
}

// ---- Kernel release ------------------------------------------------------------------------

pub const KernelVersion = struct {
    major: u32,
    minor: u32,
    patch: u32,
};

/// `MAJOR.MINOR[.PATCH][SUFFIX]` where SUFFIX starts with '-', '+', '_' or '~' and continues
/// with printable ASCII. Examples: "6.8.0-45-generic", "6.18.44-fc-v153", "5.15.0", "5.4.0+".
pub fn parse_kernel_release(text: []const u8) Error!KernelVersion {
    if (text.len == 0) return error.Empty;
    if (text.len >= constants.uname_field_bytes) return error.TooLong;
    var index: usize = 0;
    const major = try read_number(text, &index);
    if (index >= text.len) return error.Malformed;
    if (text[index] != '.') return error.Malformed;
    index += 1;
    const minor = try read_number(text, &index);
    var patch: u32 = 0;
    if (index < text.len) {
        if (text[index] == '.') {
            index += 1;
            patch = try read_number(text, &index);
        }
    }
    if (index < text.len) try check_release_suffix(text[index..]);
    assert(index <= text.len);
    assert(major <= 999_999_999); // At most nine digits.
    return .{ .major = major, .minor = minor, .patch = patch };
}

/// Reads one canonical number at `index` and advances past it.
fn read_number(text: []const u8, index: *usize) Error!u32 {
    assert(index.* <= text.len);
    const start = index.*;
    var end = start;
    while (end < text.len) : (end += 1) {
        if (!is_digit(text[end])) break;
    }
    index.* = end;
    const value = try parse_decimal(text[start..end], constants.kernel_number_digits_max);
    assert(end > start); // An empty run is an error above, never a number.
    return @intCast(value);
}

fn check_release_suffix(suffix: []const u8) Error!void {
    assert(suffix.len > 0);
    assert(suffix.len < constants.uname_field_bytes);
    const starts = "-+_~";
    if (std.mem.indexOfScalar(u8, starts, suffix[0]) == null) return error.Malformed;
    for (suffix) |byte| {
        if (!is_visible(byte)) return error.Malformed;
    }
}

// ---- cgroup controllers --------------------------------------------------------------------

pub const Controller = enum(u4) { cpuset, cpu, io, memory, hugetlb, pids, rdma, misc };

pub const ControllerSet = struct {
    bits: u16 = 0,
    /// Names that are well formed but not in `Controller`.
    unknown: u32 = 0,

    pub fn has(set: ControllerSet, controller: Controller) bool {
        return set.bits & (@as(u16, 1) << @backingInt(controller)) != 0;
    }

    pub fn is_empty(set: ControllerSet) bool {
        if (set.bits != 0) return false;
        return set.unknown == 0;
    }

    fn add(set: *ControllerSet, controller: Controller) Error!void {
        if (set.has(controller)) return error.Duplicate;
        set.bits |= @as(u16, 1) << @backingInt(controller);
        assert(set.has(controller));
        assert(set.bits != 0);
    }
};

/// `cgroup.controllers` and `cgroup.subtree_control`: space-separated lowercase names and a
/// newline. An empty list is valid.
pub fn parse_controller_list(text: []const u8) Error!ControllerSet {
    if (text.len > constants.cgroup_list_bytes_max) return error.TooLong;
    const body = if (std.mem.endsWith(u8, text, "\n")) text[0 .. text.len - 1] else text;
    var set: ControllerSet = .{};
    if (body.len == 0) return set;
    var words = std.mem.splitScalar(u8, body, ' ');
    var count: u32 = 0;
    while (words.next()) |word| {
        count += 1;
        if (count > constants.controllers_count_max) return error.TooMany;
        if (word.len == 0) return error.Malformed;
        if (word.len > constants.controller_name_bytes_max) return error.TooLong;
        for (word) |byte| {
            if (!is_controller_name_byte(byte)) return error.Malformed;
        }
        if (std.meta.stringToEnum(Controller, word)) |controller| {
            try set.add(controller);
        } else {
            set.unknown += 1;
        }
    }
    // Every word was counted exactly once, as known or unknown.
    assert(@popCount(set.bits) + set.unknown == count);
    assert(count <= constants.controllers_count_max);
    return set;
}

// ---- Accounts ------------------------------------------------------------------------------

pub const SubidRanges = struct {
    /// The largest single range of any matching entry; 0 if none.
    best_count: u32 = 0,
    best_start: u32 = 0,
    matched_by_name: bool = false,
    matched_by_uid: bool = false,
    /// Lines that were neither comments nor well-formed entries; never counted as matches.
    malformed_lines: u32 = 0,
};

/// `/etc/subuid` or `/etc/subgid`: `NAME_OR_UID:START:COUNT` lines. An entry matches the user
/// by name or by the decimal UID; both forms are legal and both are checked.
pub fn parse_subid(text: []const u8, user_name: ?[]const u8, uid: u32) SubidRanges {
    assert(uid != std.math.maxInt(u32)); // (uid_t)-1 is never a real owner.
    var uid_buffer: [10]u8 = undefined;
    const uid_text = std.fmt.bufPrint(&uid_buffer, "{d}", .{uid}) catch unreachable; // 10 fits.
    var result: SubidRanges = .{};
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (is_skipped_line(line)) continue;
        const entry = parse_subid_line(line) orelse {
            result.malformed_lines += 1;
            continue;
        };
        const by_name = if (user_name) |name| std.mem.eql(u8, entry.owner, name) else false;
        const by_uid = std.mem.eql(u8, entry.owner, uid_text);
        if (!by_name) {
            if (!by_uid) continue;
        }
        result.matched_by_name = result.matched_by_name or by_name;
        result.matched_by_uid = result.matched_by_uid or by_uid;
        if (entry.count > result.best_count) {
            result.best_count = entry.count;
            result.best_start = entry.start;
        }
    }
    if (result.best_count > 0) {
        const matched = result.matched_by_name or result.matched_by_uid;
        assert(matched); // A range is only ever reported for a matching line.
    }
    assert(text.len <= constants.file_bytes_max);
    return result;
}

const SubidLine = struct { owner: []const u8, start: u32, count: u32 };

fn parse_subid_line(line: []const u8) ?SubidLine {
    if (line.len > constants.account_line_bytes_max) return null;
    var fields = std.mem.splitScalar(u8, line, ':');
    const owner = fields.next() orelse return null;
    const start_text = fields.next() orelse return null;
    const count_text = fields.next() orelse return null;
    if (fields.next() != null) return null;
    if (owner.len == 0) return null;
    if (owner.len > constants.user_name_bytes_max) return null;
    const start = parse_u32(start_text) catch return null;
    const count = parse_u32(count_text) catch return null;
    // The range must fit the 32-bit id space.
    if (@as(u64, start) + count > (1 << 32)) return null;
    assert(owner.len > 0);
    assert(std.mem.indexOfScalar(u8, owner, ':') == null); // Fields were split on colons.
    return .{ .owner = owner, .start = start, .count = count };
}

pub const PasswdLookup = struct {
    name: ?[]const u8 = null,
    malformed_lines: u32 = 0,
};

/// `/etc/passwd`: `NAME:PASSWORD:UID:GID:GECOS:HOME:SHELL`. Returns the name of the first
/// well-formed entry with this UID.
pub fn parse_passwd_name(text: []const u8, uid: u32) PasswdLookup {
    assert(uid != std.math.maxInt(u32)); // (uid_t)-1 is never a real owner.
    var result: PasswdLookup = .{};
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (is_skipped_line(line)) continue;
        const entry = parse_passwd_line(line) orelse {
            result.malformed_lines += 1;
            continue;
        };
        if (entry.uid != uid) continue;
        if (result.name == null) result.name = entry.name;
    }
    if (result.name) |name| assert(name.len > 0);
    assert(text.len <= constants.file_bytes_max);
    return result;
}

const PasswdLine = struct { name: []const u8, uid: u32 };

fn parse_passwd_line(line: []const u8) ?PasswdLine {
    if (line.len > constants.account_line_bytes_max) return null;
    var fields = std.mem.splitScalar(u8, line, ':');
    var values: [7][]const u8 = undefined;
    for (&values) |*value| value.* = fields.next() orelse return null;
    if (fields.next() != null) return null;
    const name = values[0];
    if (name.len == 0) return null;
    if (name.len > constants.user_name_bytes_max) return null;
    for (name) |byte| {
        if (!is_visible(byte)) return null;
    }
    const uid = parse_u32(values[2]) catch return null;
    _ = parse_u32(values[3]) catch return null;
    assert(name.len > 0);
    assert(std.mem.indexOfScalar(u8, name, ':') == null); // Fields were split on colons.
    return .{ .name = name, .uid = uid };
}

// ---- /proc/self/status ---------------------------------------------------------------------

/// The value of the `Seccomp:` line: 0 (disabled), 1 (strict) or 2 (filter). The line must
/// appear exactly once as `Seccomp:` then spaces or tabs then a single digit.
pub fn parse_seccomp_status(text: []const u8) Error!u32 {
    assert(text.len <= constants.status_bytes_max); // Bounded by the read that produced it.
    const key = "Seccomp:";
    var found: ?u32 = null;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, key)) continue;
        if (found != null) return error.Duplicate;
        found = try parse_seccomp_value(line[key.len..]);
    }
    const mode = found orelse return error.Missing;
    assert(mode <= 2); // The kernel's modes: disabled, strict, filter.
    return mode;
}

fn parse_seccomp_value(rest: []const u8) Error!u32 {
    var index: usize = 0;
    while (index < rest.len) : (index += 1) {
        if (!is_blank(rest[index])) break;
    }
    assert(index <= rest.len);
    if (index == 0) return error.Malformed;
    if (rest.len - index != 1) return error.Malformed;
    const digit = rest[index];
    if (digit < '0') return error.Malformed;
    if (digit > '2') return error.Malformed;
    assert(is_digit(digit));
    return digit - '0';
}

// ---- File capabilities ---------------------------------------------------------------------

pub const CapabilityBits = struct {
    /// CAP_SETUID and CAP_SETGID in the permitted set.
    setuid: bool,
    setgid: bool,
    /// The effective flag: capabilities are raised at exec without the program asking.
    effective: bool,
    /// Revision 3 only: the capabilities apply only inside the user namespace of this root
    /// id. Nonzero means they do not apply on the host.
    root_id: u32,
};

const cap_setgid_bit: u5 = 6;
const cap_setuid_bit: u5 = 7;

/// Decodes `struct vfs_cap_data` (linux/capability.h): a little-endian magic word whose top
/// byte is the revision, then permitted/inheritable pairs per 32 capabilities, then (revision
/// 3) the root id. Only the first word of the permitted set is needed here.
pub fn decode_capability(bytes: []const u8) Error!CapabilityBits {
    if (bytes.len < 4) return error.Malformed;
    const magic = std.mem.readInt(u32, bytes[0..4], .little);
    const revision = magic & 0xff00_0000;
    const expected: usize = switch (revision) {
        0x0100_0000 => 12,
        0x0200_0000 => 20,
        0x0300_0000 => 24,
        else => return error.Unsupported,
    };
    if (bytes.len != expected) return error.Malformed;
    assert(bytes.len >= 12); // Every revision carries at least one permitted/inheritable pair.
    const permitted = std.mem.readInt(u32, bytes[4..8], .little);
    var root_id: u32 = 0;
    if (revision == 0x0300_0000) root_id = std.mem.readInt(u32, bytes[20..24], .little);
    if (revision != 0x0300_0000) assert(root_id == 0); // Only revision 3 has a root id.
    return .{
        .setuid = (permitted >> cap_setuid_bit) & 1 == 1,
        .setgid = (permitted >> cap_setgid_bit) & 1 == 1,
        .effective = magic & 1 == 1,
        .root_id = root_id,
    };
}

// ---- Tests ---------------------------------------------------------------------------------

const testing = std.testing;
const repeat = @import("test_util.zig").repeat;

test "sysctl integers: canonical forms pass, everything else is an error" {
    // Goal: the boundary between canonical and not, including u32 overflow.
    try testing.expectEqual(@as(u32, 0), try parse_sysctl_uint("0\n"));
    try testing.expectEqual(@as(u32, 15000), try parse_sysctl_uint("15000"));
    try testing.expectEqual(@as(u32, 4294967295), try parse_sysctl_uint("4294967295\n"));
    try testing.expectError(error.Overflow, parse_sysctl_uint("4294967296\n"));
    try testing.expectError(error.TooLong, parse_sysctl_uint("12345678901\n"));
    try testing.expectError(error.Empty, parse_sysctl_uint(""));
    try testing.expectError(error.Empty, parse_sysctl_uint("\n"));
    try testing.expectError(error.Malformed, parse_sysctl_uint("007\n"));
    try testing.expectError(error.Malformed, parse_sysctl_uint("-1\n"));
    try testing.expectError(error.Malformed, parse_sysctl_uint("+1\n"));
    try testing.expectError(error.Malformed, parse_sysctl_uint(" 1\n"));
    try testing.expectError(error.Malformed, parse_sysctl_uint("1\n\n"));
    try testing.expectError(error.Malformed, parse_sysctl_uint("1\x00\n"));
}

test "kernel release: real strings parse, malformed ones do not" {
    // Goal: the strings seen in the wild, and the neighbours that must be refused.
    const ubuntu = try parse_kernel_release("6.8.0-45-generic");
    try testing.expectEqual(KernelVersion{ .major = 6, .minor = 8, .patch = 0 }, ubuntu);
    const firecracker = try parse_kernel_release("6.18.44-fc-v153");
    try testing.expectEqual(KernelVersion{ .major = 6, .minor = 18, .patch = 44 }, firecracker);
    const plain = try parse_kernel_release("5.15.0");
    try testing.expectEqual(KernelVersion{ .major = 5, .minor = 15, .patch = 0 }, plain);
    const plus = try parse_kernel_release("5.4.0+");
    try testing.expectEqual(@as(u32, 4), plus.minor);
    const no_patch = try parse_kernel_release("5.15-rc1");
    try testing.expectEqual(KernelVersion{ .major = 5, .minor = 15, .patch = 0 }, no_patch);

    const bad = [_][]const u8{
        "",               "5",       "5.",          "5.15.",    ".5.15",   "5..15",
        "05.15.0",        "5.015.0", "5.15.00",     "5.15.0.1", "5.15.0 ", " 5.15.0",
        "5.15.0\n",       "a.b.c",   "5.15.0-\x00", "5.15.0x",  "5.15 .0", "-5.15.0",
        "5.15.0-é",
        "1234567890.1.1",
    };
    for (bad) |text| try testing.expect(std.meta.isError(parse_kernel_release(text)));
    try testing.expectError(error.TooLong, parse_kernel_release(repeat('1', 65)));
}

test "controller lists: sets, empty lists, duplicates and junk" {
    // Goal: delegated controllers are read exactly; unknown names are counted, not trusted.
    const full = try parse_controller_list("cpuset cpu io memory hugetlb pids rdma misc\n");
    for (std.enums.values(Controller)) |controller| try testing.expect(full.has(controller));
    const some = try parse_controller_list("cpu memory pids\n");
    try testing.expect(some.has(.cpu) and some.has(.memory) and some.has(.pids));
    try testing.expect(!some.has(.io));
    const empty = try parse_controller_list("\n");
    try testing.expectEqual(@as(u16, 0), empty.bits);
    try testing.expectEqual(@as(u16, 0), (try parse_controller_list("")).bits);
    const unknown = try parse_controller_list("cpu future_thing\n");
    try testing.expectEqual(@as(u32, 1), unknown.unknown);

    const bad = [_][]const u8{
        "cpu  memory\n", "cpu \n",  " cpu\n",    "CPU\n", "cpu cpu\n", "cpu\tmemory\n",
        "cpu\nmemory\n", "cpu-x\n", "cpu\x00\n",
    };
    for (bad) |text| try testing.expect(std.meta.isError(parse_controller_list(text)));
    try testing.expectError(error.TooLong, parse_controller_list(repeat('a', 33)));
}

test "subid: match by name, by uid, by both; malformed lines never count" {
    // Goal: both legal forms are honoured; the largest range wins; bad lines are counted and
    // ignored; ids that overflow the 32-bit space are not a range.
    const text =
        \\# a comment
        \\alice:100000:65536
        \\1000:200000:1000
        \\bob:300000:65536
        \\
        \\alice:oops:65536
        \\alice:100000
        \\alice:100000:65536:1
        \\alice:4294967295:2
        \\:1:2
        \\
    ;
    const by_both = parse_subid(text, "alice", 1000);
    try testing.expectEqual(@as(u32, 65536), by_both.best_count);
    try testing.expectEqual(@as(u32, 100000), by_both.best_start);
    try testing.expect(by_both.matched_by_name and by_both.matched_by_uid);
    try testing.expectEqual(@as(u32, 5), by_both.malformed_lines);

    const by_uid_only = parse_subid(text, null, 1000);
    try testing.expectEqual(@as(u32, 1000), by_uid_only.best_count);
    try testing.expect(!by_uid_only.matched_by_name and by_uid_only.matched_by_uid);

    const nobody = parse_subid(text, "carol", 4242);
    try testing.expectEqual(@as(u32, 0), nobody.best_count);
    try testing.expect(!nobody.matched_by_name and !nobody.matched_by_uid);

    const edge = parse_subid("a:4294901760:65536\n", "a", 1);
    try testing.expectEqual(@as(u32, 65536), edge.best_count);
    const over = parse_subid("a:4294901760:65537\n", "a", 1);
    try testing.expectEqual(@as(u32, 0), over.best_count);
    try testing.expectEqual(@as(u32, 1), over.malformed_lines);
}

test "passwd: the uid maps to a name; malformed lines are skipped" {
    // Goal: lookup by UID, first match wins, no partial lines.
    const text =
        \\root:x:0:0:root:/root:/bin/bash
        \\broken:x:1000
        \\alice:x:1000:1000:Alice,,,:/home/alice:/bin/bash
        \\alice2:x:1000:1000::/home/a2:/bin/sh
        \\bad name:x:1001:1001::/h:/bin/sh
        \\nonumeric:x:abc:1::/h:/bin/sh
        \\
    ;
    const found = parse_passwd_name(text, 1000);
    try testing.expectEqualStrings("alice", found.name.?);
    try testing.expectEqual(@as(u32, 3), found.malformed_lines);
    try testing.expectEqualStrings("root", parse_passwd_name(text, 0).name.?);
    try testing.expect(parse_passwd_name(text, 1001).name == null);
    try testing.expect(parse_passwd_name("", 0).name == null);
}

test "seccomp status line: values, absence, duplicates and look-alikes" {
    // Goal: only the exact `Seccomp:` key counts, with a single digit 0..2.
    const real = "Name:\tx\nSeccomp:\t2\nSeccomp_filters:\t1\n";
    try testing.expectEqual(@as(u32, 2), try parse_seccomp_status(real));
    try testing.expectEqual(@as(u32, 0), try parse_seccomp_status("Seccomp:\t0\n"));
    try testing.expectEqual(@as(u32, 1), try parse_seccomp_status("Seccomp: 1"));
    try testing.expectError(error.Missing, parse_seccomp_status("Seccomp_filters:\t1\n"));
    try testing.expectError(error.Missing, parse_seccomp_status(""));
    try testing.expectError(error.Malformed, parse_seccomp_status("Seccomp:\t3\n"));
    try testing.expectError(error.Malformed, parse_seccomp_status("Seccomp:\t10\n"));
    try testing.expectError(error.Malformed, parse_seccomp_status("Seccomp:2\n"));
    try testing.expectError(error.Malformed, parse_seccomp_status("Seccomp:\t\n"));
    try testing.expectError(error.Malformed, parse_seccomp_status("Seccomp:\t2 \n"));
    try testing.expectError(error.Duplicate, parse_seccomp_status("Seccomp:\t0\nSeccomp:\t0\n"));
    try testing.expectError(error.Missing, parse_seccomp_status(" Seccomp:\t2\n"));
}

/// Builds a capability xattr of the given revision in a 24-byte array; `size` is the used part.
fn capability_bytes(revision: u8, effective: bool, permitted: u8, root_id: u32) [24]u8 {
    var bytes: [24]u8 = @splat(0);
    bytes[0] = @intFromBool(effective);
    bytes[3] = revision;
    bytes[4] = permitted;
    std.mem.writeInt(u32, bytes[20..24], root_id, .little);
    return bytes;
}

test "capability xattr: revisions, bits and malformed sizes" {
    // Goal: decode exactly the documented layouts and refuse the rest.
    const rev2 = capability_bytes(2, true, 0x80, 0);
    const set_u = try decode_capability(rev2[0..20]);
    try testing.expect(set_u.setuid and !set_u.setgid and set_u.effective);
    try testing.expectEqual(@as(u32, 0), set_u.root_id);

    const rev1 = capability_bytes(1, false, 0xc0, 0);
    const both = try decode_capability(rev1[0..12]);
    try testing.expect(both.setuid and both.setgid and !both.effective);

    const rev3 = capability_bytes(3, true, 0xc0, 1000);
    const namespaced = try decode_capability(rev3[0..24]);
    try testing.expectEqual(@as(u32, 1000), namespaced.root_id);
    const rev3_host = capability_bytes(3, true, 0xc0, 0);
    try testing.expectEqual(@as(u32, 0), (try decode_capability(rev3_host[0..24])).root_id);

    const none = capability_bytes(2, false, 0x3f, 0);
    const neither = try decode_capability(none[0..20]);
    try testing.expect(!neither.setuid and !neither.setgid);

    try testing.expectError(error.Malformed, decode_capability(""));
    try testing.expectError(error.Malformed, decode_capability(rev2[0..3]));
    try testing.expectError(error.Malformed, decode_capability(rev2[0..19]));
    try testing.expectError(error.Malformed, decode_capability(rev2[0..21]));
    try testing.expectError(error.Malformed, decode_capability(rev1[0..20]));
    const rev4 = capability_bytes(4, false, 0, 0);
    try testing.expectError(error.Unsupported, decode_capability(rev4[0..24]));
    const rev0 = capability_bytes(0, false, 0, 0);
    try testing.expectError(error.Unsupported, decode_capability(rev0[0..12]));
}
