//! Every limit in Zigbox lives here, named with its unit last, with comptime assertions on how
//! the limits relate. Exceeding a limit at run time is an operating error with a one-line
//! message, never undefined behaviour (docs/STYLE.md, "Put a limit on everything").

const std = @import("std");
const assert = std.debug.assert;

// Exit codes. These are part of the CLI contract and of the demo scripts.
pub const exit_ok: u8 = 0;
pub const exit_failed: u8 = 1;
pub const exit_usage: u8 = 2;

// Command line.
/// Arguments after the program name. Far above anything a milestone needs; a bound, not a goal.
pub const args_count_max: u32 = 64;
/// One argument. Longer arguments are refused rather than truncated, so a command is never
/// silently misread.
pub const arg_bytes_max: u32 = 4096;
/// How much of a refused argument is echoed back in an error line.
pub const arg_echo_bytes_max: u32 = 64;
/// One rendered CLI message (help text, version, or an error line).
pub const output_bytes_max: u32 = 4096;

// Host interface.
/// Linux PATH_MAX, without the terminating NUL.
pub const path_bytes_max: u32 = 4095;
/// Largest single file read through the host: bounds every /proc, /sys and /etc read.
pub const file_bytes_max: u32 = 64 * 1024;
/// Consecutive EINTR results tolerated for one operation before it is reported as failed.
pub const eintr_retries_max: u32 = 16;
/// Upper bound on read calls for one file. Every call that is not EOF makes progress of at least
/// one byte, so this covers the worst case of one-byte short reads plus the final EOF probe.
pub const read_calls_max: u32 = file_bytes_max + 1;
/// Upper bound on write calls for one message, by the same argument.
pub const write_calls_max: u32 = output_bytes_max + 1;
/// Size of a utsname field in the kernel ABI, including the terminating NUL.
pub const uname_field_bytes: u32 = 65;

// Host simulator.
pub const sim_files_max: u32 = 64;
pub const sim_open_files_max: u32 = 8;
pub const sim_output_bytes_max: u32 = 16 * 1024;

// Doctor policy, used from slice 2 on and kept here so every limit has one home.
/// Overlayfs mounts inside user namespaces need 5.11; 5.15 is the oldest LTS kernel that has it
/// and is still widely deployed. The oldest kernel the project supports.
pub const kernel_major_min: u32 = 5;
pub const kernel_minor_min: u32 = 15;
/// A full container uid/gid map needs 65536 ids.
pub const subid_range_min: u32 = 65536;
pub const probe_timeout_ms: u32 = 5000;

// Fuzz runner.
pub const fuzz_iterations_default: u32 = 10_000;
pub const fuzz_iterations_max: u32 = 100_000_000;

comptime {
    assert(exit_ok != exit_failed);
    assert(exit_failed != exit_usage);
    assert(exit_ok != exit_usage);

    assert(args_count_max > 0);
    assert(arg_echo_bytes_max >= 8); // Room for a truncation marker and some text.
    assert(arg_echo_bytes_max < arg_bytes_max);
    assert(arg_bytes_max <= path_bytes_max + 1);
    // An error line echoes an argument, so the message buffer must hold prose plus the echo.
    assert(output_bytes_max >= 2 * arg_echo_bytes_max + 256);

    assert(path_bytes_max > 0);
    assert(path_bytes_max < std.math.maxInt(u16));
    assert(file_bytes_max > 0);
    assert(file_bytes_max <= std.math.maxInt(u32) / 2); // Offsets and lengths fit in u32.
    assert(read_calls_max > file_bytes_max);
    assert(write_calls_max > output_bytes_max);
    assert(eintr_retries_max > 0);
    assert(uname_field_bytes <= std.math.maxInt(u8));

    assert(sim_files_max > 0);
    assert(sim_open_files_max > 0);
    assert(sim_output_bytes_max >= 2 * output_bytes_max);

    assert(kernel_major_min >= 5);
    assert(kernel_minor_min < 1000);
    assert(subid_range_min == 65536);
    assert(probe_timeout_ms > 0);

    assert(fuzz_iterations_default > 0);
    assert(fuzz_iterations_default <= fuzz_iterations_max);
}
