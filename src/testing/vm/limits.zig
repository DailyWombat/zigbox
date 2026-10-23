//! Every limit of the VM harness, with its unit last, and comptime checks on how they relate.
//! The harness is test tooling, but docs/STYLE.md still asks for a bound on everything.

const std = @import("std");
const assert = std.debug.assert;

/// Everything the guest console prints is kept (and echoed to our stdout). A full boot plus
/// provisioning is well under a megabyte; the rest is headroom for a failure's own noise.
pub const console_bytes_max: u32 = 16 * 1024 * 1024;
/// The output of one guest command.
pub const command_output_bytes_max: u32 = 64 * 1024;
pub const command_bytes_max: u32 = 1024;
pub const http_connections_max: u32 = 4;
pub const http_request_bytes_max: u32 = 8 * 1024;
pub const http_routes_max: u32 = 8;
/// One served file. The release binaries are under 2 MiB (the milestone limit itself).
pub const http_body_bytes_max: u32 = 4 * 1024 * 1024;
/// Size of a binary the harness reads to inspect its ELF headers.
pub const elf_bytes_max: u32 = 4 * 1024 * 1024;
pub const program_headers_max: u32 = 64;
pub const dynamic_entries_max: u32 = 256;
pub const poll_step_ms: u32 = 200;

/// Seconds. The guest runs about this many times slower under TCG than under KVM.
pub const tcg_timeout_factor: u32 = 8;
pub const boot_timeout_kvm_s: u32 = 300;
pub const command_timeout_kvm_s: u32 = 60;
pub const shutdown_timeout_s: u32 = 60;
pub const download_chunk_bytes: u32 = 64 * 1024;
pub const overlay_size_text = "8G";
pub const guest_memory_mib: u32 = 2048;
pub const guest_cpus: u32 = 2;

/// The release size limit from the milestone: a static binary under 2 MiB.
pub const binary_bytes_max: u64 = 2 * 1024 * 1024;

comptime {
    assert(console_bytes_max >= 1024 * 1024);
    assert(command_output_bytes_max < console_bytes_max);
    assert(command_bytes_max < 4096); // The tty line discipline truncates longer lines.
    assert(http_body_bytes_max > binary_bytes_max);
    assert(elf_bytes_max >= binary_bytes_max);
    assert(poll_step_ms > 0);
    assert(tcg_timeout_factor >= 1);
    assert(boot_timeout_kvm_s * tcg_timeout_factor < 24 * 60 * 60);
    assert(guest_memory_mib >= 1024);
    assert(http_connections_max >= 2); // cloud-init may fetch two files at once.
}
