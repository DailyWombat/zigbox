//! zbx entry point. Deliberately thin: wire the real host to the CLI and exit with its code.
//! Uses `Init.Minimal` rather than `Init` so that no allocator or arena exists at all: the
//! "no allocation after startup" rule is then true by construction.

const std = @import("std");
const assert = std.debug.assert;
const cli = @import("cli.zig");
const constants = @import("constants.zig");
const HostReal = @import("host_real.zig").HostReal;

pub fn main(init: std.process.Init.Minimal) u8 {
    var real: HostReal = .{};
    var iterator = init.args.iterate();
    const code = cli.run_from_iterator(real.interface(), &iterator);
    assert(code <= constants.exit_usage);
    assert(real.open_count == 0); // Every file the CLI opened was closed.
    return code;
}

test {
    // Pull every module's tests into this test binary.
    _ = @import("constants.zig");
    _ = @import("host.zig");
    _ = @import("host_real.zig");
    _ = @import("host_sim.zig");
    _ = @import("cli.zig");
    _ = @import("parse.zig");
    _ = @import("text.zig");
    _ = @import("doctor.zig");
    _ = @import("doctor_fixtures.zig");
    _ = @import("test_util.zig");
}
