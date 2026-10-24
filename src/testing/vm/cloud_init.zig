//! The cloud-init NoCloud seed for the test VM, served over HTTP by the harness itself (no
//! genisoimage, no cloud-localds). Provisioning, in the order it happens:
//!   - user `demo` (uid 1000, no sudo, no password) with subuid/subgid 100000:65536;
//!   - `uidmap` installed (newuidmap/newgidmap, setuid root);
//!   - kernel.apparmor_restrict_unprivileged_userns=0 persisted: Ubuntu 24.04 ships it as 1,
//!     which refuses user namespaces to unconfined users, and doctor rightly reports that;
//!   - lingering enabled for demo, so the systemd user manager (user@1000.service) exists
//!     whatever way commands reach the guest;
//!   - a passwordless root shell on the serial console, which the harness drives. This VM is
//!     throwaway and has no other way in.
//! Nothing here sets Delegate=: the demo shows what stock Ubuntu delegates (see DEMO.md).

const std = @import("std");

pub const instance_id = "iid-zigbox-demo-m0";

pub const meta_data = "instance-id: " ++ instance_id ++ "\nlocal-hostname: zigbox-demo\n";

/// Printed on the console (by the last runcmd) when provisioning is complete.
pub const ready_marker = "ZBX-VM-PROVISIONED";

comptime {
    // The seed prints this marker itself; keep the two in step.
    std.debug.assert(std.mem.indexOf(u8, base(""), ready_marker) != null);
}

/// The systemd drop-in that delegates controllers to user managers. It is a prerequisite of
/// the demo only if stock Ubuntu does not delegate cpu, memory and pids already.
pub const delegate_dropin =
    \\  - path: /etc/systemd/system/user@.service.d/delegate.conf
    \\    content: |
    \\      [Service]
    \\      Delegate=cpu cpuset io memory pids
    \\
;

fn base(comptime dropin: []const u8) []const u8 {
    return
    \\#cloud-config
    \\users:
    \\  - name: demo
    \\    uid: 1000
    \\    shell: /bin/bash
    \\    lock_passwd: true
    \\ssh_pwauth: false
    \\package_update: true
    \\packages:
    \\  - uidmap
    \\write_files:
    \\  - path: /etc/sysctl.d/60-zigbox-userns.conf
    \\    content: |
    \\      # Host prerequisite of the Zigbox demo: Ubuntu 24.04 defaults this to 1, which refuses
    \\      # user namespaces to unconfined users. zbx doctor reports it when it is 1.
    \\      kernel.apparmor_restrict_unprivileged_userns = 0
    \\  - path: /etc/systemd/system/serial-getty@ttyS0.service.d/zigbox-autologin.conf
    \\    content: |
    \\      [Service]
    \\      ExecStart=
    \\      ExecStart=-/sbin/agetty --autologin root --noclear %I $TERM
    \\
    ++ dropin ++
        \\runcmd:
        \\  - sysctl --system
        \\  - grep -q '^demo:' /etc/subuid || echo 'demo:100000:65536' >> /etc/subuid
        \\  - grep -q '^demo:' /etc/subgid || echo 'demo:100000:65536' >> /etc/subgid
        \\  - loginctl enable-linger demo
        \\  - for i in $(seq 120); do systemctl is-active -q user@1000 && break; sleep 1; done
        \\  - systemctl daemon-reload
        \\  - echo ZBX-VM-PROVISIONED > /dev/console
        \\  - systemctl restart serial-getty@ttyS0.service
        \\
    ;
}

pub const user_data = base("");
pub const user_data_with_delegate = base(delegate_dropin);

test "user data is cloud-config, provisions the demo user, and sets no Delegate by default" {
    // Goal: the fixed facts the demo depends on are in the seed, and the stock-delegation
    // experiment is real: no Delegate= unless asked.
    try std.testing.expect(std.mem.startsWith(u8, user_data, "#cloud-config\n"));
    try std.testing.expect(std.mem.indexOf(u8, user_data, "uid: 1000") != null);
    try std.testing.expect(std.mem.indexOf(u8, user_data, "uidmap") != null);
    const sysctl = "apparmor_restrict_unprivileged_userns = 0";
    try std.testing.expect(std.mem.indexOf(u8, user_data, sysctl) != null);
    try std.testing.expect(std.mem.indexOf(u8, user_data, "enable-linger demo") != null);
    try std.testing.expect(std.mem.indexOf(u8, user_data, "Delegate=") == null);
    try std.testing.expect(std.mem.indexOf(u8, user_data_with_delegate, "Delegate=cpu") != null);
    try std.testing.expect(std.mem.indexOf(u8, user_data, ready_marker) != null);
    // YAML forbids tabs.
    try std.testing.expect(std.mem.indexOfScalar(u8, user_data, '\t') == null);
}
