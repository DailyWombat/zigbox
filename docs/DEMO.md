# M0 demo: `zbx doctor` on a real Ubuntu 24.04 host

`zig build demo-m0` boots a pinned Ubuntu 24.04 cloud image in QEMU, provisions it, and runs the
three steps of the milestone's demo script against the release binary. It is the only thing
that shows M0 works; unit tests, simulations and fuzzers never stand in for it.

## What it does

1. **Fresh VM.** As the unprivileged user `demo` (uid 1000), `zbx doctor` prints six `ok` lines
   (kernel, userns, cgroup, overlay, subid, seccomp) and exits 0.
2. **User namespaces disabled.** As root in the guest, `sysctl -w` turns on
   `kernel.apparmor_restrict_unprivileged_userns`, then sets `user.max_user_namespaces=0`.
   Each time `zbx doctor` must print `FAIL userns ... — fix: ...` (naming that sysctl) and exit 1.
   The sysctls are then restored and doctor must be all `ok` again.
3. **Static binary.** `file zbx` in the guest must say "statically linked". The harness also
   reads both release binaries (x86_64 and aarch64) and checks, in Zig, that each is a 64-bit
   ELF for the right machine with no `PT_INTERP` and no `DT_NEEDED`, and is under 2 MiB.

Any mismatch fails the run with the step, the expectation and the guest's own output above it.

## Running it

```
zig build demo-m0                 # KVM: needs a usable /dev/kvm
zig build demo-m0 -Daccel=tcg     # software emulation: no KVM needed, about 10 times slower
```

Without KVM and without `-Daccel=tcg` it stops at once with one line saying how to opt in.
Timeouts are scaled by 8 under TCG. It needs `qemu-system-x86_64` and `qemu-img` (QEMU is the
only external program the project uses for testing); everything else (the HTTP seed server, the
image download and its SHA-256 check, the ELF checks) is Zig.

Prerequisites and decisions, all in `src/testing/vm/`:

- **Image.** `image.zon` pins a dated Ubuntu 24.04 release by URL and SHA-256. It is downloaded
  into `.zig-cache/zbx-vm/` on first use and verified on every run; the guest disk is a qcow2
  overlay on it that is deleted afterwards, so the base is never modified.
- **Provisioning** is cloud-init NoCloud, served over HTTP by the harness (QEMU's SMBIOS
  `ds=nocloud;s=http://10.0.2.2:<port>/`), with no ISO tools: the user `demo` with subuid and
  subgid `100000:65536`; `uidmap` installed; lingering enabled for `demo`, so the systemd user
  manager (`user@1000.service`) exists however commands arrive; a passwordless root shell on the
  serial console, which is how the harness runs commands.
- **A host prerequisite, detected by doctor.** Ubuntu 24.04 ships
  `kernel.apparmor_restrict_unprivileged_userns=1`, which makes user namespaces useless to
  unconfined users, and `zbx doctor` correctly reports that on a stock install. The VM
  persists `0` in `/etc/sysctl.d/60-zigbox-userns.conf`. Step 2 turns it back on on purpose.
- **cgroup delegation needs no drop-in.** Stock Ubuntu 24.04 delegates `cpu memory pids` to
  `user@1000.service`, which is what doctor checks, so the VM does not add a `Delegate=` file.
  (`-Ddelegate-dropin=true` provisions one, to try the other case.)
- **Serial console, not SSH.** Commands go over the guest's serial console, so the harness
  needs no `ssh` client and no key. The VM is throwaway and offers no other way in.

## CI

`.github/workflows/ci.yml` has jobs `build` (both targets, size gate), `tidy`, `test`, `fuzz`
(one job per fuzzer, random seed printed) and `demo-m0` (installs QEMU, enables KVM with the
udev rule GitHub documents, caches the base image keyed on `image.zon`, runs
`zig build demo-m0 -Daccel=kvm`). The job's log is the harness's own output, guest console
included.

## Developer notes

- The development container has no `/dev/kvm`. QEMU was installed there with
  `apt-get update && apt-get install -y --no-install-recommends qemu-system-x86 qemu-utils`
  (the container is ephemeral; repeat this after a restart).
- A full run under TCG takes about 8 minutes (boot and cloud-init dominate). To iterate on the
  harness or on doctor, keep the provisioned disk with `-Dkeep-overlay=true` once, then use
  `-Dreuse-overlay=true` to boot it again (about 4 minutes, no provisioning). Both are
  development aids; the real demo always provisions a fresh VM.
- Everything the guest prints is echoed with a `  vm| ` prefix, and the seed server's
  requests with `  http| `.
