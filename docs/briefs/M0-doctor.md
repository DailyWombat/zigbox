# Brief: M0 · Doctor

Read `AGENTS.md`, `docs/STYLE.md` and the M0 section of `docs/SPEC.md` first. This brief adds the decisions the spec leaves open. Do not touch anything from M1 onward.

M0 is small, but it lays the foundations every later milestone depends on: the host interface and its simulator, the limits file, the tidy check, the fuzz runner and the VM harness. Get these right; they are the main deliverable.

## Fixed decisions

- **Zig 0.17.0** (released 2026-10-01). Pin it in `build.zig.zon` (`minimum_zig_version = "0.17.0"`) and in CI. Install it locally from https://ziglang.org/download/ (the `x86_64-linux` tarball) and verify its SHA-256 against `index.json`.
- **Build mode:** `ReleaseSafe` for both release targets. The 2 MB limit is checked against that build.
- **Test VM:** Ubuntu 24.04 LTS cloud image (`noble-server-cloudimg-amd64.img`), pinned by URL and SHA-256 in `src/testing/vm/image.zon`. QEMU with KVM, headless, serial console. An unprivileged user `demo` has a subuid/subgid range and systemd user delegation of `cpu memory pids`.
- **VM provisioning without extra tools:** cloud-init NoCloud seed served over HTTP by the Zig harness itself (QEMU `-smbios type=1,serial=ds=nocloud;s=http://10.0.2.2:<port>/`). Do not use `genisoimage` or `cloud-localds`. Commands run in the guest over the serial console or SSH with a key the harness generates per run. Pick one, and write down why.
- **CI:** GitHub Actions on `ubuntu-24.04`. Jobs: `build` (both targets plus a size check), `tidy`, `test`, `fuzz` (every fuzzer, fixed iteration count, random seed printed), and `demo-m0` (enable `/dev/kvm` with the udev rule step GitHub documents; cache the image keyed on its SHA-256). The only shell allowed is the YAML steps that install Zig and QEMU.
- **CLI:** hand-written parser, no dependency. Commands: `zbx doctor`, `zbx --version`, `zbx help`. An unknown command prints one line and exits 2.

## Architecture

```
main.zig ─▶ cli.zig ─▶ doctor.zig ──gather──▶ host.zig (interface)
                           │                    ├─ host_real.zig  (syscalls, /proc, /sys)
                           │                    └─ host_sim.zig   (seeded model + fault injection)
                           └──evaluate (pure)──▶ Report ─▶ render (pure) ─▶ stdout
```

- `doctor.zig` works in two phases. **Gather** reads raw facts through `host` into a fixed-size `Facts` struct (bounded byte buffers, no allocation). **Evaluate** is a pure function from `Facts` to `Report`; rendering is a pure function from `Report` to text. Every `if` about policy (what counts as ok, which fix to name) lives in evaluate, not in gather.
- `host.zig` is the only file that may name syscalls or paths under `/proc` and `/sys`. Keep it narrow: read a file into a caller buffer (with a size limit), `uname`, fork-and-probe (`unshare` user namespace, overlay mount inside it), look up a path's mode. In Zig, a struct of function pointers or a comptime-selected type both work; choose one and write down why.
- `constants.zig` holds every limit: buffer sizes for each `/proc` or `/sys` file read, the minimum kernel version, the minimum subuid range (65536), the probe timeout and so on, with `comptime` assertions on how they relate.

## Checks (`zbx doctor`)

Each check produces `{ name, status: ok | fail | warn, detail, fix }`. A `fail` always has a `fix`; an `ok` never has one (assert both).

1. **kernel**: version from `uname`; minimum 5.15. Comment why 5.15 (overlayfs in user namespaces landed in 5.11; pick the reason you can cite).
2. **userns**: `user.max_user_namespaces > 0`; `kernel.unprivileged_userns_clone` where it exists; Ubuntu's `kernel.apparmor_restrict_unprivileged_userns`; then a real probe (fork a child that calls `unshare(CLONE_NEWUSER)`). If the sysctls say yes but the probe fails, report that, because it is the interesting case.
3. **cgroup**: `/sys/fs/cgroup/cgroup.controllers` exists (v2). Find the user's own cgroup from `/proc/self/cgroup` and list the controllers delegated there; it needs `cpu memory pids`.
4. **overlay**: a probe mounts overlayfs on temporary directories inside a forked child's user and mount namespaces. Clean up on every path, including probe failure.
5. **subid**: the current user (by name and by UID) has a range of at least 65536 in `/etc/subuid` and `/etc/subgid`. `newuidmap` and `newgidmap` exist and are setuid root or carry file capabilities.
6. **seccomp**: the `Seccomp:` field exists in `/proc/self/status`, and `prctl(PR_GET_SECCOMP)` succeeds.

Output is one line per check: `ok   <name>  <detail>` or `FAIL <name>  <detail> — fix: <fix>`, with no colour unless stdout is a TTY. Exit 0 if every check is ok, 1 if any fails. If a check itself fails to run (a file is unreadable, a probe times out), report that as `FAIL` with a reason, never a crash and never `ok`.

## Slices (commit and stop for review after each)

**Slice 1 · Foundations.** Zig installed and pinned; `build.zig` with `test`, `tidy`, `fuzz` and release steps; `constants.zig`; `host.zig` interface plus `host_real.zig` and a first `host_sim.zig`; `cli.zig` with `--version`, `help` and the unknown-command error; `src/tidy.zig` enforcing 100 columns, 70-line functions, no `.sh` files without an allowlist entry, no `usize` in struct fields, and no `@import` of anything outside the repo and std. Unit tests and snapshot tests for the CLI. Cross-compile both targets in `ReleaseSafe` and record their sizes.

**Slice 2 · Doctor logic.** The gather, evaluate and render phases for all six checks against `host_sim`. Fixtures for real-world `/proc` and `/sys` contents: Ubuntu 24.04, Fedora 40, a cgroup v1 host like this container, AppArmor-restricted userns, a missing subuid entry, and others you think of. Snapshot tests for every fixture's full report. Fuzzers: (a) every parser on random and mutated bytes, including truncated, oversized, non-UTF-8 and NUL-containing input; (b) a doctor simulation that injects host faults at random points and asserts the report is always well formed (every check present, every fail with a fix, nothing crashes). Also run `zbx doctor` for real in this container and paste its output; it should FAIL the cgroup check and explain why.

**Slice 3 · VM and CI.** The harness in `src/testing/vm/`, `zig build demo-m0`, the CI workflow, and `DEMO.md`. The demo test asserts: (1) every check `ok` on a fresh VM; (2) after `sysctl -w kernel.apparmor_restrict_unprivileged_userns=1` and `user.max_user_namespaces=0` in the guest, `userns` FAILs with a fix line and exit code 1; (3) `file zbx` reports a statically linked ELF, and both targets are under 2 MB. This container has no KVM, so this slice cannot be run here. Make the harness fail with a clear one-line message when `/dev/kvm` is missing. TCG fallback is not required.

## Done means

- `zig build`, `zig build tidy`, `zig build test` and every fuzzer for 10,000 iterations pass locally, with the commands and results in your report.
- The CI `demo-m0` job is green on the pushed branch. The supervisor pushes and watches CI. Until it is green, M0 is "built, not demonstrated".
- No tags. The owner tags `v0.0.0-m0` after watching the demo.
