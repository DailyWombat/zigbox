# Brief: M0 · Doctor

Read `AGENTS.md` and the M0 section of `docs/SPEC.md` first. This brief adds the decisions the spec leaves open. Do not touch anything from M1 onward.

## Fixed decisions

- **Zig 0.17.0** (released 2026-10-01). Pin it in `build.zig.zon` (`minimum_zig_version = "0.17.0"`) and in CI. Install locally from https://ziglang.org/download/ (tarball for `x86_64-linux`), verify its SHA-256 against `index.json`.
- **Test VM:** Ubuntu 24.04 LTS cloud image (`noble-server-cloudimg-amd64.img`), pinned by URL and SHA-256 in `test/vm/image.lock`. Booted with QEMU + KVM, configured by cloud-init (a NoCloud seed ISO) with an unprivileged user `demo` that has a subuid/subgid range and systemd user delegation of `cpu memory pids`.
- **CI:** GitHub Actions on `ubuntu-24.04`. Jobs: `build` (both targets, size check), `test` (`zig build test`), `demo-m0` (boots the VM with KVM; enable `/dev/kvm` access via the udev rule step GitHub documents). Cache the VM image keyed on its SHA-256.
- **CLI parsing:** hand-written, no dependency. `zbx doctor`, `zbx --version`, `zbx help`. Unknown command → one-line error + exit 2.

## What to build

1. Project layout: `build.zig`, `build.zig.zon`, `src/main.zig`, `src/cli.zig`, `src/doctor.zig` (one function per check, each returning a result struct `{ name, status: ok|fail|warn, detail, fix }`).
2. `zbx doctor` checks, each reading kernel state directly (files under `/proc` and `/sys`, plus probes), never shelling out:
   - kernel version (`uname`), and a minimum (5.15; state the reason in a comment);
   - unprivileged user namespaces: `kernel.unprivileged_userns_clone` where present, `user.max_user_namespaces`, Ubuntu's `kernel.apparmor_restrict_unprivileged_userns`, and finally a real probe: fork a child that calls `unshare(CLONE_NEWUSER)` and reports;
   - cgroup v2: `/sys/fs/cgroup/cgroup.controllers` exists; the user's own cgroup (from `/proc/self/cgroup`) has `cpu`, `memory`, `pids` in its delegated `cgroup.subtree_control` path or `cgroup.controllers` — print the controllers found;
   - overlayfs in a user namespace: probe by mounting overlay inside a forked child's user+mount namespace on tmp dirs;
   - subuid/subgid: the current user has a range of at least 65536 in `/etc/subuid` and `/etc/subgid`, and `newuidmap`/`newgidmap` exist with setuid or file capabilities;
   - seccomp: `/proc/self/status` `Seccomp:` field present and `prctl(PR_GET_SECCOMP)` works.
   Each failure prints the exact fix (sysctl key and value, package name, or kernel version). Exit status 0 when all pass, 1 otherwise.
3. Output format: one line per check, `ok   <name>  <detail>` / `FAIL <name>  <detail> — fix: <fix>`. No colour unless stdout is a TTY.
4. `test/vm/`: scripts to fetch and verify the image, build the seed ISO, boot the VM headless, copy `zbx` in (9p or scp), run a command as `demo` and return its output and exit code.
5. `zig build demo-m0`: runs the three demo steps in the VM and asserts: all `ok` on first run; after `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=1` **and** `user.max_user_namespaces=0` the user-namespace check is `FAIL` with a fix line; `file zbx` says `statically linked`. Step 3 also asserts the binary is under 2 MB for both targets.
6. `DEMO.md` at the repo root: how a stranger runs the M0 demo by hand.
7. Unit tests for every check's parsing logic, fed from fixture files (so they run in the cloud container, which has cgroup v1 and runs as root).

## Done means

- `zig build`, `zig build test` pass locally; both targets cross-compile and are under 2 MB.
- The CI `demo-m0` job is green on the pushed branch. If you cannot see CI results, say so and stop at "pushed, CI not observed". Never claim the demo passed from local runs: this container cannot run it.
- Tag nothing; the owner tags `v0.0.0-m0` after watching the demo.

## Report back

A short list: what was built, what was run where (local vs CI), what was cut or left open, and any spec ambiguity you hit.
