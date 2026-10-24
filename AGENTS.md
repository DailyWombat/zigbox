# Zigbox: operating instructions

Zigbox is a rootless, daemonless Linux container runtime, image store and builder in Zig. The spec is [docs/SPEC.md](docs/SPEC.md), a snapshot of the live design doc (https://claude.ai/artifact/6D9js8mxSLYmfuZe3rQ26w). If they disagree, the live doc wins: stop and report the conflict rather than picking one.

## Rules

- **Style and testing follow [docs/STYLE.md](docs/STYLE.md)** (TigerStyle, adapted). Read it before writing code. Review rejects code that breaks it.
- Work one milestone at a time, from its brief in `docs/briefs/`. Do not start a later milestone or build anything listed under Non-goals.
- A milestone is done only when its demo script runs live in the test VM. Unit tests passing, or code that compiles, is never reported as a passed demo. Say exactly what was and was not run.
- Each demo script becomes an automated test, `zig build demo-mN`. Never break an earlier demo: all prior `demo-mN` tests run in CI.
- Error messages are part of the demo: one line saying what was refused and why, never an `errno` dump.
- When scope is in doubt, cut scope and keep the demo. Record the cut in the milestone's demo document, `docs/demos/mN.md`.
- Zig version is pinned in `build.zig.zon` (`minimum_zig_version`) and CI. Do not upgrade during a milestone.
- No third-party dependencies; standard library only (see STYLE.md for the allowed external programs).
- No libc: never set `link_libc`. Release targets are `x86_64-linux` and `aarch64-linux`, static, built `ReleaseSafe` so assertions stay on.
- The pinned Zig is newer than most model training data, and std APIs (I/O, `std.Io`, readers/writers, build system) changed in 0.15–0.17. Read the pinned std source (`$(zig env | jq -r .lib_dir)/std`) before using an API; do not write from memory.
- All namespace work happens in a single-threaded child before `execve`. Thread pools only in the parent.
- Never run anything with `sudo` in tests on a developer's host. Privileged setup (sysctl toggles) happens only inside the test VM.

## Environment facts (checked 2026-10-23 in the Claude Code cloud container)

- The cloud container runs as root, has cgroup v1/hybrid (no `cgroup.controllers`), no `/dev/kvm`, no `newuidmap`, no `pasta`. It is not a valid test host: use it to build, unit-test and cross-compile only.
- Real validation happens in a QEMU guest (Ubuntu 24.04 cloud image) on GitHub Actions `ubuntu-24.04` runners, which expose KVM.
- Zig downloads from https://ziglang.org/download/ work through the proxy.

## Commands

- `zig build` builds `zig-out/bin/zbx`.
- `zig build test` runs unit, snapshot and simulation tests.
- `zig build tidy` checks line length, function length and banned patterns.
- `zig build fuzz -- <fuzzer> [seed]` runs one seeded fuzzer.
- `zig build demo-mN` runs milestone N's demo inside the test VM (harness in `src/testing/vm/`, written in Zig).

## Working as the implementer subagent

- Work in slices as the brief defines them. At the end of each slice, commit locally and stop with a report. **Do not push.** The supervisor reviews each slice adversarially, and you fix what the review finds before the next slice.
- Report what you ran and its output, what you did not run and why, every deviation from the brief, and anything in the spec or brief that seemed wrong.

## README status

- [README.md](README.md) holds the status of every milestone and slice: what is built and reviewed, what is in review, and what is not started. The supervisor updates it in the same push that changes the status. Never mark anything "demonstrated" until its `demo-mN` job is green in CI.

## Git

- Develop on the branch you were given and commit in small, meaningful steps. The supervisor pushes, with `git push -u origin <branch>`, after review.
- Never report an unpushed commit as pushed.
