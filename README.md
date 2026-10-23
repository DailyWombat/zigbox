# Zigbox

A rootless, daemonless Linux container runtime, image store and builder, written in Zig, designed as if Docker were being invented today. Every milestone ends in a demo a person can watch work in under five minutes.

- **Design:** [docs/SPEC.md](docs/SPEC.md), a snapshot of the [live design doc](https://claude.ai/artifact/6D9js8mxSLYmfuZe3rQ26w).
- **How the code is written and tested:** [docs/STYLE.md](docs/STYLE.md) (TigerBeetle's TigerStyle, adapted).
- **Rules for contributors and agents:** [AGENTS.md](AGENTS.md).

## Status

*As of 2026-10-23. No milestone is demonstrated in CI yet. M0's demo has passed twice, independently, in a fresh Ubuntu 24.04 VM under software emulation (TCG); the CI run with KVM is the remaining step.*

| Milestone | What it adds | Status |
| --- | --- | --- |
| **M0 · Doctor** | `zbx doctor`: is this host ready to run Zigbox? | **In progress**: all three slices built and reviewed; demo passes under TCG; CI not yet run |
| M1 · Shell | Run a shell in a rootless, isolated root filesystem | Not started |
| M2 · Limits | cgroup limits, capabilities, seccomp, read-only root | Not started |
| M3 · Store | Content-addressed, deduplicated file trees | Not started |
| M4 · Pull | Pull and run public OCI images | Not started |
| M5 · Network | No network unless granted; published ports via `pasta` | Not started |
| M6 · State | Named, listed state volumes | Not started |
| M7 · Build | Hermetic, reproducible builds from a step DAG | Not started |
| M8 · Trust | Signatures, provenance and a run policy | Not started |
| S1–S5 | Stretch: microVMs, lazy start, egress grants, Dockerfile import, WASM | Not started |

### M0 in detail

M0 is built in three slices. Each is reviewed adversarially before it is pushed.

| Slice | Contents | Status |
| --- | --- | --- |
| 1 · Foundations | Zig 0.17.0 pinned; `build`, `test`, `tidy`, `fuzz` and `release` steps; limits in `src/constants.zig`; the host interface (`src/host.zig`) with real and simulated implementations; `zbx --version` and `zbx help`; the style checker; the seeded fuzz runner; release size gate (under 2 MiB) | **Built and reviewed.** Unit, snapshot and fuzz tests pass. Release binaries: x86_64 305 KB, aarch64 214 KB (stripped, static, ReleaseSafe). |
| 2 · Doctor logic | The six `zbx doctor` checks (kernel, user namespaces, cgroup delegation to the systemd user manager, overlayfs, subuid/subgid with `newuidmap`/`newgidmap`, seccomp); real probes in a forked child; parsers; 42 snapshot fixtures of real and broken hosts; 12 seeded fuzzers | **Built and reviewed.** Runs for real on the build container (root and ordinary users); verdicts on a real Ubuntu host await slice 3. Release binaries: x86_64 366 KB, aarch64 269 KB. |
| 3 · VM and CI | QEMU test VM harness in Zig, `zig build demo-m0`, GitHub Actions workflow, [demo document](docs/demos/m0.md) | **Built and reviewed.** `demo-m0` passed from a fresh VM under software emulation (TCG) in two independent runs (implementer and supervisor, about 8.5 minutes each): six `ok` lines, the right FAIL and fix for both sysctls, a static binary. Never run: the KVM path, the HTTPS image download, the CI workflow. |

**What works today on this branch:** `zbx --version`, `zbx help`, clear one-line errors for bad input, and `zbx doctor`, which checks this host and names the fix for every failure. It has run only on the cgroup v1 build container so far; the M0 demo on a clean Ubuntu 24.04 VM is slice 3.

## Building

Requires Zig 0.17.0 exactly ([download](https://ziglang.org/download/)). There are no other dependencies.

```sh
zig build                          # zig-out/bin/zbx (debug)
zig build test                     # unit, snapshot and simulation tests
zig build tidy                     # formatting and mechanical style rules
zig build fuzz -- <fuzzer> [seed]  # one seeded fuzzer; prints its seed so failures replay
zig build release                  # static ReleaseSafe binaries for x86_64 and aarch64, size-checked
```

Linux only, by design. Running containers will need unprivileged user namespaces, cgroup v2 with user delegation and the `uidmap` package; `zbx doctor` checks all of this.

## License

MIT. See [LICENSE](LICENSE).
