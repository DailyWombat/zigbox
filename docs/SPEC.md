# Zigbox: A First-Principles Container Runtime in Zig

Snapshot of https://claude.ai/artifact/6D9js8mxSLYmfuZe3rQ26w taken 2026-10-23 (doc rev 8). The live doc is authoritative; update this file when it changes.

## Purpose and design principles

Zigbox is a Linux container runtime, image store and builder written in Zig, designed as if Docker were being invented today. It is a learning-and-showcase build: every milestone must end in something a person can watch work in under five minutes.

The opinions it encodes, in priority order:

1. **Rootless and daemonless.** No privileged daemon, no root socket. Every command is an ordinary process run by the user. Privilege comes only from user namespaces and the standard setuid helpers (`newuidmap`, `newgidmap`).
2. **Content-addressed files, not stacked layers.** Images are Merkle trees of file chunks hashed with BLAKE3. Identical files dedupe across all images; deleting a file shrinks the image; identity is a digest, never a mutable tag.
3. **Hermetic, reproducible builds.** Build steps form a DAG with declared inputs, no network unless a step asks for it, and a cache keyed on input content rather than on the text of the instruction.
4. **Secure by default.** Capabilities default-deny, seccomp on, `no_new_privs` on, network off unless granted. Isolation strength is a stated choice, not an accident.
5. **Separable tools.** Run, store and build are distinct subsystems with narrow interfaces, even if they ship as one binary.
6. **The thirty-second experience survives.** `zbx pull alpine && zbx run alpine sh` must be as easy as Docker. Principles that make the first run painful are wrong.

Why Zig: namespace setup (`clone3`, `unshare`, `setns`, `pivot_root`) must happen in a single-threaded process. Go's runtime forces runc to carry a C shim for this; Zig has no hidden runtime, calls syscalls directly through `std.os.linux`, needs no libc, and produces small static binaries.

## How to read the milestones

A milestone is done when its demo script runs live, start to finish, on a clean test VM, in front of someone who did not write the code. Passing unit tests is necessary but not sufficient.

Each milestone has four parts:

- **Goal**: the one capability it adds, in a sentence.
- **Scope**: what to build, and what is deliberately deferred.
- **Demo script**: the exact commands a presenter types and what the audience should see. The implementer turns each script into an automated integration test (`zig build demo-mN`) that asserts the same outputs.
- **Acceptance criteria**: checkable conditions, including failure behaviour.

Ground rules for the implementer:

- Each milestone ships as a tagged release with a `DEMO.md` that a stranger can follow.
- Error messages are part of the demo. A refused action must say what was refused and why, in one line, not an `errno` dump.
- Never break an earlier demo. All prior `demo-mN` tests run in CI on every change.
- When a milestone's scope is in doubt, cut scope and keep the demo.

## Milestone map

M0 to M2 make a hardened runtime; M3 and M4 add the store and real images, which unlocks networking and state (M5, M6) and hermetic builds and signing (M7, M8). M7 steps also reuse the M2 sandbox.

## Milestones

### M0 · Doctor: the host is ready

**Goal:** a binary that tells you, truthfully, whether this machine can run Zigbox.

**Scope:** `zig build` project layout, CLI skeleton, CI, a QEMU test VM with a pinned kernel and distro. `zbx doctor` probes for unprivileged user namespaces, cgroup v2 with user delegation, overlayfs in user namespaces, subuid/subgid ranges, and seccomp support.

**Demo script:**

1. On the test VM, run `zbx doctor`. Every check prints `ok` with the detected value (kernel version, cgroup controllers delegated to the user).
2. Disable unprivileged user namespaces with `sysctl`, run `zbx doctor` again. That check fails with a one-line fix.
3. Run `file zbx` to show a single static binary with no libc dependency.

**Acceptance criteria:**

- [ ] Static binary under 2 MB for x86_64 and aarch64, cross-compiled from one machine.
- [ ] Each failing check names the fix (sysctl key, package, or kernel version).
- [ ] CI boots the VM and runs `demo-m0`.

### M1 · Shell: a rootless, isolated process

**Goal:** run a shell inside an unpacked root filesystem, with no root privileges, isolated from the host.

**Scope:** `clone3` with user, mount, PID, UTS and IPC namespaces; UID/GID maps (single-UID mapping first, then a full subuid range via `newuidmap`); bind-mounted rootfs, `pivot_root`, fresh `/proc`, minimal `/dev`; exit-code propagation and signal forwarding. Input is a plain directory (an Alpine minirootfs tarball unpacked by hand). Deferred: images, limits, networking.

**Demo script:**

1. As an ordinary user, run `zbx run --rootfs ./alpine -- /bin/sh`.
2. Inside: `id` shows `uid=0(root)`; `ps` shows only PID 1 and `ps`; `hostname` shows the container name; `cat /etc/os-release` shows Alpine.
3. In a second host terminal: `ps -o user,pid,cmd` shows the shell running as the presenter's own UID.
4. Inside: `touch /etc/hacked`. On the host, `ls ./alpine/etc/hacked` shows it landed only in the rootfs, nowhere else.
5. Inside: `exit 42`. On the host, `echo $?` prints `42`.
6. Run `zbx run --rootfs ./alpine -- sleep 1000`, press Ctrl-C: it stops immediately.

**Acceptance criteria:**

- [ ] No setuid bit on `zbx`; works with the setuid `newuidmap` only.
- [ ] Host mounts and processes are invisible from inside.
- [ ] Namespace setup happens before any thread is spawned (assert in debug builds).

### M2 · Limits: contained and hardened

**Goal:** a misbehaving container cannot take down the host or regain privilege.

**Scope:** cgroup v2 limits for memory, CPU and PIDs inside the user's delegated cgroup (a transient systemd user scope); capabilities dropped to a minimal allowlist; a default seccomp filter; `no_new_privs`; read-only rootfs option. Exit reasons reported in plain words.

**Demo script:**

1. `zbx run --rootfs ./alpine --pids 64 -- sh -c ':(){ :|:& };:'`. The fork bomb stalls; the host stays responsive; `zbx` exits reporting the PID limit.
2. `zbx run --rootfs ./alpine --memory 128m -- stress-ng --vm 1 --vm-bytes 512m`. Output ends with `killed: out of memory (limit 128 MiB)`.
3. `zbx run --rootfs ./alpine -- mount -t tmpfs none /mnt` fails with `operation not permitted`.
4. `zbx run --rootfs ./alpine --read-only -- touch /x` fails; `touch /tmp/x` succeeds (tmpfs).

**Acceptance criteria:**

- [ ] Limits are visible in `/sys/fs/cgroup` under the user's slice while running and gone after exit.
- [ ] Seccomp profile is a checked-in, reviewed file, not an inline list.
- [ ] OOM, PID-limit and signal exits are distinguished in the exit report.

### M3 · Store: content-addressed file trees

**Goal:** root filesystems live in a deduplicated, verifiable store and are run by digest.

**Scope:** `zbx store import <dir>` walks a tree, chunks files, hashes with BLAKE3, and writes a Merkle tree of directories; the root hash is the tree's identity. Materialize for running as a read-only lower directory (hardlink farm from the store) plus a per-container writable upper via overlayfs. `zbx commit` turns a container's changes into a new tree digest. `zbx store verify` and `zbx store gc`.

**Demo script:**

1. Import `./alpine`; note its digest and `zbx store du` total.
2. Copy the rootfs, add one 10 MB file, import the copy. `zbx store du` grows by about 10 MB, not by a second full rootfs.
3. `zbx run <digest> -- sh`, install a package with `apk add`, exit, then `zbx commit`. A new digest prints; `zbx store diff <old> <new>` lists only the added files.
4. Corrupt a chunk on disk by hand. `zbx store verify` names the damaged file and every tree that references it.
5. Delete a file in a committed tree: the new tree's stored size drops (no whiteout baggage).

**Acceptance criteria:**

- [ ] Importing the same directory twice yields the same digest, independent of mtime and import order.
- [ ] File modes, ownership, xattrs and symlinks round-trip.
- [ ] Running a container never writes into the shared store.

### M4 · Pull: real images run

**Goal:** pull a public OCI image and run it, with the store doing the deduplication across images.

**Scope:** registry client for anonymous pulls (Docker Hub token dance, GHCR); manifest index platform selection; gzip and zstd layer decode; tar extraction with whiteout handling, applied into the M3 store as one flattened tree; image config (entrypoint, env, working dir, user) honoured at run. Tags resolve to digests, recorded in a lockfile `zbx.lock`. Deferred: push, private registries.

**Demo script:**

1. `zbx pull alpine:3.20` prints the resolved digest.
2. `zbx run alpine:3.20 -- cat /etc/os-release`.
3. `zbx pull python:3.12-slim` then `zbx pull python:3.13-slim`. `zbx store du --by-image` shows the second costs far less than its compressed size, because shared files are stored once.
4. `zbx run python:3.12-slim -- python -c 'print(2**100)'`.
5. Change the tag in `zbx.lock` to a wrong digest: `zbx run` refuses, naming the expected and actual digests.

**Acceptance criteria:**

- [ ] Top 20 official Docker Hub images run their default command (or a documented reason they cannot rootless).
- [ ] Every image is identified internally by tree digest; tags are aliases only.
- [ ] Interrupted pulls resume without re-downloading completed blobs.

### M5 · Network: access as an explicit grant

**Goal:** a container has no network unless granted, and a granted service is reachable from the host.

**Scope:** `--net none` as the default (loopback only); `--net host`; rootless user-mode networking via `pasta` (from the passt project) for `--publish HOST:CONTAINER`; a generated `/etc/resolv.conf` and `/etc/hosts`. Deferred: container-to-container networks and egress allowlists (see stretch goals).

**Demo script:**

1. `zbx run alpine -- wget -qO- https://example.com` fails: `network: none (grant with --net)`.
2. `zbx run --net user alpine -- wget -qO- https://example.com` prints the page.
3. `zbx run --publish 8080:80 nginx` in one terminal; `curl localhost:8080` on the host returns the nginx welcome page.
4. `ss -tlnp` on the host shows the listener owned by the presenter's user, and `sudo iptables -S` shows no rules added.

**Acceptance criteria:**

- [ ] No host firewall or routing changes, ever.
- [ ] `pasta` absence is caught by `zbx doctor` and by a clear error at run.
- [ ] Published ports are released when the container exits, including on crash.

### M6 · State: durable data is declared

**Goal:** data that must outlive a container is named, typed and listed, never an anonymous directory.

**Scope:** named state volumes (`--state pgdata:/var/lib/postgresql/data`), ephemeral tmpfs mounts, read-only bind mounts from the host, and read-only secret files mounted from a host path at run. `zbx state ls`, `zbx state rm`, `zbx state export` to a tarball. UID mapping handled so the container's user owns its state.

**Demo script:**

1. `zbx run --state pgdata:/var/lib/postgresql/data --publish 5432:5432 -e POSTGRES_PASSWORD=demo postgres:16`.
2. From the host, `psql` in, create a table, insert a row.
3. Kill the container. Start it again with the same command; the row is still there.
4. `zbx state ls` shows `pgdata`, its size and the last container that used it.
5. Run without `--state`: data is gone after exit, as advertised.

**Acceptance criteria:**

- [ ] State volumes live outside the content store and are never garbage-collected implicitly.
- [ ] Ownership inside the container is correct without `chmod 777` workarounds.
- [ ] Secret mounts are read-only and excluded from `zbx commit`.

### M7 · Build: hermetic and reproducible

**Goal:** build images from a declared DAG of steps, so the same inputs always produce the same digest.

**Scope:** a build file (format is an open question below) declaring steps, each with a base tree, input files or prior step outputs, a command, and an optional `network: true`. Each step runs as an M2-hardened container with network off by default; its output tree goes into the store; its cache key is the hash of its inputs plus command. Timestamps normalized; independent steps run in parallel. Deferred: Dockerfile import (stretch).

**Demo script:**

1. Build a small Zig or Go hello-world image: `zbx build`. Note the final digest and the step timings.
2. Run `zbx build` again: every step is a cache hit, completes in under a second.
3. Edit a README that no step declares as input: no rebuild, same digest.
4. Edit the source file: only the compile step and its dependents rebuild; the cache report shows hits and misses per step.
5. On a second clean VM, build from the same commit: identical digest.
6. Add a step that runs `curl` without `network: true`: it fails, naming the step and the grant needed.

**Acceptance criteria:**

- [ ] Bit-for-bit reproducible digest across two machines for the demo project.
- [ ] Cache keys depend on content, never on file mtimes or step text order alone.
- [ ] `zbx build --graph` prints the step DAG.

### M8 · Trust: signed, with provenance

**Goal:** a host can refuse to run anything it cannot trace back to a trusted key and a recorded build.

**Scope:** ed25519 keys (`zbx key new`); `zbx sign <digest>`; a provenance record emitted by M7 builds (input digests, build file hash, builder version) stored beside the tree; a run policy file (`trusted keys`, `require signature`, `require provenance`). Deferred: Sigstore integration, transparency logs.

**Demo script:**

1. Build and sign an image. `zbx inspect --provenance <digest>` shows its inputs and builder.
2. Enable policy `require signature`. Running the signed image works; running an unsigned `alpine` is refused, naming the policy rule.
3. Tamper with one file in the stored tree. `zbx run` refuses: the tree digest no longer matches the signature.
4. `zbx verify <digest>` walks from the signature to every input, offline.

**Acceptance criteria:**

- [ ] Signatures are over tree digests, so they survive re-pulls and re-materialization.
- [ ] Policy refusals happen before any process starts.

### Stretch milestones

Each keeps the same demo-first contract; none blocks M0 to M8.

- **S1 · MicroVM isolation:** the same image runs under a Firecracker or Cloud Hypervisor backend with `--isolation vm`; demo shows a kernel exploit test passing in namespace mode and contained in VM mode.
- **S2 · Lazy start:** start a large image before its files are local, fetching chunks on first read; demo starts a multi-GB image in seconds.
- **S3 · Container networks and egress grants:** `--allow db:5432`, `--egress api.example.com:443`; demo shows an allowed call succeed and a disallowed one refused.
- **S4 · Dockerfile import:** translate a common Dockerfile into the M7 build format, flagging non-hermetic steps.
- **S5 · WASM workloads:** run a WASI component through the same CLI, store and policy.

## Non-goals

These are out of scope for M0 to M8. Raise a change to the doc before building any of them.

- **Non-Linux hosts.** No macOS or Windows support; on those, run Zigbox inside a Linux VM.
- **Rootful mode.** There is no `sudo zbx`. If something only works as root, it is not supported.
- **Docker API or CLI compatibility.** Commands may resemble Docker's, but no socket API and no drop-in flag parity.
- **Orchestration.** No Compose equivalent, no clustering, no scheduler, no restart policies beyond what a systemd user unit gives.
- **Image push and private registries.** Pull-only from public registries until after M8.
- **Dockerfile execution.** Dockerfiles are not run directly (import is stretch S4).
- **Live migration, checkpoint/restore, GPU passthrough.**

## Technical notes, risks and open questions

### Notes for the implementer

- **Pin the Zig version** in `build.zig.zon` and CI. Zig is pre-1.0 and its standard library changes between releases; upgrade deliberately, between milestones, never during one.
- **Lean on the standard library first.** Zig's std covers raw Linux syscalls, BLAKE3, ed25519, JSON, tar, gzip/deflate, zstd decompression and a TLS client. Verify each is adequate when its milestone starts; add a dependency only with a written reason.
- **Single-threaded until exec.** All namespace work happens in the child before `execve`. Thread pools (pull, build) live only in the parent `zbx` process.
- **Kernel baseline.** Target a recent LTS kernel with unprivileged user namespaces, cgroup v2 delegation and overlayfs mountable inside user namespaces. Ubuntu 24.04 and Fedora 40 or later are reasonable test VMs; some distros restrict unprivileged user namespaces through AppArmor, so `zbx doctor` must detect that.
- **Test in VMs, not containers.** Integration tests boot a QEMU guest so namespace and cgroup behaviour is real.

### Risks

| Risk | Where it bites | Mitigation |
| --- | --- | --- |
| Rootless networking is a deep rabbit hole | M5 | Depend on `pasta` rather than writing a userspace network stack |
| Registry quirks (auth, rate limits, odd manifests) | M4 | Test against a fixed list of images; cache blobs in CI |
| File-level store is slower to materialize than layer unpacking | M3, M4 | Benchmark against the top 20 images at M4; fall back to cached materialized trees |
| Reproducibility leaks (timestamps, file order, locale) | M7 | Two-VM digest comparison in CI from M7 on |
| Zig std churn breaks the build | All | Pinned version; upgrades are their own tagged change |

### Open questions

- [ ] Build file format for M7: ZON (Zig's native object notation), a small Starlark subset, or a typed config language? Decide before M7 starts.
- [ ] Chunking for M3: whole-file hashing first, or content-defined chunking from the start? Whole-file is simpler; chunking matters for large files that change slightly.
- [ ] Should the store be shareable across users on one host, or strictly per-user?
- [ ] Final project name and CLI name (`zigbox` / `zbx` are placeholders).
