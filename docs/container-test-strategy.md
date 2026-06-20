# Container-Based Integration Test Strategy

**Status**: Proposal  
**Audience**: SDK + Agent contributors  
**Goal**: Replace host-dependent `t.Skip()` integration tests with deterministic,
multi-distro container tests using immutable Docker stages for known system states.

## Problem

The SDK currently tests real system tool interactions in two ways, neither of
which provides NIS2-grade assurance:

1. **Unit tests with `exectest.FakeRunner`** — validate argv shape and scripted
   stdout, but never exercise the real binary. A shell quoting change, locale
   shift, or output format drift is invisible.

2. **Host-probe integration tests** (`//go:build integration`) — run the real
   tool if installed on the CI host. If the tool is absent, skip silently.
   Coverage depends on what happens to be installed in the CI runner, not on
   what matters in production.

The result: the SDK's highest-risk code — argv construction, output parsing,
error decoding — is only tested against mocks. Container tests fix both classes
of gap simultaneously.

## Architecture

### One Dockerfile per distro, multiple stages per Dockerfile

Each stage IS a known system state. The Dockerfile IS the specification. The
image hash IS the proof that the state hasn't changed.

```
sdk/test/Dockerfile.debian
  ├── base                      — clean Debian with full tool surface
  ├── state-locked-apt          — stale /var/lib/dpkg/lock
  ├── state-degraded-systemd    — masked systemd-journald.service
  ├── state-missing-tools       — cryptsetup, fuser removed
  └── state-nologin-users       — user with /usr/sbin/nologin shell

sdk/test/Dockerfile.fedora
  ├── base                      — clean Fedora with full tool surface
  ├── state-locked-dnf          — stale /var/lib/dnf/transaction-done
  ├── state-corrupted-rpmdb     — missing __db.* files
  ├── state-degraded-systemd    — masked service
  └── state-missing-tools       — cryptsetup removed

sdk/test/Dockerfile.opensuse
sdk/test/Dockerfile.archlinux
  ... equivalent bad-state stages for each distro's tool surface
```

**Why stages, not separate Dockerfiles**: A stage inherits the `base` layer
(which installs the full tool surface once) and adds one thin mutation. The
`base` stage is identical across all targets, so Docker layer caching means
subsequent matrix cells build in seconds.

**Why stages, not runtime setup**: Runtime setup (the test function mutates the
container filesystem) carries two risks:
- The setup code can silently fail, making the test vacuously succeed.
- The setup code can produce the wrong state (e.g., writing to
  `/var/lib/dpkg/lock` when the SDK actually reads `/var/lib/apt/lists/lock`
  after a distro update), and no one notices until production.

A `RUN` directive in the Dockerfile with a `test -f` assertion fails the BUILD
if the state is wrong. The resulting image is immutable.

### The test owns its precondition

Every container test checks its expected filesystem state at the top and skips
if the state doesn't match. No external mapping between "this CI job" and "these
tests" — the test IS the authority.

```go
//go:build container

func TestRepair_RemovesStaleDpkgLock(t *testing.T) {
    if _, err := os.Stat("/var/lib/dpkg/lock"); os.IsNotExist(err) {
        t.Skip("irrelevant: not a locked-package-manager container")
    }

    m, _ := pkg.New(pkg.Apt, exec.NewRunner(exec.Direct))
    err := m.Repair(ctx)
    require.NoError(t, err)
    require.NoFileExists(t, "/var/lib/dpkg/lock")
}
```

This means:
- Running `go test -tags=container ./...` against ANY stage works correctly —
  tests that don't apply to the current state skip cleanly.
- A developer running a single test locally can build the relevant stage with
  one command and get a deterministic result.
- Adding a new test does not require updating CI configuration.

### Bad-state verification at build time

Each bad-state stage in the Dockerfile verifies its own precondition at BUILD
time using `RUN test`. A Dockerfile that creates `state-locked-apt` but fails
to actually produce a lock file fails the build, not the test.

```dockerfile
FROM base AS state-locked-apt
RUN touch /var/lib/dpkg/lock
RUN touch /var/lib/dpkg/lock-frontend
RUN test -f /var/lib/dpkg/lock || (echo "PRECONDITION FAILED" && exit 1)
```

### States requiring kernel capabilities

A small number of bad states need Docker capabilities that must be granted at
`docker run` time, not inside the container. These get thin `FROM` stages in the
same Dockerfile, and the CI matrix entry includes the appropriate `docker run`
flags:

| State | Capability needed | Run flag |
|-------|------------------|----------|
| Immutable file (`chattr +i`) | `LINUX_IMMUTABLE` | `--cap-add LINUX_IMMUTABLE` |
| LUKS header corruption | Loop device access | `--privileged --device /dev/loop0` |
| fuser on some distros | Process tracing | `--cap-add SYS_PTRACE` |

## Catalog of planned states

### Package managers — `pkg`, `pkg/repair.go`, `sys/repo`

| State | Precondition | Distros |
|-------|-------------|---------|
| `state-locked-apt` | `/var/lib/dpkg/lock` exists, no process holds it | Debian |
| `state-locked-dnf` | Stale `/var/lib/dnf/transaction-done` | Fedora |
| `state-locked-zypper` | `/var/run/zypp.pid` exists | openSUSE |
| `state-corrupted-rpmdb` | Missing `__db.*` files in `/var/lib/rpm` | Fedora, openSUSE |
| `state-missing-gpg-key` | Apt source lists URL with no imported key | Debian |
| `state-conflicting-hold` | `apt-mark hold bash` active | Debian |
| `state-missing-fuser` | `/usr/bin/fuser` absent | All |

### User management — `sys/user`

| State | Precondition | Distros |
|-------|-------------|---------|
| `state-stale-passwd-lock` | `/etc/passwd.lock` exists | All |
| `state-passwd-shadow-mismatch` | User in passwd, not in shadow | All |
| `state-wrong-home-owner` | `/home/<user>` owned by wrong UID | All |
| `state-gid-collision` | Two groups share GID 1001 | All |

### Filesystem — `sys/fs`

| State | Precondition | Distros |
|-------|-------------|---------|
| `state-immutable-file` | `chattr +i` on a file under managed root | All (with cap) |
| `state-world-writable-parent` | Parent dir 0777 non-sticky | All |
| `state-nonexistent-parent` | Write target's parent missing | All |

### Systemd services — `sys/service`

| State | Precondition | Distros |
|-------|-------------|---------|
| `state-degraded-systemd` | `systemctl mask` one unit, `--failed` non-empty | All with systemd |
| `state-missing-unit-file` | Unit referenced but `.service` file deleted | All with systemd |

### Encryption — `sys/encryption`

| State | Precondition | Distros |
|-------|-------------|---------|
| `state-missing-cryptsetup` | `/usr/sbin/cryptsetup` absent | All |
| `state-no-dev-shm` | `/dev/shm` bind-mounted to `/dev/null` | All |
| `state-luks-header-corrupt` | Loopback LUKS volume with trash bytes at offset 0 | All (with `--privileged`) |

### Timesync — `sys/timesync`

| State | Precondition | Distros |
|-------|-------------|---------|
| `state-chrony-stopped` | `chronyd` not running, stale drift file | Fedora, openSUSE |
| `state-ntp-disabled` | `timedatectl set-ntp false` | All with systemd |

### Terminal — `sys/terminal`

| State | Precondition | Distros |
|-------|-------------|---------|
| `state-nologin-user` | User with `/usr/sbin/nologin` shell | All |
| `state-missing-shell` | `/bin/bash` and `/bin/sh` removed | All |

### DNS — `sys/dns`

| State | Precondition | Distros |
|-------|-------------|---------|
| `state-resolved-masked` | `systemd-resolved.service` masked | All with systemd |
| `state-resolv-conf-broken` | `/etc/resolv.conf` symlink to nonexistent target | All |

### Firewall — `sys/firewall`

| State | Precondition | Distros |
|-------|-------------|---------|
| `state-nft-conflicting` | nft rules from another namespace present | All |
| `state-firewalld-no-zone` | Default zone deleted | Fedora |
| `state-ufw-inactive` | ufw disabled, stale rule files in `/etc/ufw` | Debian |

## CI integration

### Matrix strategy

The CI workflow mirrors the existing agent integration test pattern (one
`Dockerfile` per distro, `docker build --target`, `docker run`), extended with
per-state matrix entries:

```yaml
jobs:
  container:
    strategy:
      fail-fast: false
      matrix:
        include:
          # Clean state — exercises every package's happy path
          - distro: debian
            target: base
          - distro: fedora
            target: base
          - distro: opensuse
            target: base
          - distro: archlinux
            target: base

          # Bad states per distro
          - distro: debian
            target: state-locked-apt
          - distro: debian
            target: state-degraded-systemd
          - distro: debian
            target: state-stale-passwd-lock
          # ... etc

          - distro: fedora
            target: state-locked-dnf
          - distro: fedora
            target: state-corrupted-rpmdb
          - distro: fedora
            target: state-ntp-disabled
          # ... etc
    steps:
      - uses: docker/build-push-action@v6
        with:
          file: sdk/test/Dockerfile.${{ matrix.distro }}
          target: ${{ matrix.target }}
          tags: pm-sdk-test
          cache-from: type=gha
          cache-to: type=gha,mode=max

      - run: |
          docker run --rm pm-sdk-test \
            go test -tags=container -count=1 -timeout=10m ./...
```

### Build caching

The `docker/build-push-action` with `cache-from: type=gha` reuses layers across
matrix cells. The `base` stage is identical for all targets on a given distro,
so it builds once per distro. Subsequent `state-*` stages each add a thin layer
and build in seconds.

### Runtime cost

A 4-distro × 5-state matrix (20 cells) with Go test caching completes in
approximately 8-12 minutes, dominated by the first `base` stage build per
distro and the slowest test package (`pkg` with real package manager
operations). This is comparable to the existing agent integration CI runtime.

## Coverage impact

| Before | After |
|--------|-------|
| `pkg`: 100% unit, 0% against real apt/dnf/pacman/zypper | 100% unit + verified against all 4 distros |
| `sys/encryption`: 100% unit, cryptsetup/LUKS output verified by mock | Verified against real `cryptsetup isLuks`, `lsblk -J` |
| `sys/user`: 100% unit, passwd/group/shadow parsing by mock | Verified against real `getent passwd`, `useradd`, `usermod` |
| `sys/smart`: 100% unit, `smartctl -j` output by mock | Verified against real smartctl (if block device available) |
| `sys/timesync`: 100% unit, timedatectl/chronyc output by mock | Verified against real `timedatectl show`, `chronyc tracking` |
| `pkg/repair.go`: 0% against real stale locks | Verified against real locked apt/dnf/zypper states |
| `sys/exec`: 100% unit, SIGTERM→SIGKILL by mock | Verified against real process group signaling |

## Relationship to existing agent integration tests

The agent's `internal/executor/integration_test.go` exercises the SDK
**indirectly** through the executor dispatch layer. It validates end-to-end
behavior (user creation produces a real passwd entry, package install produces
a real installed binary) but cannot test the SDK's internal parsing, error
decoding, or argv construction in isolation.

The SDK container tests operate one layer below: they exercise the SDK's
public API directly (Manager interfaces, Source interfaces) against the real
tools. Both test suites run in the same CI, on the same container images,
providing defense-in-depth: the agent tests prove the system works, the SDK
tests prove the primitives work independently.

## Implementation order

1. **Dockerfiles** — `sdk/test/Dockerfile.debian`, `.fedora`, `.opensuse`,
   `.archlinux`. Modeled on the existing `agent/test/Dockerfile.integration*`
   pattern, with the addition of `state-*` stages.

2. **CI workflow** — `sdk/.github/workflows/container-test.yml`. Modeled on the
   existing `agent/.github/workflows/integration-test.yml`.

3. **First container test** — one package, one distro, one bad state. Proves the
   pattern end-to-end: build → run → test detects its precondition → test
   asserts behavior.

4. **Remaining packages** — add `//go:build container` test files progressively,
   targeting the highest-risk parsers and repair paths first.

5. **Retire host-probe tests** — as container tests cover the same behavior
   deterministically, the `t.Skip("tool not present")` integration tests become
   redundant and can be removed or consolidated.
