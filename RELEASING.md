# Releasing mcp-hookd

Releases are built and packaged by [`.github/workflows/release.yml`](.github/workflows/release.yml) using [`scripts/ci/package-release.py`](scripts/ci/package-release.py) and gated by [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

## 1. Prepare Version and Lockfile on `main`

1. Update `[package].version` in `Cargo.toml` to the target semantic version `X.Y.Z`.
2. Refresh `Cargo.lock` so `--locked` builds succeed without modifying the lockfile:

```bash
cargo update -w
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo build --release --locked
python3 scripts/ci/run-tests.py
```

3. Commit the `Cargo.toml` and `Cargo.lock` update and merge it into `main`.

## 2. Optional Pre-Tag Dry Run (`workflow_dispatch`)

Triggering the `release` workflow manually via `workflow_dispatch` on GitHub Actions validates cross-platform archive builds and native binary smoke tests before creating a tag:

- Runs `check`, the 7-platform build and smoke-test jobs (`build`, `linux`, `freebsd`), and `bundle` (producing the `verified-bundle` workflow artifact with all 7 archives and `SHA256SUMS`).
- Skips the nested `ci.yml` call (`if: github.event_name == 'push'`) and skips creating a draft GitHub Release (`if: github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')`).

## 3. Push the `vX.Y.Z` Tag

Once the release commit is on `origin/main`, tag that commit and push the tag:

```bash
git checkout main
git pull --ff-only origin main
git tag vX.Y.Z
git push origin vX.Y.Z
```

On `refs/tags/v*` pushes, the `check` job enforces two release invariants:

- The tag name must match `Cargo.toml` (`v{package.version}`).
- The tagged commit must be an ancestor of `origin/main` (`git merge-base --is-ancestor HEAD origin/main`).

In parallel with archive packaging, the `ci` job runs the full `.github/workflows/ci.yml` suite across `ubuntu-latest`, `windows-latest`, `windows-11-arm`, `macos-latest` (including an `x86_64-apple-darwin` target check), `debian-bookworm` (`rust:1.92.0-slim-bookworm` running tests as `nobody`), `alpine-amd64` and `alpine-arm64` (`rust:1.92.0-alpine3.23` running tests as `nobody`), and `freebsd-15.1-amd64` (`vmactions/freebsd-vm`).

## 4. Seven-Platform Archive Matrix and Smoke Tests

Each platform job compiles with `cargo build --release --locked` and runs `scripts/ci/package-release.py`:

| Platform ID | Job | Runner / Environment | Rust Target | Archive Name |
| :--- | :--- | :--- | :--- | :--- |
| `linux-amd64` | `linux` | `ubuntu-24.04` (`rust:1.92.0-alpine3.23`) | Host `x86_64` musl | `mcp-hookd-X.Y.Z-linux-amd64.tar.gz` |
| `linux-arm64` | `linux` | `ubuntu-24.04-arm` (`rust:1.92.0-alpine3.23`) | Host `aarch64` musl | `mcp-hookd-X.Y.Z-linux-arm64.tar.gz` |
| `macos-amd64` | `build` | `macos-15-intel` | `x86_64-apple-darwin` | `mcp-hookd-X.Y.Z-macos-amd64.tar.gz` |
| `macos-arm64` | `build` | `macos-15` | `aarch64-apple-darwin` | `mcp-hookd-X.Y.Z-macos-arm64.tar.gz` |
| `windows-amd64` | `build` | `windows-latest` | `x86_64-pc-windows-msvc` | `mcp-hookd-X.Y.Z-windows-amd64.zip` |
| `windows-arm64` | `build` | `windows-11-arm` | `aarch64-pc-windows-msvc` | `mcp-hookd-X.Y.Z-windows-arm64.zip` |
| `freebsd-amd64` | `freebsd` | `ubuntu-24.04` (`vmactions/freebsd-vm` 15.1) | Host `x86_64` FreeBSD | `mcp-hookd-X.Y.Z-freebsd-amd64.tar.gz` |

`scripts/ci/package-release.py` performs four checks on every platform runner:

1. Copies the `mcp-hookd` (or `mcp-hookd.exe`) binary, `LICENSE`, `NOTICE`, and `README.md` into `mcp-hookd-X.Y.Z-{platform}/` and creates the `.tar.gz` or `.zip` archive under `dist/`.
2. Unpacks the generated archive into a clean temporary directory.
3. Executes `mcp-hookd --version` from the unpacked directory and verifies the output equals `mcp-hookd X.Y.Z`.
4. Writes a minimal `hookd.json` smoke configuration and runs `mcp-hookd check --config` against the unpacked binary.

The `bundle` job then collects all `release-*` artifacts, verifies that the directory contains the exact set of 7 expected archives with no missing or unexpected files, generates `SHA256SUMS`, and uploads `verified-bundle`.

## 5. Verify and Publish the Draft Release

When `check`, `ci`, and `bundle` all succeed on a `vX.Y.Z` tag push, the `release` job queries the GitHub commits API to verify `refs/tags/vX.Y.Z` still points to the exact commit SHA recorded in `check`, then creates a draft GitHub Release titled `mcp-hookd X.Y.Z` (`--draft --verify-tag --generate-notes`) with all 7 archives and `SHA256SUMS`.

Before publishing the draft Release on GitHub:

1. Confirm all 7 platform archives plus `SHA256SUMS` are attached to the draft Release.
2. Download `SHA256SUMS` and at least one archive, verify `sha256sum -c SHA256SUMS --ignore-missing`, and check that the unpacked `mcp-hookd-X.Y.Z-{platform}/` directory contains the executable, `LICENSE`, `NOTICE`, and `README.md`.
3. Review the generated release notes and publish the draft Release.
