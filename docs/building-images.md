# Building guest images

Behavioral Sandbox (BSX) uses minimal Alpine Linux guest images containing only the components required to run workloads and the static guest agent. Guest rootfs trees are built reproducibly without root privileges.

## Building rootfs trees (`cargo xtask build-rootfs`)

Image builds are orchestrated through `cargo xtask build-rootfs`.

```console
cargo xtask build-rootfs               # minimal guest image (artifacts/rootfs-guest)
cargo xtask build-rootfs --desktop     # desktop image (artifacts/rootfs-desktop)
cargo xtask build-rootfs --arch aarch64 # target another architecture
```

### Unprivileged rootfs assembly

Guest rootfs trees are constructed on Linux without requiring `root` or Docker:
- **`apk.static`**: Alpine's static package manager fetches and extracts `.apk` packages into the staged tree (`--no-scripts`).
- **`fakeroot`**: Wraps file creation so files in `artifacts/rootfs-guest` are owned by `uid 0` (root) in the filesystem metadata rather than the builder's user ID. This ensures two builds on different machines produce identical directory trees and hashes.
- **Cross-architecture builds**: Because package installation extracts static archives without executing guest scripts, a Linux builder of either architecture (`x86_64` or `aarch64`) can assemble an image for the other architecture.

## Image closures

### Minimal guest closure (`artifacts/rootfs-guest`)

The default sandbox image includes:
- Alpine Linux base packages (musl libc, busybox, standard POSIX utilities).
- Python 3 runtime for script execution.
- `guest-agent`: The static musl Rust binary baked at `/usr/local/bin/guest-agent`.

### Desktop guest closure (`artifacts/rootfs-desktop`)

The desktop sandbox image adds graphical and terminal session support for `--display` runs:
- **`cage`**: A minimal Wayland kiosk compositor based on wlroots.
- **`foot`**: A fast, lightweight Wayland terminal emulator.
- **`seatd` & `udev`**: Seat management and device node creation inside the guest.
- **`bsx-session`**: A helper session supervisor that launches `seatd`, starts `cage`, and runs `foot` in a Wayland kiosk session.

## Reproducibility and lockfiles

To ensure deterministic builds across hosts, package closures are locked:
- **Lockfiles**: `xtask/rootfs-packages.x86_64.lock` records the exact package versions and SHA-256 hashes (with per-architecture lockfiles generated on build).
- **Verification**: `cargo xtask build-rootfs --verify` builds the image twice, asserting that the staged trees match byte-for-byte and that package versions match the lockfile.
- **Updating pins**: `cargo xtask build-rootfs --update-lock` re-pins the package closure when Alpine package versions update upstream.

## Offline vendoring (`cargo xtask vendor`)

For offline or air-gapped dev environments, `cargo xtask vendor` downloads all sha-pinned upstream archives (Alpine base tarballs, `apk.static`, and `.apk` package closures) into a local `vendor/` mirror directory.

- `cargo xtask vendor --verify` checks the local vendor mirror against its hash manifest without making network calls.
