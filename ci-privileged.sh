#!/bin/sh
# One-line privileged gate (P20.17b). The manual invocation stacks three env concerns:
#
#   sudo -E env "PATH=$PATH" CARGO_TARGET_DIR=… EKVM_SCRATCH_DIR=… cargo xtask ci-privileged
#
# because `sudo` drops rustup's cargo from PATH, a root build must stay out of ./target, and /tmp is
# `nodev` on a systemd host. This collapses them into `sudo -E ./ci-privileged.sh`.
#
#   - CARGO_TARGET_DIR keeps root-owned build artifacts out of ./target (they block later non-root builds)
#   - EKVM_SCRATCH_DIR points scratch off a `nodev`/`noexec` /tmp so the jailed-boot tests' chroot works
#   - PATH restores rustup's cargo, which sudo strips from a root shell
#
# xtask cannot do this itself: the outer `cargo run` that builds xtask writes to ./target as root
# *before* any xtask code runs, so the redirect must be set before cargo starts (xtask can only
# refuse; see the P20.17a pre-checks and docs/contributing-ci.md). Run it from the repo root.
#
# Each of the three honours a value you already exported, so override any by setting it first.
set -eu

# rustup installs cargo under the invoking user's home. `sudo -E` preserves $HOME, but a distro with
# `secure_path` set (or a plain `sudo`) resets PATH to root's, so resolve cargo explicitly when it's
# not already on PATH, falling back to $SUDO_USER's home.
if ! command -v cargo >/dev/null 2>&1; then
    cargo_bin="$HOME/.cargo/bin"
    if [ ! -x "$cargo_bin/cargo" ] && [ -n "${SUDO_USER:-}" ]; then
        cargo_bin="$(getent passwd "$SUDO_USER" | cut -d: -f6)/.cargo/bin"
    fi
    if [ ! -x "$cargo_bin/cargo" ]; then
        # The backticks are literal punctuation in the message, not a substitution.
        # shellcheck disable=SC2016
        printf 'ci-privileged.sh: cannot find cargo — run under `sudo -E`, or install rustup for root\n' >&2
        exit 1
    fi
    PATH="$cargo_bin:$PATH"
    export PATH
fi

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$PWD/target-privileged}"
# Short by design: the jailer nests this dir name twice in the API socket path, which must fit
# sun_path (~108 bytes), so /var/tmp/ekvm, not a long /var/tmp/ekvm-scratch.
export EKVM_SCRATCH_DIR="${EKVM_SCRATCH_DIR:-/var/tmp/ekvm}"
mkdir -p "$EKVM_SCRATCH_DIR"

exec cargo xtask ci-privileged "$@"
