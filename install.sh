#!/bin/sh
# Install the ebpf-kvm-engine sandbox engine from a release package (decision 035).
#
# Canonical use (once releases are public):
#   curl -fsSL https://raw.githubusercontent.com/packsixfour/ebpf-kvm-engine/main/install.sh | sh
#
# Also works from a local package (offline / pre-release testing):
#   EBPF_KVM_ENGINE_DIST_TARBALL=dist/ebpf-kvm-engine-<ver>-x86_64-linux.tar.gz sh install.sh
# and from inside an extracted tarball (the copy packed next to bin/ebpf-kvm-engine):
#   sh ./install.sh
#
# Knobs (env):
#   EBPF_KVM_ENGINE_REPO            GitHub repo to fetch from        (default packsixfour/ebpf-kvm-engine)
#   EBPF_KVM_ENGINE_VERSION         release version, no leading v    (default: the latest release)
#   EBPF_KVM_ENGINE_DIST_TARBALL    local tarball, skips the network
#   EBPF_KVM_ENGINE_INSTALL_PREFIX  where the binary goes            (default ~/.local/bin)
#   EBPF_KVM_ENGINE_DATA_DIR        where the artifacts go           (default $XDG_DATA_HOME/ebpf-kvm-engine or
#                                                           ~/.local/share/ebpf-kvm-engine)
#   EBPF_KVM_ENGINE_NO_TOML=1       don't write ~/.ebpf-kvm-engine.toml
#
# The sha256 is the contract at both layers: the tarball against SHA256SUMS (when available), and
# every extracted file against the package's MANIFEST.sha256. Nothing installs unverified.
set -eu

REPO="${EBPF_KVM_ENGINE_REPO:-packsixfour/ebpf-kvm-engine}"
PREFIX="${EBPF_KVM_ENGINE_INSTALL_PREFIX:-$HOME/.local/bin}"
DATA="${EBPF_KVM_ENGINE_DATA_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/ebpf-kvm-engine}"
VERSION="${EBPF_KVM_ENGINE_VERSION:-}"
TARBALL="${EBPF_KVM_ENGINE_DIST_TARBALL:-}"

say()  { printf '%s\n' "$*"; }
fail() { printf 'install.sh: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "missing required tool: $1"; }

# Whether the filesystem holding $1 is mounted `nodev` (device nodes there are inert, so the jailer's
# chroot /dev/kvm can't be opened), mirroring the detector in crates/vmm/src/doctor.rs. Uses findmnt
# (util-linux, present on every systemd host); a missing findmnt reads as "not nodev" so we never
# guess wrong and pin a scratch dir the operator didn't ask for.
is_nodev() {
    command -v findmnt >/dev/null 2>&1 || return 1
    case ",$(findmnt -no OPTIONS -T "$1" 2>/dev/null)," in
        *,nodev,*) return 0 ;;
        *)         return 1 ;;
    esac
}

[ "$(uname -s)" = "Linux" ]  || fail "the engine is Linux-only (it needs KVM)"
[ "$(uname -m)" = "x86_64" ] || fail "the supported architecture is x86_64; this host is $(uname -m)"
need tar
need sha256sum

TMP=""
cleanup() { [ -n "$TMP" ] && rm -rf "$TMP"; }
trap cleanup EXIT INT TERM

# Where this script itself lives: inside an extracted package it sits next to bin/ebpf-kvm-engine, and then
# the surrounding stage IS the install source (no download, no re-extract).
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd || true)

STAGE=""
if [ -n "$SCRIPT_DIR" ] && [ -x "$SCRIPT_DIR/bin/ebpf-kvm-engine" ] && [ -f "$SCRIPT_DIR/MANIFEST.sha256" ]; then
    say "installing from the extracted package at $SCRIPT_DIR"
    STAGE="$SCRIPT_DIR"
else
    if [ -z "$TARBALL" ]; then
        need curl
        if [ -z "$VERSION" ]; then
            VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
                | sed -n 's/^ *"tag_name": *"v\{0,1\}\([^"]*\)".*/\1/p' | head -n1)
            [ -n "$VERSION" ] || fail "could not resolve the latest release of $REPO (private repo, or no release yet?) — set EBPF_KVM_ENGINE_VERSION or EBPF_KVM_ENGINE_DIST_TARBALL"
        fi
        ASSET="ebpf-kvm-engine-$VERSION-x86_64-linux.tar.gz"
        BASE="https://github.com/$REPO/releases/download/v$VERSION"
        TMP=$(mktemp -d)
        say "downloading $ASSET from $REPO v$VERSION"
        curl -fsSL -o "$TMP/$ASSET" "$BASE/$ASSET"    || fail "download failed: $BASE/$ASSET"
        curl -fsSL -o "$TMP/SHA256SUMS" "$BASE/SHA256SUMS" || fail "download failed: $BASE/SHA256SUMS"
        curl -fsSL -o "$TMP/SHA256SUMS.sig" "$BASE/SHA256SUMS.sig" 2>/dev/null || true
        ( cd "$TMP" && grep "  $ASSET\$" SHA256SUMS | sha256sum -c - >/dev/null ) \
            || fail "sha256 verification of $ASSET failed"
        say "sha256 verified against SHA256SUMS"
        TARBALL="$TMP/$ASSET"
    else
        [ -f "$TARBALL" ] || fail "EBPF_KVM_ENGINE_DIST_TARBALL not found: $TARBALL"
        SUMS=$(dirname -- "$TARBALL")/SHA256SUMS
        if [ -f "$SUMS" ]; then
            ( cd "$(dirname -- "$TARBALL")" && grep "  $(basename -- "$TARBALL")\$" SHA256SUMS | sha256sum -c - >/dev/null ) \
                || fail "sha256 verification of $TARBALL against $SUMS failed"
            say "sha256 verified against $SUMS"
        else
            say "note: no SHA256SUMS next to the tarball; relying on the inner manifest only"
        fi
        [ -n "$TMP" ] || TMP=$(mktemp -d)
    fi

    tar -C "$TMP" -xzf "$TARBALL" || fail "extract failed: $TARBALL"
    STAGE=$(find "$TMP" -mindepth 1 -maxdepth 1 -type d -name 'ebpf-kvm-engine-*' | head -n1)
    [ -n "$STAGE" ] || fail "no ebpf-kvm-engine-* directory inside the tarball"
fi

# Every file must match the package manifest before anything is copied into place.
( cd "$STAGE" && grep -v '  MANIFEST\.sha256$' MANIFEST.sha256 | sha256sum --quiet -c - ) \
    || fail "package manifest verification failed"
say "package manifest verified ($(wc -l < "$STAGE/MANIFEST.sha256") files)"

# Verify the release manifest ed25519 signature if SHA256SUMS.sig is present (decision 040).
SUMS_SIG=""
if [ -n "$TMP" ] && [ -f "$TMP/SHA256SUMS.sig" ]; then
    SUMS_SIG="$TMP/SHA256SUMS.sig"
elif [ -n "$TARBALL" ] && [ -f "$(dirname -- "$TARBALL")/SHA256SUMS.sig" ]; then
    SUMS_SIG="$(dirname -- "$TARBALL")/SHA256SUMS.sig"
fi

if [ -n "$SUMS_SIG" ]; then
    PUBKEY="${EBPF_KVM_ENGINE_PUBKEY:-${EBPF_KVM_ENGINE_TRUSTED_KEYS:-}}"
    if [ -n "$PUBKEY" ]; then
        "$STAGE/bin/ebpf-kvm-engine" verify "$SUMS_SIG" --key "$PUBKEY" >/dev/null \
            || fail "ed25519 signature verification of SHA256SUMS.sig failed for key $PUBKEY"
        say "ed25519 signature verified against trusted public key"
    else
        SIG_KEY=$(grep -o '"key_id":"[^"]*"' "$SUMS_SIG" 2>/dev/null | head -n1 | cut -d'"' -f4 || true)
        if [ -n "$SIG_KEY" ]; then
            say "note: SHA256SUMS is ed25519-signed (key_id ${SIG_KEY:0:16}...); set EBPF_KVM_ENGINE_PUBKEY to verify"
        fi
    fi
fi

mkdir -p "$PREFIX" "$DATA"
install -m 0755 "$STAGE/bin/ebpf-kvm-engine" "$PREFIX/ebpf-kvm-engine"
say "installed $PREFIX/ebpf-kvm-engine"
for f in vmlinux rootfs-guest.ext4 probes; do
    install -m 0644 "$STAGE/share/ebpf-kvm-engine/$f" "$DATA/$f"
    say "installed $DATA/$f"
done

# A starter config, written only if none exists (the engine's own nearest-up-from-cwd discovery
# finds ~/.ebpf-kvm-engine.toml for anything under $HOME). Never overwrites: your config is yours.
if [ -z "${EBPF_KVM_ENGINE_NO_TOML:-}" ] && [ ! -e "$HOME/.ebpf-kvm-engine.toml" ]; then
    # The jailed default (real root) mknods /dev/kvm inside a chroot under the scratch dir; on a host
    # whose default base (/tmp) is `nodev` (every systemd default) those nodes are inert and the boot
    # fails ScratchDirNodev. Pin scratch_dir off nodev so the first `sudo ebpf-kvm-engine run` works
    # (P20.16a); skipped when $HOME is also nodev, which pinning wouldn't fix. Kept short (~/.ekvm, not
    # a deep dir under the data dir): the jailer nests the per-VM dir name twice in the API socket
    # path, which must fit sun_path (~108 bytes).
    SCRATCH=""
    if is_nodev /tmp && ! is_nodev "$HOME"; then
        SCRATCH="$HOME/.ekvm"
        mkdir -p "$SCRATCH"
    fi
    {
        say '# Written by install.sh; the engine reads the nearest .ebpf-kvm-engine.toml walking up from the cwd.'
        printf 'kernel = "%s"\n' "$DATA/vmlinux"
        printf 'rootfs = "%s"\n' "$DATA/rootfs-guest.ext4"
        if [ -n "$SCRATCH" ]; then
            printf '# /tmp is nodev on this host; a non-nodev scratch dir so the jailed default boots.\nscratch_dir = "%s"\n' "$SCRATCH"
        fi
    } > "$HOME/.ebpf-kvm-engine.toml"
    if [ -n "$SCRATCH" ]; then
        say "wrote $HOME/.ebpf-kvm-engine.toml (kernel + rootfs paths, and scratch_dir: /tmp is nodev here)"
    else
        say "wrote $HOME/.ebpf-kvm-engine.toml (kernel + rootfs paths)"
    fi
fi

say ""
say "done. Next steps:"
case ":$PATH:" in
    *":$PREFIX:"*) ;;
    *) say "  - add $PREFIX to your PATH" ;;
esac
# The engine finds the eBPF object under the default data dir on its own, so only a *relocated*
# install still needs the override spelled out.
if [ "$DATA" != "${XDG_DATA_HOME:-$HOME/.local/share}/ebpf-kvm-engine" ]; then
    say "  - non-default data dir, so observability needs: export EBPF_KVM_ENGINE_PROBES_OBJECT=\"$DATA/probes\""
fi
FC_PIN1="c8c2496f8786da12b7bbfbc5060af3573c22baa2e5f79ff6ee084993642bbe01"
FC_PIN2="809789cd7567b77b20edec9b301953338c2023c37ea63db82d46cb61773ad511"
FC_BIN=$(command -v firecracker 2>/dev/null || true)
if [ -n "$FC_BIN" ]; then
    FC_HASH=$(sha256sum "$FC_BIN" 2>/dev/null | awk '{print $1}')
    if [ "$FC_HASH" = "$FC_PIN1" ] || [ "$FC_HASH" = "$FC_PIN2" ]; then
        say "  - Firecracker binary on PATH verified ($FC_BIN, sha256 ok)"
    else
        say "  - Firecracker binary on PATH ($FC_BIN, sha256 ${FC_HASH:-unknown}); pinned v1.9 release sha256 is $FC_PIN1"
    fi
else
    say "  - Firecracker is not bundled: install firecracker + jailer (v1.9) on PATH, from"
    say "      https://github.com/firecracker-microvm/firecracker/releases/tag/v1.9.0 (sha256: $FC_PIN1)"
fi
say "  - check the host; it prints the exact run command for this host:"
say "      ebpf-kvm-engine doctor"
say "  - then run something (the default jails the VMM, which needs real root):"
say "      sudo -E ebpf-kvm-engine run -- echo hello       # jailed, the supported posture"
say "      ebpf-kvm-engine run --unjailed -- echo hello    # no root: still behind KVM, VMM unconfined"
