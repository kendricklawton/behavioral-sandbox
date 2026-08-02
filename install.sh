#!/bin/sh
# Install the ekvm sandbox engine from a release package.
# Canonical use (once releases are public):
#   curl -fsSL https://raw.githubusercontent.com/packsixfour/ekvm/main/install.sh | sh
# Also works from a local package (offline / pre-release testing):
#   EKVM_DIST_TARBALL=dist/ekvm-<ver>-x86_64-linux.tar.gz sh install.sh
# and from inside an extracted tarball (the copy packed next to bin/ekvm):
#   sh ./install.sh
# Knobs (env):
#   EKVM_REPO            GitHub repo to fetch from        (default packsixfour/ekvm)
#   EKVM_VERSION         release version, no leading v    (default: the latest release)
#   EKVM_DIST_TARBALL    local tarball, skips the network
#   EKVM_INSTALL_PREFIX  where the binary goes            (default ~/.local/bin)
#   EKVM_DATA_DIR        where the artifacts go           (default $XDG_DATA_HOME/ekvm or
#                                                           ~/.local/share/ekvm)
#   EKVM_RELEASE_PUBKEY  release public key (SPKI PEM: a file path, or the PEM text itself);
#                        overrides the key pinned in this script. Supplied out of band, it is a
#                        stronger trust anchor than the pin (which is same-origin with this script).
#   EKVM_INSECURE_SKIP_SIGNATURE=1  skip release-signature verification. NOT recommended; exists
#                        for releases predating the signing scheme and hosts without an
#                        Ed25519-capable openssl. Hash + manifest checks still run.
#   EKVM_NO_TOML=1       don't write ~/.ekvm.toml
# Integrity, outermost first: SHA256SUMS carries a detached ed25519 signature (SHA256SUMS.sig),
# verified with stock openssl against the pinned key BEFORE the manifest is trusted; the tarball
# is checked against SHA256SUMS; every extracted file against the package's MANIFEST.sha256.
# Downloads hard-fail without a signature; nothing installs unverified.
set -eu

REPO="${EKVM_REPO:-packsixfour/ekvm}"
PREFIX="${EKVM_INSTALL_PREFIX:-$HOME/.local/bin}"
DATA="${EKVM_DATA_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/ekvm}"
VERSION="${EKVM_VERSION:-}"
TARBALL="${EKVM_DIST_TARBALL:-}"

if [ -t 1 ]; then
    BOLD='\033[1m'
    GREEN='\033[32m'
    BLUE='\033[34m'
    YELLOW='\033[33m'
    RED='\033[31m'
    RESET='\033[0m'
else
    BOLD='' GREEN='' BLUE='' YELLOW='' RED='' RESET=''
fi

say()  { printf '%s\n' "$*"; }
info() { printf '%b==>%b %b%s%b\n' "$BLUE" "$RESET" "$BOLD" "$*" "$RESET"; }
ok()   { printf '%b  ✓%b %s\n' "$GREEN" "$RESET" "$*"; }
warn() { printf '%b  !%b %s\n' "$YELLOW" "$RESET" "$*"; }
fail() { printf '%binstall.sh: error:%b %s\n' "$RED" "$RESET" "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "missing required tool: $1"; }

# Whether the filesystem holding $2 is mounted with flag $1 (`nodev` makes the jailer's chroot
# /dev/kvm inert; `noexec` refuses the exec of its firecracker copy), mirroring the detector in
# crates/engine/src/doctor.rs. Uses findmnt (util-linux, present on every systemd host); a missing
# findmnt reads as "flag absent" so we never guess wrong and pin a scratch dir the operator didn't
# ask for.
has_mount_flag() {
    command -v findmnt >/dev/null 2>&1 || return 1
    case ",$(findmnt -no OPTIONS -T "$2" 2>/dev/null)," in
        *,"$1",*) return 0 ;;
        *)        return 1 ;;
    esac
}

# Either flag that makes a jailed boot fail from a chroot under $1.
blocks_jail() {
    has_mount_flag nodev "$1" || has_mount_flag noexec "$1"
}

[ "$(uname -s)" = "Linux" ]  || fail "the engine is Linux-only (it needs KVM)"
[ "$(uname -m)" = "x86_64" ] || fail "the supported architecture is x86_64; this host is $(uname -m)"
need tar
need sha256sum

SKIP_SIG="${EKVM_INSECURE_SKIP_SIGNATURE:-}"

# The pinned release public key. Trust framing, stated honestly: this pin is same-origin with the
# script (both live in the repo), so it defeats a tampered *release asset*, not a compromised
# repo; EKVM_RELEASE_PUBKEY supplied out of band is the stronger anchor. The PIN_EOF markers are
# load-bearing: a dist test asserts this block is byte-identical to the repo's release-key.pem,
# so the key xtask signs against and the key installers trust can never drift.
write_pinned_release_key() {
    cat > "$1" <<'PIN_EOF'
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAi7i9h0nOfdhTwRpLC/HgDdmMkRhFrviVL2kET+fWoUU=
-----END PUBLIC KEY-----
PIN_EOF
}

# Resolve the public key to verify against into RELEASE_PUB (a file path). $1 is a writable dir
# for materializing the pinned or inline PEM.
resolve_release_pub() {
    case "${EKVM_RELEASE_PUBKEY:-}" in
        "")
            write_pinned_release_key "$1/release-key.pem"
            RELEASE_PUB="$1/release-key.pem" ;;
        "-----BEGIN"*)
            printf '%s\n' "$EKVM_RELEASE_PUBKEY" > "$1/release-key.pem"
            RELEASE_PUB="$1/release-key.pem" ;;
        *)
            [ -f "$EKVM_RELEASE_PUBKEY" ] || fail "EKVM_RELEASE_PUBKEY is not a file or a PEM block: $EKVM_RELEASE_PUBKEY"
            RELEASE_PUB="$EKVM_RELEASE_PUBKEY" ;;
    esac
}

# Verify the detached ed25519 signature ($2) over the manifest's exact bytes ($1) with the host's
# own openssl, never a binary from the artifact under test. Fail closed on BOTH the exit status
# and the output string: openssl pkeyutl has a known history of exit-status bugs across versions,
# and the success line is not localized.
verify_release_sig() {
    VOUT=$(openssl pkeyutl -verify -pubin -inkey "$RELEASE_PUB" -rawin -in "$1" -sigfile "$2" 2>&1) \
        || fail "release signature verification failed (needs openssl >= 1.1.1 with Ed25519; EKVM_INSECURE_SKIP_SIGNATURE=1 overrides): $VOUT"
    case "$VOUT" in
        *"Signature Verified Successfully"*)
            ok "release signature verified (detached ed25519, $(basename -- "$RELEASE_PUB"))" ;;
        *)
            fail "unexpected openssl verify output, treating as failure: $VOUT" ;;
    esac
}

TMP=""
cleanup() { [ -n "$TMP" ] && rm -rf "$TMP"; }
trap cleanup EXIT INT TERM

# Where this script itself lives: inside an extracted package it sits next to bin/ekvm, and then
# the surrounding stage IS the install source (no download, no re-extract).
# `CDPATH=` neutralises a user's CDPATH for this one `cd`, which would otherwise resolve a relative
# path somewhere else entirely and echo where it went. shellcheck reads the empty assignment as a
# typo; it is the intended POSIX idiom.
# The `|| true` is the else-branch on purpose: an unresolvable `$0` leaves SCRIPT_DIR empty, which
# the next block tests for. shellcheck warns because that shape is usually a mistaken if-then-else.
# shellcheck disable=SC1007,SC2015
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd || true)

STAGE=""
if [ -n "$SCRIPT_DIR" ] && [ -x "$SCRIPT_DIR/bin/ekvm" ] && [ -f "$SCRIPT_DIR/MANIFEST.sha256" ]; then
    info "Installing from extracted package at $SCRIPT_DIR"
    # No release signature reaches this mode (the manifest lives inside the artifact it attests):
    # self-attested by design; say so rather than imply more.
    warn "extracted-package mode: the per-file manifest is the only integrity check here"
    STAGE="$SCRIPT_DIR"
else
    if [ -z "$TARBALL" ]; then
        need curl
        [ -n "$SKIP_SIG" ] || need openssl
        if [ -z "$VERSION" ]; then
            VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
                | sed -n 's/^ *"tag_name": *"v\{0,1\}\([^"]*\)".*/\1/p' | head -n1)
            [ -n "$VERSION" ] || fail "could not resolve latest release of $REPO (private repo or no release yet?): set EKVM_VERSION or EKVM_DIST_TARBALL"
        fi
        ASSET="ekvm-$VERSION-x86_64-linux.tar.gz"
        BASE="https://github.com/$REPO/releases/download/v$VERSION"
        TMP=$(mktemp -d)
        info "Downloading $ASSET from $REPO v$VERSION"
        curl -fsSL -o "$TMP/$ASSET" "$BASE/$ASSET"    || fail "download failed: $BASE/$ASSET"
        curl -fsSL -o "$TMP/SHA256SUMS" "$BASE/SHA256SUMS" || fail "download failed: $BASE/SHA256SUMS"
        # Signature first: SHA256SUMS is trusted only after its detached signature checks, and a
        # missing .sig is a hard fail, never a silent downgrade.
        if [ -z "$SKIP_SIG" ]; then
            curl -fsSL -o "$TMP/SHA256SUMS.sig" "$BASE/SHA256SUMS.sig" \
                || fail "download failed: $BASE/SHA256SUMS.sig (a release predating the signing scheme installs only with EKVM_INSECURE_SKIP_SIGNATURE=1)"
            resolve_release_pub "$TMP"
            verify_release_sig "$TMP/SHA256SUMS" "$TMP/SHA256SUMS.sig"
        else
            warn "EKVM_INSECURE_SKIP_SIGNATURE=1: release signature NOT verified; authenticity rests on the download channel alone"
        fi
        ( cd "$TMP" && grep "  $ASSET\$" SHA256SUMS | sha256sum -c - >/dev/null ) \
            || fail "sha256 verification of $ASSET failed"
        ok "sha256 verified against SHA256SUMS"
        TARBALL="$TMP/$ASSET"
    else
        [ -f "$TARBALL" ] || fail "EKVM_DIST_TARBALL not found: $TARBALL"
        TMP=$(mktemp -d)
        SUMS=$(dirname -- "$TARBALL")/SHA256SUMS
        SUMS_SIG=$(dirname -- "$TARBALL")/SHA256SUMS.sig
        if [ -f "$SUMS" ]; then
            if [ -z "$SKIP_SIG" ] && [ -f "$SUMS_SIG" ]; then
                need openssl
                resolve_release_pub "$TMP"
                verify_release_sig "$SUMS" "$SUMS_SIG"
            else
                warn "no verified release signature next to tarball (dev dists are unsigned); relying on sha256 + manifest"
            fi
            ( cd "$(dirname -- "$TARBALL")" && grep "  $(basename -- "$TARBALL")\$" SHA256SUMS | sha256sum -c - >/dev/null ) \
                || fail "sha256 verification of $TARBALL against $SUMS failed"
            ok "sha256 verified against $SUMS"
        else
            warn "no SHA256SUMS next to tarball; relying on inner manifest only"
        fi
    fi

    tar -C "$TMP" -xzf "$TARBALL" || fail "extract failed: $TARBALL"
    STAGE=$(find "$TMP" -mindepth 1 -maxdepth 1 -type d -name 'ekvm-*' | head -n1)
    [ -n "$STAGE" ] || fail "no ekvm-* directory inside tarball"
fi

# Every file must match the package manifest before anything is copied into place.
( cd "$STAGE" && grep -v '  MANIFEST\.sha256$' MANIFEST.sha256 | sha256sum --quiet -c - ) \
    || fail "package manifest verification failed"
ok "package manifest verified ($(wc -l < "$STAGE/MANIFEST.sha256") files)"

mkdir -p "$PREFIX" "$DATA"
install -m 0755 "$STAGE/bin/ekvm" "$PREFIX/ekvm"
ok "installed $PREFIX/ekvm"
for f in vmlinux rootfs-guest.ext4 probes; do
    install -m 0644 "$STAGE/share/ekvm/$f" "$DATA/$f"
    ok "installed $DATA/$f"
done

# A starter config, written only if none exists (the engine's own nearest-up-from-cwd discovery
# finds ~/.ekvm.toml for anything under $HOME). Never overwrites: your config is yours.
if [ -z "${EKVM_NO_TOML:-}" ] && [ ! -e "$HOME/.ekvm.toml" ]; then
    # The jailed default (real root) builds a chroot under the scratch dir (a mknod'd /dev/kvm, an
    # exec'd firecracker copy); on a host whose default base (/tmp) is `nodev` (every systemd
    # default) or `noexec` (hardened baselines) the boot fails ScratchDirNodev/ScratchDirNoexec.
    # Pin scratch_dir off both so the first `sudo ekvm run` works (P20.16a); skipped when $HOME is
    # also restricted, which pinning wouldn't fix. Kept short (~/.ekvm, not a deep dir under the
    # data dir): the jailer nests the per-VM dir name twice in the API socket path, which must fit
    # sun_path (~108 bytes).
    SCRATCH=""
    if blocks_jail /tmp && ! blocks_jail "$HOME"; then
        SCRATCH="$HOME/.ekvm"
        mkdir -p "$SCRATCH"
    fi
    {
        say '# Written by install.sh; the engine reads the nearest .ekvm.toml walking up from the cwd.'
        printf 'kernel = "%s"\n' "$DATA/vmlinux"
        printf 'rootfs = "%s"\n' "$DATA/rootfs-guest.ext4"
        if [ -n "$SCRATCH" ]; then
            printf '# /tmp is nodev/noexec on this host; a scratch dir off both so the jailed default boots.\nscratch_dir = "%s"\n' "$SCRATCH"
        fi
    } > "$HOME/.ekvm.toml"
    if [ -n "$SCRATCH" ]; then
        ok "wrote $HOME/.ekvm.toml (kernel + rootfs paths, and scratch_dir: /tmp is nodev/noexec here)"
    else
        ok "wrote $HOME/.ekvm.toml (kernel + rootfs paths)"
    fi
fi

say ""
info "Installation complete! Next steps:"
case ":$PATH:" in
    *":$PREFIX:"*) ;;
    *) say "  - add $PREFIX to your PATH:  export PATH=\"$PREFIX:\$PATH\"" ;;
esac
# The engine finds the eBPF object under the default data dir on its own, so only a *relocated*
# install still needs the override spelled out.
if [ "$DATA" != "${XDG_DATA_HOME:-$HOME/.local/share}/ekvm" ]; then
    say "  - non-default data dir, so observability needs: export EKVM_PROBES_OBJECT=\"$DATA/probes\""
fi
# Keep in step with PINNED_FIRECRACKER_SHA256 in crates/engine/src/doctor.rs.
FC_PIN1="2fd0171309af7e24cf8dafc8a6f921c1434c49b5f9349bb996b7ed0a4deb8aa7"
# The release the printed commands below install; keep in step with PINNED_FC_VERSION in
# crates/engine/src/spawn.rs (a dist test compares the series so the two cannot drift).
FC_VER="v1.16.1"
FC_BIN=$(command -v firecracker 2>/dev/null || true)
if [ -n "$FC_BIN" ]; then
    FC_HASH=$(sha256sum "$FC_BIN" 2>/dev/null | awk '{print $1}')
    if [ "$FC_HASH" = "$FC_PIN1" ]; then
        ok "Firecracker binary on PATH verified ($FC_BIN, sha256 ok)"
    else
        warn "Firecracker binary on PATH ($FC_BIN, sha256 ${FC_HASH:-unknown}); pinned $FC_VER release sha256 is $FC_PIN1"
    fi
else
    # Upstream ships versioned binary names inside a versioned directory; without the exact
    # commands an operator improvises the download, the rename, and which file the sha covers.
    warn "Firecracker is not bundled: install firecracker + jailer $FC_VER on PATH:"
    say "      curl -LO https://github.com/firecracker-microvm/firecracker/releases/download/$FC_VER/firecracker-$FC_VER-x86_64.tgz"
    say "      tar xzf firecracker-$FC_VER-x86_64.tgz"
    say "      install release-$FC_VER-x86_64/firecracker-$FC_VER-x86_64 \"$PREFIX/firecracker\""
    say "      install release-$FC_VER-x86_64/jailer-$FC_VER-x86_64 \"$PREFIX/jailer\""
    say "      (sha256 of the firecracker binary, not the tarball: $FC_PIN1)"
fi
say "  - check the host; it prints the exact run command for this host:"
say "      ekvm doctor"
# Unjailed first: it works in the shell reading this, while sudo needs rights a fresh operator
# account may lack. The sudo form re-injects the caller's PATH: sudoers secure_path overrides
# PATH even under -E, hiding both a user-local ekvm and the firecracker/jailer binaries the
# engine itself resolves.
say "  - then run something (the default jails the VMM, which needs real root):"
say "      ekvm run --unjailed -- echo hello                 # no root needed: still behind KVM, VMM unconfined"
say "      sudo -E env \"PATH=\$PATH\" ekvm run -- echo hello   # jailed, the supported posture"
