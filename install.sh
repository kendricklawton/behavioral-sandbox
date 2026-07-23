#!/bin/sh
# Install the agent sandbox engine from a release package (decision 035).
#
# Canonical use (once releases are public):
#   curl -fsSL https://raw.githubusercontent.com/k-henry-org/agent/main/install.sh | sh
#
# Also works from a local package (offline / pre-release testing):
#   AGENT_DIST_TARBALL=dist/agent-<ver>-x86_64-linux.tar.gz sh install.sh
# and from inside an extracted tarball (the copy packed next to bin/agent):
#   sh ./install.sh
#
# Knobs (env):
#   AGENT_REPO            GitHub repo to fetch from        (default k-henry-org/agent)
#   AGENT_VERSION         release version, no leading v    (default: the latest release)
#   AGENT_DIST_TARBALL    local tarball, skips the network
#   AGENT_INSTALL_PREFIX  where the binary goes            (default ~/.local/bin)
#   AGENT_DATA_DIR        where the artifacts go           (default $XDG_DATA_HOME/agent or
#                                                           ~/.local/share/agent)
#   AGENT_NO_TOML=1       don't write ~/.agent.toml
#
# The sha256 is the contract at both layers: the tarball against SHA256SUMS (when available), and
# every extracted file against the package's MANIFEST.sha256. Nothing installs unverified.
set -eu

REPO="${AGENT_REPO:-k-henry-org/agent}"
PREFIX="${AGENT_INSTALL_PREFIX:-$HOME/.local/bin}"
DATA="${AGENT_DATA_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/agent}"
VERSION="${AGENT_VERSION:-}"
TARBALL="${AGENT_DIST_TARBALL:-}"

say()  { printf '%s\n' "$*"; }
fail() { printf 'install.sh: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "missing required tool: $1"; }

[ "$(uname -s)" = "Linux" ]  || fail "the engine is Linux-only (it needs KVM)"
[ "$(uname -m)" = "x86_64" ] || fail "the supported architecture is x86_64; this host is $(uname -m)"
need tar
need sha256sum

TMP=""
cleanup() { [ -n "$TMP" ] && rm -rf "$TMP"; }
trap cleanup EXIT INT TERM

# Where this script itself lives: inside an extracted package it sits next to bin/agent, and then
# the surrounding stage IS the install source (no download, no re-extract).
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd || true)

STAGE=""
if [ -n "$SCRIPT_DIR" ] && [ -x "$SCRIPT_DIR/bin/agent" ] && [ -f "$SCRIPT_DIR/MANIFEST.sha256" ]; then
    say "installing from the extracted package at $SCRIPT_DIR"
    STAGE="$SCRIPT_DIR"
else
    if [ -z "$TARBALL" ]; then
        need curl
        if [ -z "$VERSION" ]; then
            VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
                | sed -n 's/^ *"tag_name": *"v\{0,1\}\([^"]*\)".*/\1/p' | head -n1)
            [ -n "$VERSION" ] || fail "could not resolve the latest release of $REPO (private repo, or no release yet?) — set AGENT_VERSION or AGENT_DIST_TARBALL"
        fi
        ASSET="agent-$VERSION-x86_64-linux.tar.gz"
        BASE="https://github.com/$REPO/releases/download/v$VERSION"
        TMP=$(mktemp -d)
        say "downloading $ASSET from $REPO v$VERSION"
        curl -fsSL -o "$TMP/$ASSET" "$BASE/$ASSET"    || fail "download failed: $BASE/$ASSET"
        curl -fsSL -o "$TMP/SHA256SUMS" "$BASE/SHA256SUMS" || fail "download failed: $BASE/SHA256SUMS"
        ( cd "$TMP" && grep "  $ASSET\$" SHA256SUMS | sha256sum -c - >/dev/null ) \
            || fail "sha256 verification of $ASSET failed"
        say "sha256 verified against SHA256SUMS"
        TARBALL="$TMP/$ASSET"
    else
        [ -f "$TARBALL" ] || fail "AGENT_DIST_TARBALL not found: $TARBALL"
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
    STAGE=$(find "$TMP" -mindepth 1 -maxdepth 1 -type d -name 'agent-*' | head -n1)
    [ -n "$STAGE" ] || fail "no agent-* directory inside the tarball"
fi

# Every file must match the package manifest before anything is copied into place.
( cd "$STAGE" && grep -v '  MANIFEST\.sha256$' MANIFEST.sha256 | sha256sum --quiet -c - ) \
    || fail "package manifest verification failed"
say "package manifest verified ($(wc -l < "$STAGE/MANIFEST.sha256") files)"

mkdir -p "$PREFIX" "$DATA"
install -m 0755 "$STAGE/bin/agent" "$PREFIX/agent"
say "installed $PREFIX/agent"
for f in vmlinux rootfs-agent.ext4 probes; do
    install -m 0644 "$STAGE/share/agent/$f" "$DATA/$f"
    say "installed $DATA/$f"
done

# A starter config, written only if none exists (the engine's own nearest-up-from-cwd discovery
# finds ~/.agent.toml for anything under $HOME). Never overwrites: your config is yours.
if [ -z "${AGENT_NO_TOML:-}" ] && [ ! -e "$HOME/.agent.toml" ]; then
    cat > "$HOME/.agent.toml" <<EOF
# Written by install.sh; the engine reads the nearest .agent.toml walking up from the cwd.
kernel = "$DATA/vmlinux"
rootfs = "$DATA/rootfs-agent.ext4"
EOF
    say "wrote $HOME/.agent.toml (kernel + rootfs paths)"
fi

say ""
say "done. Next steps:"
case ":$PATH:" in
    *":$PREFIX:"*) ;;
    *) say "  - add $PREFIX to your PATH" ;;
esac
# The engine finds the eBPF object under the default data dir on its own, so only a *relocated*
# install still needs the override spelled out.
if [ "$DATA" != "${XDG_DATA_HOME:-$HOME/.local/share}/agent" ]; then
    say "  - non-default data dir, so observability needs: export AGENT_PROBES_OBJECT=\"$DATA/probes\""
fi
say "  - Firecracker is not bundled: install firecracker + jailer (v1.9) on PATH, from"
say "      https://github.com/firecracker-microvm/firecracker/releases (or use the container image,"
say "      which bundles a pinned one)"
say "  - check the host; it prints the exact run command for this host:"
say "      agent doctor"
say "  - then run something (the default jails the VMM, which needs real root):"
say "      sudo -E agent run -- echo hello       # jailed, the supported posture"
say "      agent run --unjailed -- echo hello    # no root: still behind KVM, VMM unconfined"
