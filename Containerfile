# The engine as a container image: a runtime-only image assembled FROM a `cargo
# xtask dist` stage (build outside, package inside), bundling the sha-pinned Firecracker release
# the engine drives (the `FC_VERSION` ARG below; a gate test holds it to the engine's own pin,
# because this file is a third copy of that pin and the other two once drifted for 21 months).
# The KVM boundary cannot come from the image: run it with the host's /dev/kvm.
#   cargo xtask dist
#   docker build -f Containerfile --build-arg DIST=dist/ekvm-<ver>-x86_64-linux -t ekvm:<ver> .
#   (optional, for the OCI labels: --build-arg VERSION=<ver> --build-arg REVISION=$(git rev-parse HEAD))
#   docker run --rm ekvm:<ver>                                # doctor: what this host can do
#   docker run --rm --device /dev/kvm ekvm:<ver> run --unjailed -- echo hi
#   docker run --rm --device /dev/kvm --cap-add NET_ADMIN ekvm:<ver> run --unjailed --net ...
# The jailed default and eBPF observation need more of the host (real root in the user namespace,
# CAP_BPF/CAP_PERFMON, cgroup v2 delegation); a hardened deployment runs those on the host or in a
# privileged container, a hoster call the engine does not make for you.

# The one base for both stages, pinned by manifest-list digest so the tool userspace below is the
# same bytes on every build (the tag alone moves, and it is the only unpinned input this file had).
# A digest freezes security fixes out too, so refreshing it is a deliberate act:
#   docker buildx imagetools inspect ubuntu:24.04    # take the Digest line
ARG BASE=ubuntu:24.04@sha256:561618e2c15bf2397621dd04f96926663a3b5616c189cf7e38db7e82f5c538ea

FROM ${BASE} AS firecracker
# Pinned like every upstream input: the sha256 is the contract, the URL is replaceable.
ARG FC_VERSION=v1.16.1
ARG FC_SHA256=382a02a869e4d6d5cb14c40577f9545e8458021ea8b0b2d3fc10ec14d9c242e6
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && curl -fsSL -o /tmp/fc.tgz \
       "https://github.com/firecracker-microvm/firecracker/releases/download/${FC_VERSION}/firecracker-${FC_VERSION}-x86_64.tgz" \
    && echo "${FC_SHA256}  /tmp/fc.tgz" | sha256sum -c - \
    && tar -C /tmp -xzf /tmp/fc.tgz \
    && install -m 0755 "/tmp/release-${FC_VERSION}-x86_64/firecracker-${FC_VERSION}-x86_64" /usr/local/bin/firecracker \
    && install -m 0755 "/tmp/release-${FC_VERSION}-x86_64/jailer-${FC_VERSION}-x86_64" /usr/local/bin/jailer

# The ekvm binary is static musl (`cargo xtask dist` verifies it), so the base is not chosen for
# its libc: it supplies the tool userspace the engine shells out to (iproute2, e2fsprogs,
# util-linux). Which distro provides those inside the image is a pinned, closed detail of this
# file, not a host assumption; the engine itself probes capabilities, never distro identity.
FROM ${BASE}
ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.source="https://github.com/ekvm-rs/ekvm" \
      org.opencontainers.image.title="ekvm" \
      org.opencontainers.image.description="Self-hostable, isolated code-execution sandbox: Firecracker microVMs, host-side eBPF" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"
# iproute2: the tap/netns shell-outs; e2fsprogs: output-image build + read-after-death recovery.
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 e2fsprogs \
    && rm -rf /var/lib/apt/lists/*
COPY --from=firecracker /usr/local/bin/firecracker /usr/local/bin/jailer /usr/local/bin/
ARG DIST
COPY ${DIST}/ /opt/ekvm/
ENV EKVM_KERNEL=/opt/ekvm/share/ekvm/vmlinux \
    EKVM_ROOTFS=/opt/ekvm/share/ekvm/rootfs-guest.ext4 \
    EKVM_PROBES_OBJECT=/opt/ekvm/share/ekvm/probes \
    PATH=/opt/ekvm/bin:/usr/local/bin:/usr/bin:/bin
# The layout the ENV paths promise, checked at build time. The threat is an unset or wrong DIST:
# an empty ARG expands the COPY above to `COPY / /opt/ekvm/`, which silently bakes the whole build
# context into a layer; this turns that into a build failure that names the missing piece.
RUN test -x /opt/ekvm/bin/ekvm \
 && test -f "$EKVM_KERNEL" && test -f "$EKVM_ROOTFS" && test -f "$EKVM_PROBES_OBJECT"
# Deliberately no USER: the engine's supported paths need root in the container's user namespace
# (the jailer mknod's device nodes, taps need CAP_NET_ADMIN), and a nonroot USER here would only
# pretend otherwise. The graduated --device/--cap-add tiers in the header are the real knob.
ENTRYPOINT ["/opt/ekvm/bin/ekvm"]
CMD ["doctor"]
