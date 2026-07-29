# The engine as a container image: a runtime-only image assembled FROM a `cargo
# xtask dist` stage (build outside, package inside), bundling the sha-pinned Firecracker release
# the engine drives (the `FC_VERSION` ARG below; a gate test holds it to the engine's own pin,
# because this file is a third copy of that pin and the other two once drifted for 21 months).
# The KVM boundary cannot come from the image: run it with the host's /dev/kvm.
#   cargo xtask dist
#   docker build -f Containerfile --build-arg DIST=dist/ekvm-<ver>-x86_64-linux -t ekvm:<ver> .
#   docker run --rm ekvm:<ver>                                # doctor: what this host can do
#   docker run --rm --device /dev/kvm ekvm:<ver> run --unjailed -- echo hi
#   docker run --rm --device /dev/kvm --cap-add NET_ADMIN ekvm:<ver> run --unjailed --net ...
# The jailed default and eBPF observation need more of the host (real root in the user namespace,
# CAP_BPF/CAP_PERFMON, cgroup v2 delegation); a hardened deployment runs those on the host or in a
# privileged container, a hoster call the engine does not make for you.

FROM ubuntu:24.04 AS firecracker
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
FROM ubuntu:24.04
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
ENTRYPOINT ["/opt/ekvm/bin/ekvm"]
CMD ["doctor"]
