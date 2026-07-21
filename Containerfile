# The engine as a container image (decision 035): a runtime-only image assembled FROM a `cargo
# xtask dist` stage (build outside, package inside), bundling the sha-pinned Firecracker v1.9 the
# engine drives. The KVM boundary cannot come from the image: run it with the host's /dev/kvm.
#
#   cargo xtask dist
#   docker build -f Containerfile --build-arg DIST=dist/agent-<ver>-x86_64-linux -t agent:<ver> .
#
#   docker run --rm agent:<ver>                                # doctor: what this host can do
#   docker run --rm --device /dev/kvm agent:<ver> run --unjailed -- echo hi
#   docker run --rm --device /dev/kvm --cap-add NET_ADMIN agent:<ver> run --unjailed --net ...
#
# The jailed default and eBPF observation need more of the host (real root in the user namespace,
# CAP_BPF/CAP_PERFMON, cgroup v2 delegation); a hardened deployment runs those on the host or in a
# privileged container, a hoster call the engine does not make for you.

FROM ubuntu:24.04 AS firecracker
# Pinned like every upstream input: the sha256 is the contract, the URL is replaceable.
ARG FC_VERSION=v1.9.1
ARG FC_SHA256=88d89221063ee4021b539a4fea4567642f4eecfb5d52eec04cd3390833f7f3de
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && curl -fsSL -o /tmp/fc.tgz \
       "https://github.com/firecracker-microvm/firecracker/releases/download/${FC_VERSION}/firecracker-${FC_VERSION}-x86_64.tgz" \
    && echo "${FC_SHA256}  /tmp/fc.tgz" | sha256sum -c - \
    && tar -C /tmp -xzf /tmp/fc.tgz \
    && install -m 0755 "/tmp/release-${FC_VERSION}-x86_64/firecracker-${FC_VERSION}-x86_64" /usr/local/bin/firecracker \
    && install -m 0755 "/tmp/release-${FC_VERSION}-x86_64/jailer-${FC_VERSION}-x86_64" /usr/local/bin/jailer

# The runtime base must carry a glibc at least as new as the dist builder's (the binary is
# glibc-linked); ubuntu:24.04 matches the release builder and the tested-distro line.
FROM ubuntu:24.04
# iproute2: the tap/netns shell-outs; e2fsprogs: output-image build + read-after-death recovery.
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 e2fsprogs \
    && rm -rf /var/lib/apt/lists/*
COPY --from=firecracker /usr/local/bin/firecracker /usr/local/bin/jailer /usr/local/bin/
ARG DIST
COPY ${DIST}/ /opt/agent/
ENV AGENT_KERNEL=/opt/agent/share/agent/vmlinux \
    AGENT_ROOTFS=/opt/agent/share/agent/rootfs-agent.ext4 \
    AGENT_PROBES_OBJECT=/opt/agent/share/agent/probes \
    PATH=/opt/agent/bin:/usr/local/bin:/usr/bin:/bin
ENTRYPOINT ["/opt/agent/bin/agent"]
CMD ["doctor"]
