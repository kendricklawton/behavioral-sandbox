# Reports what of the GPU stack a guest can actually reach: the DRM nodes it has, the driver
# behind them, whether the virtio-gpu device advertises 3D, and whether any userspace GL, GLES or
# Vulkan driver is present to use it. Prints `PROBE key value` lines. No libdrm, no Mesa.
import ctypes, fcntl, os, struct

DRM = 0x64
def ioc(nr, size, rw=3): return (rw << 30) | (size << 16) | (DRM << 8) | nr
# struct drm_version: three ints, 4 bytes of padding to the first u64, then (len, ptr) for each of
# name, date and desc. 12 + 4 + 48 = 64.
VERSION = ioc(0x00, 64)
VERSION_FMT = "<iii4xQQQQQQ"
# VIRTGPU_GETPARAM is DRM_COMMAND_BASE (0x40) + 0x03, struct { __u64 param; __u64 value; }.
VIRTGPU_GETPARAM = ioc(0x43, 16)
# VIRTGPU_GET_CAPS is DRM_COMMAND_BASE + 0x09: { u32 cap_set_id, u32 cap_set_ver, u64 addr,
# u32 size, u32 pad }. Asking for each id says which the host renderer actually answers for,
# rather than trusting a decoding of the SUPPORTED_CAPSET_IDs bitmask.
VIRTGPU_GET_CAPS = ioc(0x49, 24)
CAPSETS = {1: "VIRGL", 2: "VIRGL2", 3: "GFXSTREAM_VULKAN", 4: "VENUS", 5: "CROSS_DOMAIN",
           6: "DRM", 7: "GFXSTREAM_GLES", 8: "GFXSTREAM_COMPOSER"}
# The parameter ids virtio_drm.h names. 3D_FEATURES is the one that says whether virgl is live.
PARAMS = {"3D_FEATURES": 1, "CAPSET_QUERY_FIX": 2, "RESOURCE_BLOB": 3, "HOST_VISIBLE": 4,
          "CROSS_DEVICE": 5, "CONTEXT_INIT": 6, "SUPPORTED_CAPSET_IDs": 7}


def line(key, value): print(f"PROBE {key} {value}", flush=True)


def driver_of(node, fd):
    # Two passes: the first returns the lengths, the second fills the buffers.
    v = bytearray(struct.pack(VERSION_FMT, 0, 0, 0, 0, 0, 0, 0, 0, 0))
    fcntl.ioctl(fd, VERSION, v, True)
    maj, mino, patch, nlen, _, _, _, dlen, _ = struct.unpack(VERSION_FMT, v)
    name, desc = (ctypes.c_char * (nlen + 1))(), (ctypes.c_char * (dlen + 1))()
    v = bytearray(struct.pack(VERSION_FMT, 0, 0, 0, nlen, ctypes.addressof(name),
                              0, 0, dlen, ctypes.addressof(desc)))
    fcntl.ioctl(fd, VERSION, v, True)
    line(f"{node}_driver",
         f"{name.value.decode()} {maj}.{mino}.{patch} ({desc.value.decode()})")


def params_of(node, fd):
    for label, param in PARAMS.items():
        # `value` is a pointer to where the kernel writes the answer, not an inline field.
        out = ctypes.c_uint64(0)
        buf = bytearray(struct.pack("<QQ", param, ctypes.addressof(out)))
        try:
            fcntl.ioctl(fd, VIRTGPU_GETPARAM, buf, True)
            line(f"{node}_param_{label}", out.value)
        except OSError as e:
            line(f"{node}_param_{label}", f"errno {e.errno} ({os.strerror(e.errno)})")


def capsets_of(node, fd):
    answered = []
    for cid, cname in CAPSETS.items():
        caps = (ctypes.c_ubyte * 1024)()
        buf = bytearray(struct.pack("<IIQII", cid, 0, ctypes.addressof(caps), 1024, 0))
        try:
            fcntl.ioctl(fd, VIRTGPU_GET_CAPS, buf, True)
            answered.append(f"{cname}({cid})")
        except OSError:
            pass
    line(f"{node}_capsets_answered", " ".join(answered) if answered else "(none)")


nodes = sorted(os.listdir("/dev/dri")) if os.path.isdir("/dev/dri") else []
line("dri_nodes", " ".join(nodes) if nodes else "(none)")
line("render_node", "yes" if any(n.startswith("renderD") for n in nodes) else "no")

for node in [n for n in nodes if n.startswith("card")]:
    try:
        fd = os.open(f"/dev/dri/{node}", os.O_RDWR | os.O_CLOEXEC)
    except OSError as e:
        line(f"{node}_open", f"failed {e.errno}")
        continue
    # A failing ioctl must not leak the card, or a probe of a second node runs short of fds.
    try:
        driver_of(node, fd)
        params_of(node, fd)
        capsets_of(node, fd)
    finally:
        os.close(fd)

# Userspace: a kernel driver with no Mesa behind it can scan out, and nothing more.
for label, globs in [
    ("mesa_dri", ["/usr/lib/dri", "/usr/lib/xorg/modules/dri"]),
    ("libgl", ["/usr/lib/libGL.so.1", "/usr/lib/libGLESv2.so.2", "/usr/lib/libEGL.so.1"]),
    ("vulkan_icd", ["/usr/share/vulkan/icd.d"]),
    ("libvulkan", ["/usr/lib/libvulkan.so.1"]),
]:
    found = [p for p in globs if os.path.exists(p)]
    line(label, " ".join(found) if found else "(absent)")
