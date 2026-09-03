# Draws frames on the first connected DRM output as fast as the chosen path allows, a counter in
# every one, and reports how fast that was. Two paths, because they measure different ceilings:
#   dirty  one dumb buffer, DIRTYFB per frame: unpaced, so the rate is what the virtio-gpu flush,
#          libkrun's readback and the host backend sustain together.
#   flip   two dumb buffers, PAGE_FLIP with a vblank event per frame: paced by the refresh rate the
#          guest was told, so the rate is what a well-behaved compositor gets.
# No libdrm needed: the ioctls are issued by hand, as in drm_draw.py.
import ctypes, fcntl, mmap, os, select, struct, sys, time

DRM = 0x64
def ioc(nr, size, rw=3): return (rw << 30) | (size << 16) | (DRM << 8) | nr
GETRESOURCES, GETCONNECTOR, GETENCODER = ioc(0xA0, 64), ioc(0xA7, 80), ioc(0xA6, 20)
CREATE_DUMB, ADDFB, MAP_DUMB, SETCRTC = ioc(0xB2, 32), ioc(0xAE, 28), ioc(0xB3, 16), ioc(0xA2, 104)
DIRTYFB, PAGE_FLIP = ioc(0xB1, 24), ioc(0xB0, 32)
PAGE_FLIP_EVENT = 1

mode_name = sys.argv[1] if len(sys.argv) > 1 else "dirty"
frames = int(sys.argv[2]) if len(sys.argv) > 2 else 300

fd = os.open("/dev/dri/card0", os.O_RDWR | os.O_CLOEXEC)
def call(req, buf): fcntl.ioctl(fd, req, buf, True); return buf

res = call(GETRESOURCES, bytearray(64))
_, _, _, _, nfb, ncrtc, nconn, nenc = struct.unpack_from("<QQQQIIII", res)
crtcs, conns, encs = (ctypes.c_uint32 * max(ncrtc, 1))(), (ctypes.c_uint32 * max(nconn, 1))(), (ctypes.c_uint32 * max(nenc, 1))()
call(GETRESOURCES, bytearray(struct.pack("<QQQQIIIIIIII", 0, ctypes.addressof(crtcs), ctypes.addressof(conns), ctypes.addressof(encs), 0, ncrtc, nconn, nenc, 0, 0, 0, 0)))
conn_id = conns[0]
c = call(GETCONNECTOR, bytearray(struct.pack("<QQQQIIIIIIIIIIII", 0, 0, 0, 0, 0, 0, 0, 0, conn_id, 0, 0, 0, 0, 0, 0, 0)))
nmodes, _, _, enc_id = struct.unpack_from("<IIII", c, 32)
modes = (ctypes.c_ubyte * (68 * max(nmodes, 1)))()
call(GETCONNECTOR, bytearray(struct.pack("<QQQQIIIIIIIIIIII", 0, ctypes.addressof(modes), 0, 0, nmodes, 0, 0, 0, conn_id, 0, 0, 0, 0, 0, 0, 0)))
mode = bytes(modes)[:68]
clock, hdisp, _, _, _, _, vdisp = struct.unpack_from("<IHHHHHH", mode)
vrefresh = struct.unpack_from("<I", mode, 24)[0]  # drm_mode_modeinfo: clock, ten u16 fields, then vrefresh
if enc_id == 0: enc_id = encs[0]
e = call(GETENCODER, bytearray(struct.pack("<IIIII", enc_id, 0, 0, 0, 0)))
crtc_id = struct.unpack("<IIIII", e)[2] or crtcs[0]

def framebuffer():
    d = call(CREATE_DUMB, bytearray(struct.pack("<IIIIIIQ", vdisp, hdisp, 32, 0, 0, 0, 0)))
    _, _, _, _, handle, pitch, size = struct.unpack("<IIIIIIQ", d)
    fb_id = struct.unpack_from("<I", call(ADDFB, bytearray(struct.pack("<IIIIIII", 0, hdisp, vdisp, pitch, 32, 24, handle))))[0]
    offset = struct.unpack_from("<Q", call(MAP_DUMB, bytearray(struct.pack("<IIQ", handle, 0, 0))), 8)[0]
    mem = mmap.mmap(fd, size, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE, offset=offset)
    return fb_id, pitch, mem

# Every frame repaints the whole buffer, so the readback moves real bytes: a grey that steps with the
# counter, and the counter itself in the top-left 16x16 block's blue byte.
def paint(mem, pitch, n):
    g = 0x20 + (n % 64)
    row = bytes((g, g, g, 0)) * hdisp
    for y in range(vdisp):
        mem[y * pitch:y * pitch + hdisp * 4] = row
    px = bytes((n & 0xFF, (n >> 8) & 0xFF, 0, 0)) * 16
    for y in range(16):
        mem[y * pitch:y * pitch + 64] = px

fbs = [framebuffer(), framebuffer()] if mode_name == "flip" else [framebuffer()]
paint(fbs[0][2], fbs[0][1], 0)
call(SETCRTC, bytearray(struct.pack("<QIIIIIII", ctypes.addressof(conns), 1, crtc_id, fbs[0][0], 0, 0, 0, 1) + mode))
print(f"FLIP setup mode={hdisp}x{vdisp}@{vrefresh} path={mode_name} frames={frames}", flush=True)

intervals = []
last = time.monotonic_ns()
started = last
for n in range(1, frames + 1):
    fb_id, pitch, mem = fbs[n % len(fbs)]
    paint(mem, pitch, n)
    if mode_name == "flip":
        call(PAGE_FLIP, bytearray(struct.pack("<IIIIQ", crtc_id, fb_id, PAGE_FLIP_EVENT, 0, n)))
        select.select([fd], [], [])
        os.read(fd, 64)  # the vblank event: the flip has happened
    else:
        call(DIRTYFB, bytearray(struct.pack("<IIIIQ", fb_id, 0, 0, 0, 0)))
    now = time.monotonic_ns()
    intervals.append(now - last)
    last = now
elapsed = last - started
intervals.sort()
rank = lambda p: intervals[max(1, min(len(intervals), -(-p * len(intervals) // 100))) - 1]
print(f"FLIP done path={mode_name} frames={frames} elapsed_ns={elapsed} fps={frames * 1e9 / elapsed:.1f} "
      f"interval_us p50={rank(50) // 1000} p90={rank(90) // 1000} p99={rank(99) // 1000} max={intervals[-1] // 1000}", flush=True)
