# Lists the modes the first connector offers and, given an index, sets that mode on a fresh
# dumb buffer, paints it, and holds it for a while. Same hand-rolled ioctls as drm_flip.py.
import ctypes, fcntl, mmap, os, struct, sys, time
DRM = 0x64
def ioc(nr, size, rw=3): return (rw << 30) | (size << 16) | (DRM << 8) | nr
GETRESOURCES, GETCONNECTOR, GETENCODER = ioc(0xA0, 64), ioc(0xA7, 80), ioc(0xA6, 20)
CREATE_DUMB, ADDFB, MAP_DUMB, SETCRTC, DIRTYFB = ioc(0xB2, 32), ioc(0xAE, 28), ioc(0xB3, 16), ioc(0xA2, 104), ioc(0xB1, 24)
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
raw = bytes(modes)
print(f"MODES {nmodes}")
for i in range(nmodes):
    m = raw[i*68:(i+1)*68]
    clock, hdisp, _, _, _, _, vdisp = struct.unpack_from("<IHHHHHH", m)
    vrefresh, flags, mtype = struct.unpack_from("<III", m, 24)
    name = m[36:68].split(b"\0")[0].decode()
    print(f"MODE {i} {hdisp}x{vdisp}@{vrefresh} type={mtype} {name}", flush=True)
if len(sys.argv) < 2:
    sys.exit(0)
if enc_id == 0: enc_id = encs[0]
e = call(GETENCODER, bytearray(struct.pack("<IIIII", enc_id, 0, 0, 0, 0)))
crtc_id = struct.unpack("<IIIII", e)[2] or crtcs[0]
steps = [(int(sys.argv[i]), float(sys.argv[i+1])) for i in range(1, len(sys.argv) - 1, 2)]
for idx, hold in steps:
    mode = raw[idx*68:(idx+1)*68]
    clock, hdisp, _, _, _, _, vdisp = struct.unpack_from("<IHHHHHH", mode)
    d = call(CREATE_DUMB, bytearray(struct.pack("<IIIIIIQ", vdisp, hdisp, 32, 0, 0, 0, 0)))
    _, _, _, _, handle, pitch, size = struct.unpack("<IIIIIIQ", d)
    fb_id = struct.unpack_from("<I", call(ADDFB, bytearray(struct.pack("<IIIIIII", 0, hdisp, vdisp, pitch, 32, 24, handle))))[0]
    offset = struct.unpack_from("<Q", call(MAP_DUMB, bytearray(struct.pack("<IIQ", handle, 0, 0))), 8)[0]
    mem = mmap.mmap(fd, size, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE, offset=offset)
    for y in range(vdisp):
        mem[y*pitch:y*pitch+hdisp*4] = bytes((0x40, 0x40, 0x40, 0)) * hdisp
    for y in range(16):
        mem[y*pitch:y*pitch+64] = bytes((0, 0, 0xff, 0)) * 16
    try:
        call(SETCRTC, bytearray(struct.pack("<QIIIIIII", ctypes.addressof(conns), 1, crtc_id, fb_id, 0, 0, 0, 1) + mode))
        print(f"SETCRTC ok {hdisp}x{vdisp}", flush=True)
    except OSError as e:
        print(f"SETCRTC failed {hdisp}x{vdisp}: {e}", flush=True); sys.exit(1)
    end = time.monotonic() + hold
    while time.monotonic() < end:
        call(DIRTYFB, bytearray(struct.pack("<IIIIQ", fb_id, 0, 0, 0, 0)))
        time.sleep(0.25)
print("DONE", flush=True)
