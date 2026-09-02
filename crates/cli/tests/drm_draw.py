# Draws a known pattern on the first connected DRM output through a dumb buffer: red top-left,
# green top-right, blue bottom-left, white bottom-right, grey elsewhere. No libdrm needed.
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
res = bytearray(struct.pack("<QQQQIIIIIIII", 0, ctypes.addressof(crtcs), ctypes.addressof(conns), ctypes.addressof(encs), 0, ncrtc, nconn, nenc, 0, 0, 0, 0))
call(GETRESOURCES, res)
print(f"DRAW resources: crtcs={list(crtcs)} connectors={list(conns)} encoders={list(encs)}", flush=True)

conn_id = conns[0]
c = call(GETCONNECTOR, bytearray(struct.pack("<QQQQIIIIIIIIIIII", 0, 0, 0, 0, 0, 0, 0, 0, conn_id, 0, 0, 0, 0, 0, 0, 0)))
nmodes, nprops, nencs, enc_id, _, ctype, _, connection = struct.unpack_from("<IIIIIIII", c, 32)
modes = (ctypes.c_ubyte * (68 * max(nmodes, 1)))()
c = call(GETCONNECTOR, bytearray(struct.pack("<QQQQIIIIIIIIIIII", 0, ctypes.addressof(modes), 0, 0, nmodes, 0, 0, 0, conn_id, 0, 0, 0, 0, 0, 0, 0)))
mode = bytes(modes)[:68]
clock, hdisp, _, _, _, _, vdisp = struct.unpack_from("<IHHHHHH", mode)
print(f"DRAW connector {conn_id}: connection={connection} modes={nmodes} first={hdisp}x{vdisp} encoder={enc_id}", flush=True)

if enc_id == 0: enc_id = encs[0]  # no encoder attached yet: take the first the card offers
e = call(GETENCODER, bytearray(struct.pack("<IIIII", enc_id, 0, 0, 0, 0)))
_, _, crtc_id, possible, _ = struct.unpack("<IIIII", e)
if crtc_id == 0: crtc_id = crtcs[0]
print(f"DRAW encoder {enc_id}: crtc={crtc_id}", flush=True)

d = call(CREATE_DUMB, bytearray(struct.pack("<IIIIIIQ", vdisp, hdisp, 32, 0, 0, 0, 0)))
_, _, _, _, handle, pitch, size = struct.unpack("<IIIIIIQ", d)
f = call(ADDFB, bytearray(struct.pack("<IIIIIII", 0, hdisp, vdisp, pitch, 32, 24, handle)))
fb_id = struct.unpack_from("<I", f)[0]
m = call(MAP_DUMB, bytearray(struct.pack("<IIQ", handle, 0, 0)))
offset = struct.unpack_from("<Q", m, 8)[0]
mem = mmap.mmap(fd, size, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE, offset=offset)
print(f"DRAW dumb buffer: {hdisp}x{vdisp} pitch={pitch} size={size} fb={fb_id}", flush=True)

def px(x, y):  # XRGB8888 little-endian: bytes B,G,R,X
    q = (x * 2 // hdisp, y * 2 // vdisp)
    return {(0, 0): (255, 0, 0), (1, 0): (0, 255, 0), (0, 1): (0, 0, 255), (1, 1): (255, 255, 255)}[q] if (x < 16 or x >= hdisp - 16) and (y < 16 or y >= vdisp - 16) else (0x40, 0x40, 0x40)
row = bytearray(pitch)
for y in range(vdisp):
    for x in range(hdisp):
        r, g, b = px(x, y); row[x*4:x*4+4] = bytes((b, g, r, 0))
    mem[y*pitch:(y+1)*pitch] = row

crtc = bytearray(struct.pack("<QIIIIIII", ctypes.addressof(conns), 1, crtc_id, fb_id, 0, 0, 0, 1) + mode)
call(SETCRTC, crtc)
print("DRAW setcrtc ok", flush=True)
for i in range(int(sys.argv[1]) if len(sys.argv) > 1 else 5):
    call(DIRTYFB, bytearray(struct.pack("<IIIIQ", fb_id, 0, 0, 0, 0)))
    time.sleep(0.5)
print("DRAW done", flush=True)
