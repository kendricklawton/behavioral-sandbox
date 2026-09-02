# Names every input device the guest has, then prints each event it reads from any of them as
# `INPUT <n> <type> <code> <value>` until a KEY_A (30) release and a BTN_LEFT (0x110) release have
# both arrived, or the deadline passes. No evdev library needed: the records are 24 bytes each.
import fcntl, glob, os, select, struct, sys, time

FMT, KEY_A, BTN_LEFT = "llHHi", 30, 0x110
SIZE = struct.calcsize(FMT)
EVIOCGNAME = (2 << 30) | (64 << 16) | (ord("E") << 8) | 0x06

paths = sorted(glob.glob("/dev/input/event*"))
fds = {}
for p in paths:
    fd = os.open(p, os.O_RDONLY | os.O_NONBLOCK)
    name = bytearray(64)
    fcntl.ioctl(fd, EVIOCGNAME, name, True)
    fds[fd] = p[-1]
    label = name.split(b"\0", 1)[0].decode()
    print(f"INPUT device {p[-1]} {label}", flush=True)
print(f"INPUT ready {len(fds)}", flush=True)

seen, deadline = set(), time.monotonic() + (float(sys.argv[1]) if len(sys.argv) > 1 else 15)
while time.monotonic() < deadline and not {KEY_A, BTN_LEFT} <= seen:
    ready, _, _ = select.select(list(fds), [], [], 0.5)
    for fd in ready:
        data = os.read(fd, SIZE * 64)
        for off in range(0, len(data) - SIZE + 1, SIZE):
            _, _, t, c, v = struct.unpack_from(FMT, data, off)
            print(f"INPUT {fds[fd]} {t} {c} {v}", flush=True)
            if t == 1 and v == 0:
                seen.add(c)
done = {KEY_A, BTN_LEFT} <= seen
print("INPUT done" if done else "INPUT timeout", flush=True)
sys.exit(0 if done else 1)
