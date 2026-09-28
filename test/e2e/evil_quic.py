import socket, random, sys, time

mode = sys.argv[1] if len(sys.argv) > 1 else "random"
random.seed(4242)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 7000))
print("evil quic mode=%s" % mode, flush=True)

def mutate(data):
    b = bytearray(data)
    for _ in range(random.randint(1, 12)):
        if not b:
            break
        i = random.randrange(len(b))
        b[i] ^= 1 << random.randrange(8)
    return bytes(b)

count = 0
while True:
    try:
        d, a = s.recvfrom(65535)
    except Exception:
        break
    count += 1
    if mode == "random":
        r = bytes(random.getrandbits(8) for _ in range(random.randint(0, 1400)))
    elif mode == "mutate":
        r = mutate(d[:1400])
    elif mode == "truncate":
        r = d[:random.randint(0, max(1, len(d) - 1))]
    elif mode == "oversize":
        r = d[:200] + bytes(random.getrandbits(8) for _ in range(3000))
    elif mode == "falseinit":
        # long header, version 1, bogus lengths/varints
        r = bytearray(d)
        if len(r) > 8:
            r[5] = random.randint(0, 20)          # dcid len
            r[6] = random.randint(0, 60)          # scid len when dcid len==0 later
        r = bytes(r)
    elif mode == "silent":
        r = None
    else:
        r = d
    if r is not None:
        try:
            s.sendto(r, a)
        except Exception:
            pass
    # occasionally send a burst
    if count % 7 == 0:
        for _ in range(5):
            try:
                s.sendto(bytes(random.getrandbits(8) for _ in range(1350)), a)
            except Exception:
                pass
