#!/usr/bin/env python3
"""Protocol-aware TLS state-machine fuzzer for tfrpc.

Listens on 7000, reads the client's TLS ClientHello (with or without frp's
0x17 marker), then replies with a mutated ServerHello / Certificate /
ServerKeyExchange / ServerHelloDone sequence and observes the client.
"""
import socket, struct, sys, random, os, time, threading

MODE = sys.argv[1] if len(sys.argv) > 1 else "mutate_sh"
SEED = int(sys.argv[2]) if len(sys.argv) > 2 else 1
NITER = int(sys.argv[3]) if len(sys.argv) > 3 else 200
random.seed(SEED)

def rec(type_, body):
    return bytes([type_]) + b"\x03\x03" + struct.pack(">H", len(body)) + body

def hs(mtype, body):
    return bytes([mtype]) + len(body).to_bytes(3, "big") + body

def read_record(s):
    hdr = b""
    while len(hdr) < 5:
        d = s.recv(5 - len(hdr))
        if not d: return None
        hdr += d
    if hdr[0] == 0x17 and hdr[1] == 0x03:      # frp marker (single byte)
        # marker is a lone byte; re-read the real 5-byte header
        hdr = hdr[1:] + s.recv(1)
        while len(hdr) < 5:
            d = s.recv(5 - len(hdr))
            if not d: return None
            hdr += d
    ln = struct.unpack(">H", hdr[3:5])[0]
    body = b""
    while len(body) < ln:
        d = s.recv(ln - len(body))
        if not d: return None
        body += d
    return hdr[0], body

def mutate(b, intensity=0.15):
    b = bytearray(b)
    n = max(1, int(len(b) * intensity))
    for _ in range(n):
        i = random.randrange(len(b))
        b[i] = random.randrange(256)
    return bytes(b)

def valid_server_hello_12():
    body = b"\x03\x03" + os.urandom(32) + b"\x00"           # ver, random, sid_len
    body += struct.pack(">H", 0xc02f) + b"\x00"             # suite, compression
    # extensions: renegotiation_info (empty)
    ext = b"\xff\x01\x00\x00"
    body += struct.pack(">H", len(ext)) + ext
    return hs(2, body)

def valid_certificate_12():
    # empty certificate list (no certs) - exercises the nchain==0 path
    body = struct.pack(">I", 3)[1:] + struct.pack(">I", 0)[1:]
    return hs(11, body)

def valid_ske_12():
    # curve_type=3, x25519, 32-byte point, rsa_pkcs1_sha256 sig with zero length
    body = b"\x03\x00\x1d\x20" + bytes(32) + b"\x04\x01\x00\x00"
    return hs(12, body)

def valid_shd_12():
    return hs(14, b"")

def send_seq(s, mode):
    if mode == "mutate_sh":
        sh = mutate(valid_server_hello_12())
    elif mode == "truncated_sh":
        sh = valid_server_hello_12()
        sh = sh[:random.randrange(1, len(sh))]
    elif mode == "huge_sh_len":
        body = b"\x03\x03" + os.urandom(32) + b"\x00" + struct.pack(">H", 0xc02f) + b"\x00"
        body = struct.pack(">I", 0x00ffffff)[1:] + body    # lying length
        sh = b"\x16\x03\x03" + struct.pack(">H", len(body)) + body
    elif mode == "random_record":
        sh = rec(random.randrange(256), os.urandom(random.randrange(0, 300)))
    elif mode == "sh_plus_garbage":
        sh = valid_server_hello_12() + os.urandom(random.randrange(1, 200))
    elif mode == "sh_cert_ske_mut":
        sh = valid_server_hello_12()
        cert = mutate(valid_certificate_12())
        ske = mutate(valid_ske_12())
        shd = valid_shd_12()
        sh = rec(0x16, sh) + rec(0x16, cert) + rec(0x16, ske) + rec(0x16, shd)
    elif mode == "ske_mut":
        sh = rec(0x16, valid_server_hello_12()) + rec(0x16, valid_certificate_12())
        sh += rec(0x16, mutate(valid_ske_12(), 0.3)) + rec(0x16, valid_shd_12())
    elif mode == "split_records":
        # one handshake message split across many tiny records
        msg = valid_server_hello_12()
        sh = b""
        i = 0
        while i < len(msg):
            n = random.randrange(1, 8)
            sh += rec(0x16, msg[i:i+n])
            i += n
    elif mode == "record_flood":
        sh = b"".join(rec(0x16, os.urandom(random.randrange(0, 64))) for _ in range(50))
    else:
        sh = valid_server_hello_12()
    try:
        s.sendall(sh)
    except Exception:
        pass

def one_round(srv, mode):
    try:
        c, a = srv.accept()
    except Exception:
        return
    c.settimeout(3)
    try:
        r = read_record(c)
        if r:
            send_seq(c, mode)
            # give the client a moment, then see if it closes or hangs
            try:
                c.recv(100)
            except Exception:
                pass
    except Exception:
        pass
    try:
        c.close()
    except Exception:
        pass

def main():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 7000))
    srv.listen(32)
    print("tls fuzzer mode=%s seed=%d iters=%d" % (MODE, SEED, NITER), flush=True)
    for _ in range(NITER):
        one_round(srv, MODE)
    srv.close()
    print("fuzz done", flush=True)

if __name__ == "__main__":
    main()
