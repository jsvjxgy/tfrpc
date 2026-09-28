import asyncio, os, random, struct, sys, time

from aioquic.asyncio import serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection

MODE = sys.argv[1] if len(sys.argv) > 1 else "interop"
raw_queue = []
_injected = 0
conn_obj = None
random.seed(7)

def varint(v):
    if v < 64:
        return bytes([v])
    if v < 16384:
        return struct.pack("!H", v | 0x4000)
    if v < (1 << 30):
        return struct.pack("!I", v | 0x80000000)
    return struct.pack("!Q", v | 0xC000000000000000)

# monkeypatch: append raw frames to every 1-RTT packet
_orig_limits = QuicConnection._write_connection_limits

def _patched_limits(self, builder, space):
    _orig_limits(self, builder, space)
    global _injected, conn_obj
    conn_obj = self
    while raw_queue:
        payload = raw_queue.pop(0)
        try:
            buf = builder.start_frame(payload[0], capacity=max(0, len(payload) - 1))
            buf.push_bytes(payload[1:])
            _injected += 1
        except Exception as e:
            print("inject error:", repr(e), flush=True)
            break

QuicConnection._write_connection_limits = _patched_limits

def build_frames():
    out = []
    if MODE == "bad_stream":
        out.append(bytes([0x0c]) + varint(0) + varint((1 << 62) - 1) + varint(4) + b"AAAA")
        out.append(bytes([0x0c]) + varint(0) + varint(1) + varint(0))
        out.append(bytes([0x08]) + varint(0) + b"BBBB")          # no OFF, no LEN
        out.append(bytes([0x0e]) + varint(16) + varint(5) + b"CCCC")  # unknown stream id
        out.append(bytes([0x0b]) + varint(0))                    # FIN only
    elif MODE == "bad_trunc":
        out.append(bytes([0x0c]) + varint(0) + varint(0) + varint(1000) + b"X")
        out.append(bytes([0x11]) + varint(0) + varint(1 << 60))
        out.append(bytes([0x04]) + varint(0) + varint(1 << 61))
        out.append(bytes([0x1a]) + b"\x01\x02\x03")
    elif MODE == "bad_close":
        out.append(bytes([0x1c]) + varint(0x100) + varint(6) + varint((1 << 62) - 1) + b"boom")
    elif MODE == "bad_reset":
        out.append(bytes([0x04]) + varint(0) + varint(9) + varint((1 << 62) - 1))
        out.append(bytes([0x05]) + varint(0) + varint(9))
        out.append(bytes([0x19]) + varint(99))
    elif MODE == "bad_flow":
        out.append(bytes([0x10]) + varint(1 << 61))
        out.append(bytes([0x11]) + varint(0) + varint((1 << 62) - 1))
        out.append(bytes([0x12]) + varint((1 << 60) - 1))
        out.append(bytes([0x13]) + varint((1 << 60) - 1))
        out.append(bytes([0x14]) + varint(1 << 61))
        out.append(bytes([0x15]) + varint(0) + varint(1 << 61))
        out.append(bytes([0x16]) + varint(1 << 61))
        out.append(bytes([0x17]) + varint(1 << 61))
    elif MODE == "bad_path":
        out.append(bytes([0x1a]) + os.urandom(8))
        out.append(bytes([0x1b]) + os.urandom(8))
        out.append(bytes([0x18]) + varint(0) + varint(0) + varint(20) + os.urandom(20))
        out.append(bytes([0x18]) + varint(1) + varint(99) + varint(0))
    elif MODE == "bad_type":
        out.append(bytes([0x2a]) + os.urandom(10))
        out.append(bytes([0x1f]))
        out.append(bytes([0x3f]) + os.urandom(3))
    elif MODE == "random":
        for _ in range(60):
            n = random.randint(1, 60)
            out.append(bytes([random.randrange(0, 0x40)]) + os.urandom(n - 1))
    elif MODE == "keyupd":
        out.append(bytes([0x01]))          # PING so packets are actually built
    elif MODE == "overlap_stream":
        # sid 0 = control stream: a valid-but-unknown frp message (type 0x7f,
        # empty-body payload) split into overlapping / out-of-order chunks
        m = bytes([0x7f, 0, 0, 0, 0, 0, 0, 0, 32]) + b"P" * 32
        def sf(off, data, fin=0):
            import struct as _s
            def vi(v):
                if v < 64: return bytes([v])
                if v < 16384: return _s.pack("!H", v | 0x4000)
                return _s.pack("!I", v | 0x80000000)
            t = 0x0e | fin          # OFF + LEN (+ FIN)
            return bytes([t]) + vi(0) + vi(off) + vi(len(data)) + data
        out.append(sf(10, m[10:20]))       # out of order
        out.append(sf(5, m[5:15]))         # overlaps the queued chunk (split)
        out.append(sf(0, m[0:5]))          # fills the gap; drain chains
        out.append(sf(15, m[15:25]))       # overlaps consumed data
        out.append(sf(25, m[25:41], 1))    # tail + FIN
        out.append(sf(0, m[0:20]))         # duplicate of consumed range
        out.append(sf(41, b"", 1))         # zero-length FIN at end
    return out


def handler(reader, writer):
    asyncio.get_event_loop().create_task(handle_stream(reader, writer))

async def handle_stream(reader, writer):
    tr = getattr(writer, "transport", None)
    proto = getattr(tr, "_protocol", None)
    if proto is None:
        print("no protocol handle", flush=True)
    else:
        print("proto ok", flush=True)
    try:
        await reader.read(65536)   # frp login attempt
    except Exception:
        pass
    frames = build_frames()
    for i in range(400):
        for f in frames:
            raw_queue.append(f)
        if MODE == "keyupd" and i in (10, 60):
            try:
                if proto:
                    proto.request_key_update()
                elif conn_obj:
                    conn_obj.request_key_update()
            except Exception as e:
                print("keyupd error:", repr(e), flush=True)
        if MODE == "random" and i % 20 == 0:
            # also echo bytes as stream data to exercise stream parsing
            try:
                writer.write(os.urandom(random.randint(1, 200)))
            except Exception:
                pass
        try:
            if proto:
                proto.transmit()
        except Exception:
            pass
        await asyncio.sleep(0.05)
    print("injected frames:", _injected, flush=True)

async def main():
    cfg = QuicConfiguration(is_client=False, alpn_protocols=["frp"])
    cfg.load_cert_chain("/tmp/qtest-cert.pem", "/tmp/qtest-key.pem")
    cfg.max_datagram_size = 1400
    print("evil aioquic mode=%s on 7000" % MODE, flush=True)
    await serve("127.0.0.1", 7000, configuration=cfg, stream_handler=handler)
    await asyncio.Future()

asyncio.run(main())
