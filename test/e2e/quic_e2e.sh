#!/bin/bash
# QUIC end-to-end: handshake, data, loss recovery, reconnect
set -u
TFRPC=/home/tntxxd/Videos/frp/tfrpc/tfrpc
RES=/tmp/quic_result.txt
> $RES

cleanup() {
  kill -9 ${BE:-} ${FS:-} ${LP:-} ${FC:-} 2>/dev/null
  pkill -9 -x tfrpc 2>/dev/null
  pkill -9 -x frps-test 2>/dev/null
  pkill -9 -f quic_e2e_backend 2>/dev/null
  pkill -9 -f quic_e2e_lossy 2>/dev/null
}
trap cleanup EXIT
pkill -9 -x tfrpc 2>/dev/null; pkill -9 -x frps-test 2>/dev/null; sleep 0.5

cat > /tmp/quic_e2e_backend.py <<'EOF'
import socket, threading
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 2222)); s.listen(64)
def h(c):
    try:
        while True:
            d = c.recv(65536)
            if not d: break
            c.sendall(d)
    except Exception: pass
    c.close()
while True:
    c, _ = s.accept()
    threading.Thread(target=h, args=(c,), daemon=True).start()
EOF
cat > /tmp/quic_e2e_lossy.py <<'EOF'
import socket, sys, threading, random, time
DROP = float(sys.argv[1]); LISTEN = int(sys.argv[2]); TARGET = int(sys.argv[3])
random.seed(12345)
sessions = {}
def drop(): return random.random() < DROP
def reader(up, client):
    while True:
        try: d, _ = up.recvfrom(4096)
        except Exception: return
        if drop(): continue
        if random.random() < 0.03: time.sleep(0.005)
        try: s.sendto(d, client)
        except Exception: pass
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", LISTEN))
while True:
    d, a = s.recvfrom(4096)
    up = sessions.get(a)
    if up is None:
        up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sessions[a] = up
        threading.Thread(target=reader, args=(up, a), daemon=True).start()
    if drop(): continue
    try: up.sendto(d, ("127.0.0.1", TARGET))
    except Exception: pass
EOF

python3 /tmp/quic_e2e_backend.py >/dev/null 2>&1 & BE=$!

# ---- direct QUIC session: echo, 1MB, concurrency ----
printf 'bindPort = 7000\nquicBindPort = 7000\nauth.method = "token"\nauth.token = "s"\n' > /tmp/quic_e2e_frps.toml
printf 'serverAddr = "127.0.0.1"\nserverPort = 7000\ntransport.protocol = "quic"\nauth.token = "s"\n[[proxies]]\nname = "q"\ntype = "tcp"\nlocalPort = 2222\nremotePort = 6241\n' > /tmp/quic_e2e_c.toml
/tmp/frps-test -c /tmp/quic_e2e_frps.toml >/dev/null 2>&1 & FS=$!
sleep 1.5
$TFRPC -c /tmp/quic_e2e_c.toml >/tmp/quic_e2e_c.log 2>&1 & FC=$!
for i in $(seq 1 40); do grep -aq "ready" /tmp/quic_e2e_c.log 2>/dev/null && break; sleep 0.5; done
if ! grep -aq "ready" /tmp/quic_e2e_c.log; then echo "direct: FAIL (no ready)" >> $RES; exit 1; fi
timeout 60 python3 - <<'EOF' >> $RES
import socket, threading, concurrent.futures
def one(i):
    s = socket.create_connection(("127.0.0.1", 6241), timeout=15)
    msg = b"ping-%d" % i
    s.sendall(msg)
    got = b""
    while len(got) < len(msg):
        d = s.recv(65536)
        if not d: break
        got += d
    s.close()
    assert got == msg, (i, len(got))
data = bytes(range(256)) * 4096
s = socket.create_connection(("127.0.0.1", 6241), timeout=30)
got = []
def rx():
    total = 0
    while total < len(data):
        d = s.recv(65536)
        if not d: break
        got.append(d); total += len(d)
t = threading.Thread(target=rx); t.start()
s.sendall(data); t.join(60); s.close()
assert b"".join(got) == data, "1MB mismatch"
one(0)
with concurrent.futures.ThreadPoolExecutor(5) as ex:
    list(ex.map(one, range(10, 15)))
print("direct: echo + 1MB + 5 concurrent OK")
EOF
kill -9 $FS $FC 2>/dev/null; pkill -9 -x tfrpc 2>/dev/null; pkill -9 -x frps-test 2>/dev/null; sleep 0.5

# ---- lossy relay: 5% drop ----
python3 /tmp/quic_e2e_lossy.py 0.05 7100 7110 >/dev/null 2>&1 & LP=$!
printf 'bindPort = 7111\nquicBindPort = 7110\nauth.method = "token"\nauth.token = "s"\n' > /tmp/quic_e2e_frps2.toml
printf 'serverAddr = "127.0.0.1"\nserverPort = 7100\ntransport.protocol = "quic"\nauth.token = "s"\n[[proxies]]\nname = "q"\ntype = "tcp"\nlocalPort = 2222\nremotePort = 6241\n' > /tmp/quic_e2e_c2.toml
/tmp/frps-test -c /tmp/quic_e2e_frps2.toml >/dev/null 2>&1 & FS=$!
sleep 1.5
$TFRPC -c /tmp/quic_e2e_c2.toml >/tmp/quic_e2e_c2.log 2>&1 & FC=$!
for i in $(seq 1 40); do grep -aq "ready" /tmp/quic_e2e_c2.log 2>/dev/null && break; sleep 0.5; done
timeout 120 python3 - <<'EOF' >> $RES
import socket, threading
data = bytes(range(256)) * 1024
s = socket.create_connection(("127.0.0.1", 6241), timeout=30)
got = []
def rx():
    total = 0
    while total < len(data):
        d = s.recv(65536)
        if not d: break
        got.append(d); total += len(d)
t = threading.Thread(target=rx); t.start()
s.sendall(data); t.join(90); s.close()
assert b"".join(got) == data, "lossy 256KB mismatch"
print("lossy 5%%: 256KB OK")
EOF
kill -9 $LP $FS $FC 2>/dev/null; pkill -9 -x tfrpc 2>/dev/null; pkill -9 -x frps-test 2>/dev/null; sleep 0.5

# ---- reconnect after frps restart ----
printf 'bindPort = 7000\nquicBindPort = 7000\nauth.method = "token"\nauth.token = "s"\n' > /tmp/quic_e2e_frps.toml
printf 'serverAddr = "127.0.0.1"\nserverPort = 7000\ntransport.protocol = "quic"\nauth.token = "s"\n[[proxies]]\nname = "q"\ntype = "tcp"\nlocalPort = 2222\nremotePort = 6241\n' > /tmp/quic_e2e_c.toml
/tmp/frps-test -c /tmp/quic_e2e_frps.toml >/dev/null 2>&1 & FS=$!
sleep 1.5
$TFRPC -c /tmp/quic_e2e_c.toml >/tmp/quic_e2e_c3.log 2>&1 & FC=$!
for i in $(seq 1 40); do grep -aq "ready" /tmp/quic_e2e_c3.log 2>/dev/null && break; sleep 0.5; done
kill -9 $FS 2>/dev/null; sleep 1
/tmp/frps-test -c /tmp/quic_e2e_frps.toml >/dev/null 2>&1 & FS=$!
for i in $(seq 1 100); do
  [ "$(grep -ac 'login ok' /tmp/quic_e2e_c3.log)" -ge 2 ] && break
  sleep 0.5
done
if [ "$(grep -ac 'login ok' /tmp/quic_e2e_c3.log)" -ge 2 ]; then
  timeout 30 python3 - <<'EOF' >> $RES
import socket
s = socket.create_connection(("127.0.0.1", 6241), timeout=15)
s.sendall(b"after-reconnect")
got = b""
while len(got) < 15:
    d = s.recv(4096)
    if not d: break
    got += d
assert got == b"after-reconnect", got
print("reconnect: OK")
EOF
else
  echo "reconnect: FAIL (no second login)" >> $RES
fi

# ---- stream limit: 5 concurrent connections under server maxIncomingStreams=2 ----
pkill -9 -x tfrpc 2>/dev/null; pkill -9 -x frps-test 2>/dev/null; sleep 0.5
printf 'bindPort = 7601\nquicBindPort = 7600\nauth.method = "token"\nauth.token = "s"\ntransport.quic.maxIncomingStreams = 2\n' > /tmp/quic_e2e_frps3.toml
printf 'serverAddr = "127.0.0.1"\nserverPort = 7600\ntransport.protocol = "quic"\nauth.token = "s"\n[[proxies]]\nname = "q"\ntype = "tcp"\nlocalPort = 2222\nremotePort = 6241\n' > /tmp/quic_e2e_c4.toml
/tmp/frps-test -c /tmp/quic_e2e_frps3.toml >/dev/null 2>&1 & FS=$!
sleep 1.5
$TFRPC -c /tmp/quic_e2e_c4.toml >/tmp/quic_e2e_c4.log 2>&1 & FC=$!
for i in $(seq 1 40); do grep -aq "ready" /tmp/quic_e2e_c4.log 2>/dev/null && break; sleep 0.5; done
timeout 90 python3 - <<'EOF' >> $RES
import socket, concurrent.futures
def one(i):
    s = socket.create_connection(("127.0.0.1", 6241), timeout=30)
    msg = b"conn-%d" % i
    s.sendall(msg)
    got = b""
    while len(got) < len(msg):
        d = s.recv(4096)
        if not d: break
        got += d
    s.close()
    assert got == msg, (i, got)
with concurrent.futures.ThreadPoolExecutor(5) as ex:
    list(ex.map(one, range(5)))
print("stream limit 2: 5 concurrent OK")
EOF
kill -9 $FS $FC 2>/dev/null
pkill -9 -x tfrpc 2>/dev/null; pkill -9 -x frps-test 2>/dev/null; sleep 0.5

echo DONE >> $RES
