#!/bin/bash
# latency: 1000 ping-pong round trips of 64 bytes
set -u
RES=/tmp/latbench_result.txt
> $RES
pkill -9 -x tfrpc 2>/dev/null; pkill -9 -x frpc-go 2>/dev/null; pkill -9 -x frps-test 2>/dev/null; sleep 0.5
python3 -c '
import socket, threading
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("127.0.0.1",2222)); s.listen(64)
def h(c):
    try:
        while True:
            d=c.recv(65536)
            if not d: break
            c.sendall(d)
    except: pass
    c.close()
while True:
    c,_=s.accept(); threading.Thread(target=h,args=(c,),daemon=True).start()
' >/dev/null 2>&1 & E=$!
printf 'bindPort = 7000\ntransport.tcpMux = true\nauth.method = "token"\nauth.token = "s"\n' > /tmp/lb-frps.toml
/tmp/frps-test -c /tmp/lb-frps.toml >/dev/null 2>&1 & F=$!
sleep 2
run() {
  local label=$1 bin=$2
  printf 'serverAddr = "127.0.0.1"\nserverPort = 7000\nauth.token = "s"\ntransport.tcpMux = true\ntransport.tls.enable = false\n[[proxies]]\nname = "lb"\ntype = "tcp"\nlocalPort = 2222\nremotePort = 6237\n[proxies.transport]\nuseEncryption = false\n' > /tmp/lb-c.toml
  $bin -c /tmp/lb-c.toml >/dev/null 2>&1 & local C=$!
  sleep 4
  local r=$(timeout 60 python3 -c "
import socket, time, statistics
s = socket.create_connection(('127.0.0.1',6237), timeout=15)
s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
rtts = []
for i in range(1000):
    t0 = time.perf_counter()
    s.sendall(b'x' * 64)
    got = b''
    while len(got) < 64:
        d = s.recv(64 - len(got))
        if not d: break
        got += d
    rtts.append((time.perf_counter() - t0) * 1000)
s.close()
rtts.sort()
print('median=%.2fms p95=%.2fms mean=%.2fms' % (statistics.median(rtts), rtts[949], statistics.mean(rtts)))
" 2>&1 | tail -1)
  echo "$label: $r" >> $RES
  kill -9 $C 2>/dev/null; sleep 1
}
run "tfrpc  " /home/tntxxd/Videos/frp/tfrpc/tfrpc
run "frpc-go" /tmp/frpc-go
# direct baseline
r=$(timeout 30 python3 -c "
import socket, time, statistics
s = socket.create_connection(('127.0.0.1',2222), timeout=10)
s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
rtts = []
for i in range(1000):
    t0 = time.perf_counter()
    s.sendall(b'x' * 64)
    got = b''
    while len(got) < 64:
        d = s.recv(64 - len(got))
        if not d: break
        got += d
    rtts.append((time.perf_counter() - t0) * 1000)
s.close()
rtts.sort()
print('median=%.2fms p95=%.2fms' % (statistics.median(rtts), rtts[949]))
" 2>&1 | tail -1)
echo "direct : $r" >> $RES
kill -9 $E $F 2>/dev/null; pkill -9 -x tfrpc 2>/dev/null; pkill -9 -x frpc-go 2>/dev/null
echo DONE >> $RES
