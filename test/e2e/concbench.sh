#!/bin/bash
# concurrent throughput: N connections each pushing 2MB, measure aggregate
set -u
RES=/tmp/concbench_result.txt
> $RES
pkill -9 -x tfrpc 2>/dev/null; pkill -9 -x frps-test 2>/dev/null; sleep 0.5
python3 -c '
import socket, threading
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("127.0.0.1",2222)); s.listen(256)
def h(c):
    try:
        while True:
            d=c.recv(262144)
            if not d: break
            c.sendall(d)
    except: pass
    c.close()
while True:
    c,_=s.accept(); threading.Thread(target=h,args=(c,),daemon=True).start()
' >/dev/null 2>&1 & E=$!
printf 'bindPort = 7000\ntransport.tcpMux = true\nauth.method = "token"\nauth.token = "s"\n' > /tmp/cb-frps.toml
/tmp/frps-test -c /tmp/cb-frps.toml >/dev/null 2>&1 & F=$!
sleep 2
run() {
  local label=$1 bin=$2 nconn=$3
  printf 'serverAddr = "127.0.0.1"\nserverPort = 7000\nauth.token = "s"\ntransport.tcpMux = true\ntransport.tls.enable = false\n[[proxies]]\nname = "cb"\ntype = "tcp"\nlocalPort = 2222\nremotePort = 6236\n[proxies.transport]\nuseEncryption = false\n' > /tmp/cb-c.toml
  $bin -c /tmp/cb-c.toml >/dev/null 2>&1 & local C=$!
  sleep 4
  local r=$(timeout 120 python3 -c "
import socket, threading, time, hashlib, os
N = $nconn
SZ = 2*1024*1024
errs = [0]; lock = threading.Lock()
def worker():
    try:
        data = os.urandom(SZ)
        s = socket.create_connection(('127.0.0.1',6236), timeout=30)
        s.sendall(data)
        got = b''
        s.settimeout(30)
        while len(got) < len(data):
            d = s.recv(262144)
            if not d: break
            got += d
        s.close()
        if got != data:
            with lock: errs[0] += 1
    except Exception:
        with lock: errs[0] += 1
t0 = time.time()
ts = [threading.Thread(target=worker) for _ in range(N)]
for t in ts: t.start()
for t in ts: t.join()
el = time.time() - t0
tot = N * SZ * 2 / 1048576.0
print('%.1f MB/s total (%d conns, %d errors)' % (tot/el if el>0 else 0, N, errs[0]))
" 2>&1 | tail -1)
  echo "$label x$nconn: $r" >> $RES
  kill -9 $C 2>/dev/null; sleep 1
}
run "tfrpc  " /home/tntxxd/Videos/frp/tfrpc/tfrpc 1
run "tfrpc  " /home/tntxxd/Videos/frp/tfrpc/tfrpc 10
run "tfrpc  " /home/tntxxd/Videos/frp/tfrpc/tfrpc 50
run "frpc-go" /tmp/frpc-go 1
run "frpc-go" /tmp/frpc-go 10
run "frpc-go" /tmp/frpc-go 50
kill -9 $E $F 2>/dev/null; pkill -9 -x tfrpc 2>/dev/null; pkill -9 -x frpc-go 2>/dev/null
echo DONE >> $RES
