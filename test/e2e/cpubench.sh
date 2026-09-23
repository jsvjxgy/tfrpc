#!/bin/bash
# CPU efficiency: CPU-seconds per 100MB transferred (mux, no tls/enc)
set -u
RES=/tmp/cpubench_result.txt
> $RES
pkill -9 -x tfrpc 2>/dev/null; pkill -9 -x frpc-go 2>/dev/null; pkill -9 -x frps-test 2>/dev/null; sleep 0.5
python3 -c '
import socket, threading
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("127.0.0.1",2222)); s.listen(64)
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
printf 'bindPort = 7000\ntransport.tcpMux = true\nauth.method = "token"\nauth.token = "s"\n' > /tmp/cp-frps.toml
/tmp/frps-test -c /tmp/cp-frps.toml >/dev/null 2>&1 & F=$!
sleep 2
hz=$(getconf CLK_TCK)
run() {
  local label=$1 bin=$2
  printf 'serverAddr = "127.0.0.1"\nserverPort = 7000\nauth.token = "s"\ntransport.tcpMux = true\ntransport.tls.enable = false\n[[proxies]]\nname = "cp"\ntype = "tcp"\nlocalPort = 2222\nremotePort = 6238\n[proxies.transport]\nuseEncryption = false\n' > /tmp/cp-c.toml
  $bin -c /tmp/cp-c.toml >/dev/null 2>&1 & local C=$!
  sleep 4
  local t0=$(awk '{print $14+$15}' /proc/$C/stat 2>/dev/null)
  local r=$(timeout 90 python3 -c "
import socket, os, time
data = os.urandom(4*1024*1024)
s = socket.create_connection(('127.0.0.1',6238), timeout=20)
total = 0
t0 = time.time()
for i in range(12):   # 12 x 4MB = 48MB down + 48MB up
    s.sendall(data)
    got = b''
    s.settimeout(20)
    while len(got) < len(data):
        d = s.recv(262144)
        if not d: break
        got += d
    total += len(got)
s.close()
el = time.time() - t0
print('%d bytes in %.1fs' % (total, el))
" 2>&1 | tail -1)
  local t1=$(awk '{print $14+$15}' /proc/$C/stat 2>/dev/null)
  local cpu=$(( (t1-t0) * 1000 / hz ))
  echo "$label: cpu=${cpu}ms for $r" >> $RES
  kill -9 $C 2>/dev/null; sleep 1
}
run "tfrpc  " /home/tntxxd/Videos/frp/tfrpc/tfrpc
run "frpc-go" /tmp/frpc-go
kill -9 $E $F 2>/dev/null; pkill -9 -x tfrpc 2>/dev/null; pkill -9 -x frpc-go 2>/dev/null
echo DONE >> $RES
