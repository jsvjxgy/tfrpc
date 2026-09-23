#!/bin/bash
# verify shutdown(SHUT_WR) closes promptly across transports (frp semantics)
set -u
TFRPC=/home/tntxxd/Videos/frp/tfrpc/tfrpc
RES=/tmp/halfclose_result.txt
> $RES
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
run() {
  local label=$1 proto=$2 mux=$3
  pkill -9 -x tfrpc 2>/dev/null; pkill -9 -x frps-test 2>/dev/null; sleep 0.5
  printf 'bindPort = 7000\nkcpBindPort = 7000\ntransport.tcpMux = %s\nauth.method = "token"\nauth.token = "s"\n' "$mux" > /tmp/hc-frps.toml
  /tmp/frps-test -c /tmp/hc-frps.toml >/dev/null 2>&1 & local F=$!
  sleep 1.5
  printf 'serverAddr = "127.0.0.1"\nserverPort = 7000\ntransport.protocol = "%s"\ntransport.tcpMux = %s\nauth.token = "s"\n[[proxies]]\nname = "hc"\ntype = "tcp"\nlocalPort = 2222\nremotePort = 6229\n' "$proto" "$mux" > /tmp/hc-c.toml
  $TFRPC -c /tmp/hc-c.toml >/tmp/hc-c.log 2>&1 & local C=$!
  for i in $(seq 1 40); do grep -aq "ready" /tmp/hc-c.log 2>/dev/null && break; sleep 0.5; done
  local r=$(timeout 40 python3 -c "
import socket, os, time
t0=time.time()
s=socket.create_connection(('127.0.0.1',6229),timeout=15)
s.sendall(os.urandom(65536))
s.shutdown(socket.SHUT_WR)
s.settimeout(30)
try:
    while True:
        d=s.recv(65536)
        if not d: break
except Exception as e:
    print('%s after %.1fs' % (type(e).__name__, time.time()-t0)); raise SystemExit
print('EOF after %.1fs' % (time.time()-t0))
s.close()
" 2>&1 | tail -1)
  echo "$label: $r" >> $RES
  kill -9 $C $F 2>/dev/null; sleep 0.5
}
run "tcp  mux=false" tcp false
run "tcp  mux=true " tcp true
run "kcp  mux=false" kcp false
run "kcp  mux=true " kcp true
kill -9 $E 2>/dev/null; pkill -9 -x tfrpc 2>/dev/null
echo DONE >> $RES
