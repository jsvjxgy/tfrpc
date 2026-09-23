#!/bin/bash
set -u
TFRPC=/home/tntxxd/Videos/frp/tfrpc/tfrpc
RES=/tmp/kcp_e2e_result.txt
> $RES
pkill -9 -x tfrpc 2>/dev/null; pkill -9 -x frps-test 2>/dev/null; sleep 0.5
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
  local mux=$1 label=$2
  pkill -9 -x frps-test 2>/dev/null; sleep 0.5
  printf 'bindPort = 7000\nkcpBindPort = 7000\ntransport.tcpMux = %s\nauth.method = "token"\nauth.token = "s"\n' "$mux" > /tmp/kcp-frps.toml
  /tmp/frps-test -c /tmp/kcp-frps.toml >/dev/null 2>&1 & local F=$!
  sleep 1.5
  printf 'serverAddr = "127.0.0.1"\nserverPort = 7000\ntransport.protocol = "kcp"\ntransport.tcpMux = %s\nauth.token = "s"\n[[proxies]]\nname = "k"\ntype = "tcp"\nlocalPort = 2222\nremotePort = 6222\n' "$mux" > /tmp/kcp-c.toml
  $TFRPC -c /tmp/kcp-c.toml >/tmp/kcp-run.log 2>&1 & local C=$!
  for i in $(seq 1 40); do grep -aq "ready" /tmp/kcp-run.log 2>/dev/null && break; sleep 0.5; done
  local r=$(timeout 40 python3 -c "
import socket, os, hashlib
data=os.urandom(1048576); h=hashlib.md5(data).hexdigest()
s=socket.create_connection(('127.0.0.1',6222),timeout=15)
s.sendall(data)
got=b''
s.settimeout(25)
try:
    while len(got)<len(data):
        d=s.recv(65536)
        if not d: break
        got+=d
except Exception: pass
print('%d %s' % (len(got), 'OK' if hashlib.md5(got).hexdigest()==h else 'MISMATCH'))
s.close()
" 2>&1 | tail -1)
  echo "$label: recv=$r" >> $RES
  kill -9 $C $F 2>/dev/null; sleep 0.5
}
run false "kcp tcpMux=false"
run true  "kcp tcpMux=true "
kill -9 $E 2>/dev/null; pkill -9 -x tfrpc 2>/dev/null
echo DONE >> $RES
