#!/bin/bash
# load test: throughput + CPU during 16MB transfer, per mode
set -u
RES=/tmp/loadmon_result.txt
> $RES
hz=$(getconf CLK_TCK)
python3 -c '
import socket, threading
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("127.0.0.1",2222)); s.listen(128)
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
  local label=$1 cfg=$2
  pkill -9 -x tfrpc 2>/dev/null; pkill -9 -x frps-test 2>/dev/null; sleep 0.5
  local mux=true
  grep -q "tcpMux = false" $cfg && mux=false
  printf 'bindPort = 7000\nkcpBindPort = 7000\ntransport.tcpMux = %s\nauth.method = "token"\nauth.token = "s"\n' "$mux" > /tmp/lm-frps.toml
  /tmp/frps-test -c /tmp/lm-frps.toml >/dev/null 2>&1 & local F=$!
  sleep 1.5
  /home/tntxxd/Videos/frp/tfrpc/tfrpc -c $cfg >/tmp/lm-c.log 2>&1 & local C=$!
  for i in $(seq 1 40); do grep -aq "ready" /tmp/lm-c.log 2>/dev/null && break; sleep 0.5; done
  sleep 1
  local t0=$(awk '{print $14+$15}' /proc/$C/stat 2>/dev/null)
  local r=$(timeout 60 python3 -c "
import socket, os, hashlib, time
data=os.urandom(16777216); h=hashlib.md5(data).hexdigest()
t0=time.time()
s=socket.create_connection(('127.0.0.1',6230),timeout=30)
s.sendall(data)
got=b''
s.settimeout(30)
try:
    while len(got)<len(data):
        d=s.recv(262144)
        if not d: break
        got+=d
except Exception: pass
el=time.time()-t0
print('%.1fMB/s %s' % (len(got)/1048576/el if el>0 else 0, 'OK' if hashlib.md5(got).hexdigest()==h else 'FAIL'))
s.close()
" 2>&1 | tail -1)
  local t1=$(awk '{print $14+$15}' /proc/$C/stat 2>/dev/null)
  local cpu=$(( (t1-t0) * 100 / (hz * 5) ))
  echo "$label: $r (cpu=$((cpu/5))% avg over ~5s)" >> $RES
  kill -9 $C $F 2>/dev/null; sleep 0.5
}
run "tcp  mux   " /tmp/rm-tcp-mux.toml
run "tcp  nomux " /tmp/rm-tcp-nomux.toml
run "kcp  mux   " /tmp/rm-kcp-mux.toml
run "kcp  nomux " /tmp/rm-kcp-nomux.toml
kill -9 $E 2>/dev/null; pkill -9 -x tfrpc 2>/dev/null; pkill -9 -x frps-test 2>/dev/null
echo DONE >> $RES
