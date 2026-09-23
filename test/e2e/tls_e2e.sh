#!/bin/bash
set -u
RES=/tmp/tls_e2e.txt
> $RES
TFRPC=/home/tntxxd/Videos/frp/tfrpc/tfrpc
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
for mux in true false; do
  for tls in true false; do
    pkill -9 -x tfrpc 2>/dev/null; pkill -9 -x frps-test 2>/dev/null; sleep 0.5
    printf 'bindPort = 7000\ntransport.tcpMux = %s\nauth.method = "token"\nauth.token = "s"\n' "$mux" > /tmp/tls-frps.toml
    /tmp/frps-test -c /tmp/tls-frps.toml >/dev/null 2>&1 & F=$!
    sleep 1.5
    printf 'serverAddr = "127.0.0.1"\nserverPort = 7000\nauth.token = "s"\ntransport.tcpMux = %s\ntransport.tls.enable = %s\n[[proxies]]\nname = "t"\ntype = "tcp"\nlocalPort = 2222\nremotePort = 6232\n' "$mux" "$tls" > /tmp/tls-c.toml
    $TFRPC -c /tmp/tls-c.toml >/tmp/tls-run.log 2>&1 & C=$!
    for i in $(seq 1 40); do grep -aq "ready" /tmp/tls-run.log 2>/dev/null && break; sleep 0.5; done
    r=$(timeout 60 python3 -c "
import socket, os, hashlib
data=os.urandom(5242880); h=hashlib.md5(data).hexdigest()
s=socket.create_connection(('127.0.0.1',6232),timeout=20)
s.sendall(data)
got=b''
s.settimeout(40)
try:
    while len(got)<len(data):
        d=s.recv(262144)
        if not d: break
        got+=d
except Exception: pass
print('big=%d %s' % (len(got), 'OK' if hashlib.md5(got).hexdigest()==h else 'MISMATCH'))
s.close()
" 2>&1 | tail -1)
    echo "mux=$mux tls=$tls: $r" >> $RES
    kill -9 $C $F 2>/dev/null; sleep 0.5
  done
done
kill -9 $E 2>/dev/null; pkill -9 -x tfrpc 2>/dev/null
echo DONE >> $RES
