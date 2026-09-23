#!/bin/bash
# UDP proxy with an IPv6 local service (::1)
set -u
TFRPC=/home/tntxxd/Videos/frp/tfrpc/tfrpc
RES=/tmp/udp6_result.txt
> $RES
pkill -9 -x tfrpc 2>/dev/null; pkill -9 -x frps-test 2>/dev/null; sleep 0.5
python3 -c '
import socket, threading, time
s=socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("::1", 2222))
def loop():
    while True:
        try:
            d,a=s.recvfrom(2048); s.sendto(b"V6:"+d, a)
        except: break
threading.Thread(target=loop,daemon=True).start()
time.sleep(90)
' >/dev/null 2>&1 & E=$!
printf 'bindPort = 7000\nauth.method = "token"\nauth.token = "s"\n' > /tmp/u6-frps.toml
/tmp/frps-test -c /tmp/u6-frps.toml >/dev/null 2>&1 & F=$!
sleep 1.5
printf 'serverAddr = "127.0.0.1"\nserverPort = 7000\nauth.token = "s"\n[[proxies]]\nname = "u6"\ntype = "udp"\nlocalIP = "::1"\nlocalPort = 2222\nremotePort = 6224\n' > /tmp/u6-c.toml
$TFRPC -c /tmp/u6-c.toml >/tmp/u6-c.log 2>&1 & C=$!
for i in $(seq 1 30); do grep -aq "ready" /tmp/u6-c.log 2>/dev/null && break; sleep 0.5; done
r=$(timeout 12 python3 -c "
import socket
s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(8)
s.sendto(b'hello6', ('127.0.0.1',6224))
try:
    d,a=s.recvfrom(100); print(d.decode())
except Exception: print('TIMEOUT')
")
if echo "$r" | grep -q "V6:hello6"; then echo "IPv6 UDP: OK ($r)" >> $RES; else echo "IPv6 UDP: FAIL ($r)" >> $RES; fi
kill -9 $C $E $F 2>/dev/null; pkill -9 -x tfrpc 2>/dev/null
echo DONE >> $RES
