#!/bin/bash
# basic regression: tcp/udp/http proxies, mux on/off, enc/comp
set -u
RES=/tmp/final_result.txt
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
python3 -c '
import http.server, threading
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        b = b"OK"
        self.send_response(200); self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", 2224), H).serve_forever()
' >/dev/null 2>&1 & H=$!
python3 -c '
import socket, threading
s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1",2223))
def loop():
    while True:
        try:
            d,a=s.recvfrom(2048); s.sendto(b"U:"+d, a)
        except: break
threading.Thread(target=loop,daemon=True).start()
import time; time.sleep(300)
' >/dev/null 2>&1 & U=$!
for mux in true false; do
  pkill -9 -x tfrpc 2>/dev/null; pkill -9 -x frps-test 2>/dev/null; sleep 0.5
  printf 'bindPort = 7000\nvhostHTTPPort = 8081\ntransport.tcpMux = %s\nauth.method = "token"\nauth.token = "secret123"\n' "$mux" > /tmp/frps-f.toml
  /tmp/frps-test -c /tmp/frps-f.toml >/dev/null 2>&1 & F=$!
  sleep 1.5
  for enc in true false; do
    for comp in true false; do
      cat > /tmp/reg-c.toml <<TOML
serverAddr = "127.0.0.1"
serverPort = 7000
auth.token = "secret123"
transport.tcpMux = $mux
[[proxies]]
name = "tcp"
type = "tcp"
localPort = 2222
remotePort = 6222
[proxies.transport]
useEncryption = $enc
useCompression = $comp
[[proxies]]
name = "udp"
type = "udp"
localIP = "127.0.0.1"
localPort = 2223
remotePort = 6223
[proxies.transport]
useEncryption = $enc
useCompression = $comp
[[proxies]]
name = "http"
type = "http"
localPort = 2224
customDomains = ["f.local"]
TOML
      $TFRPC -c /tmp/reg-c.toml >/tmp/reg-c.log 2>&1 & C=$!
      for i in $(seq 1 30); do [ "$(grep -ac ready /tmp/reg-c.log 2>/dev/null)" = "3" ] && break; sleep 0.5; done
      t=$(timeout 8 python3 -c "
import socket
try:
    s=socket.create_connection(('127.0.0.1',6222),timeout=5)
    s.sendall(b'ping'); s.settimeout(4)
    r=s.recv(10); s.close()
    print('ping' if r==b'ping' else 'BAD')
except Exception: print('ERR')
")
      u=$(timeout 8 python3 -c "
import socket
try:
    s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5)
    s.sendto(b'u', ('127.0.0.1',6223))
    d,_=s.recvfrom(100); print(d.decode())
except Exception: print('ERR')
")
      h=$(timeout 8 curl -s -H "Host: f.local" http://127.0.0.1:8081 2>/dev/null)
      echo "mux=$mux enc=$enc comp=$comp: tcp=$t udp=$u http=$h" >> $RES
      kill -9 $C 2>/dev/null; sleep 0.3
    done
  done
  kill -9 $F 2>/dev/null
done
kill -9 $E $U $H 2>/dev/null; pkill -9 -x tfrpc 2>/dev/null
echo DONE >> $RES
