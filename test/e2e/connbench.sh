#!/bin/bash
# connection establishment time: tfrpc startup -> proxy ready
set -u
RES=/tmp/connbench_result.txt
> $RES
pkill -9 -x tfrpc 2>/dev/null; pkill -9 -x frpc-go 2>/dev/null; pkill -9 -x frps-test 2>/dev/null; sleep 0.5
printf 'bindPort = 7000\ntransport.tcpMux = true\nauth.method = "token"\nauth.token = "s"\n' > /tmp/cn-frps.toml
/tmp/frps-test -c /tmp/cn-frps.toml >/dev/null 2>&1 & F=$!
sleep 2
run() {
  local label=$1 bin=$2 tls=$3
  printf 'serverAddr = "127.0.0.1"\nserverPort = 7000\nauth.token = "s"\ntransport.tcpMux = true\ntransport.tls.enable = %s\n[[proxies]]\nname = "cn"\ntype = "tcp"\nlocalPort = 2222\nremotePort = 6239\n' "$tls" > /tmp/cn-c.toml
  local best=99999
  for i in 1 2 3 4 5; do
    $bin -c /tmp/cn-c.toml >/tmp/cn-run.log 2>&1 & local C=$!
    local t0=$(date +%s%N)
    for j in $(seq 1 200); do
      grep -aq "ready" /tmp/cn-run.log 2>/dev/null && break
      sleep 0.01
    done
    local t1=$(date +%s%N)
    local ms=$(( (t1-t0)/1000000 ))
    [ $ms -lt $best ] && best=$ms
    kill -9 $C 2>/dev/null; sleep 0.3
  done
  echo "$label (tls=$tls): best=${best}ms" >> $RES
}
run "tfrpc  " /home/tntxxd/Videos/frp/tfrpc/tfrpc false
run "frpc-go" /tmp/frpc-go false
run "tfrpc  " /home/tntxxd/Videos/frp/tfrpc/tfrpc true
run "frpc-go" /tmp/frpc-go true
kill -9 $F 2>/dev/null; pkill -9 -x tfrpc 2>/dev/null; pkill -9 -x frpc-go 2>/dev/null
echo DONE >> $RES
