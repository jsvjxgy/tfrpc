#!/bin/bash
# monitor idle CPU/RSS/fds for each transport mode
set -u
RES=/tmp/resmon_result.txt
> $RES
hz=$(getconf CLK_TCK)
monitor() {
  local label=$1 cfg=$2 extra_frps=$3
  pkill -9 -x tfrpc 2>/dev/null; pkill -9 -x frps-test 2>/dev/null; sleep 0.5
  printf 'bindPort = 7000\nkcpBindPort = 7000\ntransport.tcpMux = true\n%s\nauth.method = "token"\nauth.token = "s"\n' "$extra_frps" > /tmp/rm-frps.toml
  /tmp/frps-test -c /tmp/rm-frps.toml >/dev/null 2>&1 & local F=$!
  sleep 1.5
  /home/tntxxd/Videos/frp/tfrpc/tfrpc -c $cfg >/tmp/rm-c.log 2>&1 & local C=$!
  for i in $(seq 1 40); do grep -aq "ready" /tmp/rm-c.log 2>/dev/null && break; sleep 0.5; done
  sleep 2
  local t0=$(awk '{print $14+$15}' /proc/$C/stat 2>/dev/null)
  sleep 8
  local t1=$(awk '{print $14+$15}' /proc/$C/stat 2>/dev/null)
  local cpu=$(( (t1-t0) * 100 / (hz * 8) ))
  local rss=$(awk '/VmRSS/{print $2}' /proc/$C/status 2>/dev/null)
  local fds=$(ls /proc/$C/fd 2>/dev/null | wc -l)
  local thr=$(awk '/Threads/{print $2}' /proc/$C/status 2>/dev/null)
  echo "$label: idle_cpu=${cpu}% rss=${rss}kB fds=$fds threads=$thr" >> $RES
  kill -9 $C $F 2>/dev/null; sleep 0.3
}
printf 'serverAddr = "127.0.0.1"\nserverPort = 7000\nauth.token = "s"\ntransport.tcpMux = true\ntransport.protocol = "tcp"\n[[proxies]]\nname = "m"\ntype = "tcp"\nlocalPort = 2222\nremotePort = 6230\n' > /tmp/rm-tcp-mux.toml
printf 'serverAddr = "127.0.0.1"\nserverPort = 7000\nauth.token = "s"\ntransport.tcpMux = false\ntransport.protocol = "tcp"\n[[proxies]]\nname = "m"\ntype = "tcp"\nlocalPort = 2222\nremotePort = 6230\n' > /tmp/rm-tcp-nomux.toml
printf 'serverAddr = "127.0.0.1"\nserverPort = 7000\nauth.token = "s"\ntransport.tcpMux = true\ntransport.protocol = "kcp"\n[[proxies]]\nname = "m"\ntype = "tcp"\nlocalPort = 2222\nremotePort = 6230\n' > /tmp/rm-kcp-mux.toml
printf 'serverAddr = "127.0.0.1"\nserverPort = 7000\nauth.token = "s"\ntransport.tcpMux = false\ntransport.protocol = "kcp"\n[[proxies]]\nname = "m"\ntype = "tcp"\nlocalPort = 2222\nremotePort = 6230\n' > /tmp/rm-kcp-nomux.toml
monitor "tcp  mux   " /tmp/rm-tcp-mux.toml ""
monitor "tcp  nomux " /tmp/rm-tcp-nomux.toml ""
monitor "kcp  mux   " /tmp/rm-kcp-mux.toml ""
monitor "kcp  nomux " /tmp/rm-kcp-nomux.toml ""
pkill -9 -x tfrpc 2>/dev/null; pkill -9 -x frps-test 2>/dev/null
echo DONE >> $RES
