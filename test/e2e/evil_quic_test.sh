#!/bin/bash
# hostile QUIC server: random/mutated/truncated/oversized/bogus Initials
set -u
TFRPC=/home/tntxxd/Videos/frp/tfrpc/tfrpc
RES=/tmp/evil_quic_result.txt
> $RES
pkill -9 -x tfrpc 2>/dev/null
pkill -9 -f evil_quic.py 2>/dev/null
sleep 0.5
printf 'serverAddr = "127.0.0.1"\nserverPort = 7000\ntransport.protocol = "quic"\nauth.token = "s"\n[[proxies]]\nname = "q"\ntype = "tcp"\nlocalPort = 2222\nremotePort = 6241\n' > /tmp/evil_quic_c.toml

cleanup() {
  pkill -9 -x tfrpc 2>/dev/null
  pkill -9 -f evil_quic.py 2>/dev/null
}
trap cleanup EXIT

for mode in random mutate truncate oversize falseinit silent; do
  python3 /home/tntxxd/Videos/frp/tfrpc/test/e2e/evil_quic.py "$mode" >/dev/null 2>&1 & EP=$!
  sleep 0.3
  timeout -k 2 6 $TFRPC -c /tmp/evil_quic_c.toml >/tmp/evil_quic_$mode.log 2>&1
  kill -9 $EP 2>/dev/null
  pkill -9 -x tfrpc 2>/dev/null
  if grep -aqE "AddressSanitizer|runtime error|LeakSanitizer|Segmentation" /tmp/evil_quic_$mode.log; then
    echo "$mode: FAIL" >> $RES
  else
    echo "$mode: survived" >> $RES
  fi
  sleep 0.3
done
echo DONE >> $RES
