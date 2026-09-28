#!/bin/bash
# deep frame-level fuzzing with a real QUIC peer (aioquic): after a valid
# handshake, the server injects malformed 1-RTT frames (needs: pip aioquic)
set -u
TFRPC=/home/tntxxd/Videos/frp/tfrpc/tfrpc
RES=/tmp/aioquic_result.txt
> $RES

if ! python3 -c "import aioquic" 2>/dev/null; then
  echo "aioquic not installed, skipping" >> $RES
  echo DONE >> $RES
  exit 0
fi

pkill -9 -x tfrpc 2>/dev/null
pkill -9 -f evil_aioquic 2>/dev/null
sleep 0.5
[ -f /tmp/qtest-cert.pem ] || openssl req -x509 -newkey rsa:2048 \
  -keyout /tmp/qtest-key.pem -out /tmp/qtest-cert.pem -days 1 -nodes \
  -subj "/CN=localhost" 2>/dev/null
printf 'serverAddr = "127.0.0.1"\nserverPort = 7000\ntransport.protocol = "quic"\nauth.token = "s"\n[[proxies]]\nname = "q"\ntype = "tcp"\nlocalPort = 2222\nremotePort = 6241\n' > /tmp/aioquic_c.toml

cleanup() {
  pkill -9 -x tfrpc 2>/dev/null
  pkill -9 -f evil_aioquic 2>/dev/null
}
trap cleanup EXIT

for mode in interop bad_stream bad_trunc bad_close bad_reset bad_flow bad_path bad_type random overlap_stream; do
  python3 /home/tntxxd/Videos/frp/tfrpc/test/e2e/evil_aioquic.py "$mode" >/dev/null 2>&1 & SP=$!
  sleep 0.8
  timeout -k 2 8 $TFRPC -c /tmp/aioquic_c.toml >/tmp/aioquic_$mode.log 2>&1
  kill -9 $SP 2>/dev/null
  pkill -9 -x tfrpc 2>/dev/null
  if grep -aqE "AddressSanitizer|runtime error|LeakSanitizer|Segmentation" /tmp/aioquic_$mode.log; then
    echo "$mode: FAIL" >> $RES
  else
    echo "$mode: survived" >> $RES
  fi
  sleep 0.3
done
echo DONE >> $RES
