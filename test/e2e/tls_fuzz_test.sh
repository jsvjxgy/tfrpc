#!/bin/bash
# TLS state-machine fuzzing against an ASan build of tfrpc
set -u
RES=/tmp/tls_fuzz_result.txt
> $RES
MODES="mutate_sh truncated_sh huge_sh_len random_record sh_plus_garbage sh_cert_ske_mut ske_mut split_records record_flood"
pkill -9 -x tfrpc-asan 2>/dev/null; pkill -9 -x python3 2>/dev/null; sleep 0.5
printf 'serverAddr = "127.0.0.1"\nserverPort = 7000\nauth.token = "x"\ntransport.tls.enable = true\nloginFailExit = false\n[[proxies]]\nname = "p"\ntype = "tcp"\nlocalPort = 2222\nremotePort = 6222\n' > /tmp/tlsf-c.toml
for phase in "TLS1.2:1" "TLS1.3:0"; do
  pname=${phase%%:*}; force12=${phase##*:}
  for mode in $MODES; do
    python3 /tmp/tls_fuzz.py "$mode" 7 20 >/dev/null 2>&1 &
    FZ=$!
    if [ "$force12" = "1" ]; then
      TFRPC_TLS_FORCE12=1 ASAN_OPTIONS=detect_leaks=0 timeout 45 /tmp/tfrpc-asan -c /tmp/tlsf-c.toml >/tmp/tlsf-$mode.log 2>&1
    else
      ASAN_OPTIONS=detect_leaks=0 timeout 45 /tmp/tfrpc-asan -c /tmp/tlsf-c.toml >/tmp/tlsf-$mode.log 2>&1
    fi
    kill -9 $FZ 2>/dev/null
    if grep -qaE "AddressSanitizer|SEGV|runtime error|stack-overflow" /tmp/tlsf-$mode.log; then
      echo "$pname/$mode: CRASH" >> $RES
      grep -aE "AddressSanitizer|SUMMARY" /tmp/tlsf-$mode.log | head -2 >> $RES
    else
      echo "$pname/$mode: survived" >> $RES
    fi
    sleep 0.3
  done
done
pkill -9 -x tfrpc-asan 2>/dev/null
echo DONE >> $RES
