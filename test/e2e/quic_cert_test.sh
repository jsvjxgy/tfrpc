#!/bin/bash
# QUIC certificate verification matrix against frps
cd /home/tntxxd/Videos/frp/tfrpc || exit 1
TFRPC=./tfrpc
RES=/tmp/quic_cert_result.txt
> $RES
pkill -9 -x tfrpc 2>/dev/null; pkill -9 -x frps-test 2>/dev/null
pkill -9 -f echo_backend.py 2>/dev/null
sleep 0.5
python3 /tmp/echo_backend.py >/dev/null 2>&1 & BE=$!

D=/tmp/quic-cert; rm -rf $D; mkdir -p $D
openssl req -x509 -newkey rsa:2048 -nodes -keyout $D/ca-key.pem -out $D/ca.pem \
  -days 2 -subj "/CN=Test CA" 2>/dev/null
openssl req -x509 -newkey rsa:2048 -nodes -keyout $D/other-ca-key.pem -out $D/other-ca.pem \
  -days 2 -subj "/CN=Other CA" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout $D/srv-key.pem -out $D/srv.csr \
  -subj "/CN=localhost" 2>/dev/null
printf "subjectAltName=DNS:localhost\n" > $D/san.cnf
openssl x509 -req -in $D/srv.csr -CA $D/ca.pem -CAkey $D/ca-key.pem -CAcreateserial \
  -out $D/srv.pem -days 2 -extfile $D/san.cnf 2>/dev/null
openssl ecparam -genkey -name prime256v1 -noout -out $D/ec-key.pem 2>/dev/null
openssl req -new -key $D/ec-key.pem -out $D/ec.csr -subj "/CN=localhost" 2>/dev/null
openssl x509 -req -in $D/ec.csr -CA $D/ca.pem -CAkey $D/ca-key.pem -CAcreateserial \
  -out $D/ec.pem -days 2 -extfile $D/san.cnf 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout $D/cli-key.pem -out $D/cli.csr \
  -subj "/CN=client" 2>/dev/null
openssl x509 -req -in $D/cli.csr -CA $D/ca.pem -CAkey $D/ca-key.pem -CAcreateserial \
  -out $D/cli.pem -days 2 2>/dev/null

write_frps() { # cert key trusted_ca
  {
    echo 'bindPort = 7201'
    echo 'quicBindPort = 7200'
    echo 'auth.method = "token"'
    echo 'auth.token = "s"'
    [ -n "$1" ] && echo "transport.tls.certFile = \"$1\""
    [ -n "$2" ] && echo "transport.tls.keyFile = \"$2\""
    [ -n "$3" ] && echo "transport.tls.trustedCaFile = \"$3\""
  } > /tmp/cert-frps.toml
}
write_cli() { # addr trusted_ca server_name cert key
  {
    echo "serverAddr = \"$1\""
    echo 'serverPort = 7200'
    echo 'transport.protocol = "quic"'
    echo 'auth.token = "s"'
    [ -n "$2" ] && echo "transport.tls.trustedCaFile = \"$2\""
    [ -n "$3" ] && echo "transport.tls.serverName = \"$3\""
    [ -n "$4" ] && echo "transport.tls.certFile = \"$4\""
    [ -n "$5" ] && echo "transport.tls.keyFile = \"$5\""
    echo '[[proxies]]'
    echo 'name = "q"'
    echo 'type = "tcp"'
    echo 'localPort = 2222'
    echo 'remotePort = 6241'
  } > /tmp/cert-c.toml
}

run_case() { # label expect addr ca server_name cert key frps_cert frps_key frps_ca
  local label=$1 expect=$2
  write_frps "$8" "$9" "${10}"
  /tmp/frps-test -c /tmp/cert-frps.toml >/tmp/cert-frps.log 2>&1 & FS=$!
  sleep 1.2
  write_cli "$3" "$4" "$5" "$6" "$7"
  $TFRPC -c /tmp/cert-c.toml >/tmp/cert-c.log 2>&1 & FC=$!
  local got=fail
  for i in $(seq 1 24); do
    if grep -aq "ready" /tmp/cert-c.log 2>/dev/null; then got=ok; break; fi
    sleep 0.5
  done
  if [ "$got" = "$expect" ]; then echo "$label: PASS ($got)" >> $RES
  else echo "$label: FAIL (got=$got expect=$expect)" >> $RES; fi
  kill -9 $FC $FS 2>/dev/null
  pkill -9 -x tfrpc 2>/dev/null; pkill -9 -x frps-test 2>/dev/null
  sleep 0.3
}

run_case "self-signed no CA"           ok   "127.0.0.1" ""             ""          ""            ""            "$D/srv.pem" "$D/srv-key.pem" ""
run_case "good CA + localhost"         ok   "localhost"  "$D/ca.pem"   ""          ""            ""            "$D/srv.pem" "$D/srv-key.pem" ""
run_case "good CA + ip mismatch"       fail "127.0.0.1" "$D/ca.pem"   ""          ""            ""            "$D/srv.pem" "$D/srv-key.pem" ""
run_case "good CA + serverName"        ok   "127.0.0.1" "$D/ca.pem"   "localhost" ""            ""            "$D/srv.pem" "$D/srv-key.pem" ""
run_case "wrong CA"                    fail "localhost"  "$D/other-ca.pem" ""      ""            ""            "$D/srv.pem" "$D/srv-key.pem" ""
run_case "ECDSA cert + good CA"        ok   "localhost"  "$D/ca.pem"   ""          ""            ""            "$D/ec.pem"  "$D/ec-key.pem" ""
run_case "mTLS required, client cert"  fail "localhost"  "$D/ca.pem"   ""          "$D/cli.pem"  "$D/cli-key.pem" "$D/srv.pem" "$D/srv-key.pem" "$D/ca.pem"
run_case "mTLS not required, client cert" ok "localhost" "$D/ca.pem"   ""          "$D/cli.pem"  "$D/cli-key.pem" "$D/srv.pem" "$D/srv-key.pem" ""

kill -9 $BE 2>/dev/null
pkill -9 -f echo_backend.py 2>/dev/null
echo DONE >> $RES
