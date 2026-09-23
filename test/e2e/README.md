# End-to-end test scripts

These scripts drive `tfrpc` against a real `frps` (Go, built with
`go build -tags "noweb frps" -o /tmp/frps-test ./cmd/frps`).

| script | what it covers |
|---|---|
| `final_reg.sh` | tcp/udp/http proxies × tcpMux × enc × comp (8 combos) |
| `tls_e2e.sh` | 5 MB transfers × tcpMux × TLS on/off (4 combos) |
| `kcp_e2e.sh` | KCP transport, tcpMux on/off (2 combos) |
| `halfclose_test.sh` | `shutdown(SHUT_WR)` behaviour across transports |
| `udp6_test.sh` / `tcp6_test.sh` | IPv6 local services for UDP/TCP proxies |
| `https_test.sh` | HTTPS vhost proxy (SNI routing, local TLS) |
| `interrupt_test.sh` | frps restart → automatic reconnect |
| `evil_test.sh` / `evil_v2_test.sh` | hostile-server fuzzing (v1 and v2) |
| `resmon.sh` / `loadmon.sh` | idle CPU/RSS/fd and load CPU monitoring |
| `concbench.sh` | aggregate throughput at 1/10/50 concurrent connections |
| `latbench.sh` | ping-pong RTT (median/p95) |
| `cpubench.sh` | CPU-seconds per 48 MB transferred |
| `evil_frps.py` / `evil_v2.py` | malicious frps implementations |
| `tls_fuzz.py` / `tls_fuzz_test.sh` | protocol-aware TLS state-machine fuzzing (9 mutation modes x TLS 1.2/1.3) |
| `lossy_udp.py` | NAT-like lossy UDP relay for KCP ARQ tests |

Requirements: `frps-test`, `curl`, `python3`; some scripts expect helper
files under `/tmp` (configs are written by the scripts themselves).

Coverage-guided libFuzzer harnesses for the TLS client live in `test/fuzz/`.
