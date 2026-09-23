# tfrpc — Tight FRP Client

A from-scratch, **pure-C implementation of the frp client** (`frpc`),
wire-compatible with the official Go [`frps`](https://github.com/fatedier/frp)
server. No external dependencies — all cryptography, compression and TLS are
implemented in-tree.

It was written for MIPS routers (MT7621/OpenWrt) where a Go frpc is 13–20 MB.
The resulting binary is ~150 KB.

[中文文档](README.zh-CN.md)

## Features

| Feature | Notes |
|---|---|
| Proxy types | `tcp`, `udp`, `http`, `https` |
| Multi-user | `user` attribute (proxies are namespaced on the server) |
| Authentication | `token` — md5(token+timestamp), byte-compatible with frp |
| Wire protocol | **v1 and v2** (`transport.wireProtocol`) |
| Transports | plain TCP, **KCP over UDP**, **yamux** multiplexing (`transport.tcpMux`) |
| Encryption | per-proxy AES-128-CFB; v2 control channel AEAD (AES-256-GCM / XChaCha20-Poly1305); PBKDF2-HMAC-SHA1 and HKDF-SHA256 key derivation |
| AES acceleration | runtime CPU dispatch: x86 AES-NI, otherwise a 256-byte S-box software AES |
| Compression | per-proxy **snappy** (`useCompression`), byte-compatible with `golang/snappy` |
| TLS | **TLS 1.3 and TLS 1.2**, self-contained: X25519/ECDHE key agreement, HKDF-SHA256 / TLS PRF, AES-128-GCM records |
| Certificates | **RSA and ECDSA (P-256)**; multi-level chain verification; DNS SAN host matching; **mTLS** client certificates |
| Config format | TOML (subset) |

## Platform support

tfrpc targets **Linux** only. It relies on two Linux-specific interfaces:

- `/dev/urandom` for random bytes
- `SOCK_CLOEXEC` for socket creation

Supported architectures: **x86_64, aarch64, armv7/armv6, mips/mipsel,
riscv64, i386**. It builds against musl or glibc, and static linking is
supported (recommended for routers).

macOS, Windows and the BSDs are **not** supported; porting would require
replacing the two interfaces above (e.g. `getrandom()`/`arc4random()` and
socket-flag handling).

## Quick start

```sh
make
./tfrpc -c tfrpc.toml
```

Minimal config (`tfrpc.toml`):

```toml
serverAddr = "your-server.example"
serverPort = 7000
user = "alice"

[auth]
token = "secret123"

[[proxies]]
name = "ssh"
type = "tcp"
localIP = "127.0.0.1"
localPort = 22
remotePort = 6022
```

## Build

Requirements: a C11 compiler and pthreads. Nothing else.

### Native

```sh
make                 # -> ./tfrpc
make clean
```

### Cross-compilation (MT7621 / OpenWrt)

The OpenWrt SDK toolchain for ramips/mt7621 produces a small dynamically
linked musl binary that runs on the router as-is (the router provides
`libc.so` and `libgcc_s.so.1`):

```sh
TC=$PWD/openwrt-toolchain-25.12.5-ramips-mt7621_gcc-14.3.0_musl.Linux-x86_64
BIN=$TC/toolchain-mipsel_24kc_gcc-14.3.0_musl/bin

export PATH=$BIN:$PATH            # the compiler wrapper needs its bin/ in PATH
make mipsle \
     CROSS=$BIN/mipsel-openwrt-linux-musl- \
     CC=gcc
# -> ./tfrpc  (ELF 32-bit MIPS, dynamically linked, interpreter
#              /lib/ld-musl-mipsel-sf.so.1)
```

Notes:

- Use `CC=gcc`, not `CC=mipsel-openwrt-linux-musl-cc`: the `-cc` wrapper is not
  shipped by every toolchain, while `-gcc` is.
- `STAGING_DIR` warnings printed by the toolchain are harmless.
- The `mipsle` target runs `clean` first and **overwrites** the native binary;
  rebuild with plain `make` before running native tests again.

Static build (no router libc needed):

```sh
make mipsle CROSS=$BIN/mipsel-openwrt-linux-musl- CC=gcc LIBS="-static"
```

Generic cross builds:

```sh
make CROSS=<prefix>- CC=<compiler>
```

### Other architectures

The code is portable C11 (no x86 intrinsics are required; AES-NI is enabled at
runtime only on x86). Any musl/glibc toolchain works, e.g.
`mipsel-linux-gnu-`, `arm-linux-gnueabihf-`, `aarch64-linux-gnu-`.

## Configuration reference

### Common

```toml
serverAddr = "your-server.example"   # frps address
serverPort = 7000                    # frps bindPort
user = "alice"                       # optional multi-user prefix
loginFailExit = true                 # exit if the server rejects the login (default true)
```

### `[auth]`

```toml
[auth]
token = "secret123"                  # must match frps auth.token
```

### `transport.*`

```toml
transport.wireProtocol = "v2"        # "v1" (default) or "v2"
transport.protocol = "kcp"           # "tcp" (default) or "kcp"; needs kcpBindPort on frps
transport.tcpMux = false             # must match frps (default true)
transport.poolCount = 20             # raise frps' work-connection pool (poolCount + 10)
```

### `transport.tls.*`

TLS is **enabled by default**, matching frp since v0.50.0.

```toml
transport.tls.enable = true                      # default
transport.tls.serverName = "your.server"         # SNI + verified hostname (default: serverAddr)
transport.tls.trustedCaFile = "/path/ca.pem"     # enables certificate verification
transport.tls.disableCustomTLSFirstByte = true   # default: no 0x17 marker (frp default)
transport.tls.certFile = "/path/client.crt"      # optional client certificate (mTLS)
transport.tls.keyFile  = "/path/client.key"      # RSA private key (PKCS#1 or PKCS#8 PEM)
```

Behavior matches stock frpc:

- **No `trustedCaFile`** — the session is encrypted but the server certificate
  is not verified (`InsecureSkipVerify` semantics, exactly like frpc without a
  CA file). Use this to hide the token over untrusted networks.
- **With `trustedCaFile`** — the full server chain is verified level by level
  against the configured CA, the CertificateVerify / ServerKeyExchange
  signature is checked, and the hostname is matched against the DNS SAN
  (wildcards supported). Any mismatch aborts the handshake.

### Proxies

```toml
[[proxies]]
name = "ssh"
type = "tcp"                         # tcp | udp | http | https
localIP = "127.0.0.1"
localPort = 22
remotePort = 6022

[proxies.transport]
useEncryption = true                 # per-proxy AES-128-CFB (default true)
useCompression = true                # per-proxy snappy (default false)
```

`http` / `https` proxies use `customDomains = ["a.example", "b.example"]`
instead of `remotePort`.

## Protocol implementation

### Wire protocol

- **v1** (default): `[1B type][8B length][JSON]` messages; the control channel
  is AES-128-CFB encrypted after login.
- **v2**: 8-byte magic + `[2B type][2B flags][4B len]` frames; ClientHello /
  ServerHello handshake with a HKDF-SHA256 key schedule; AEAD control channel;
  binary UDP packet codec. `xchacha20-poly1305` is preferred on MIPS (no
  AES-NI), `aes-256-gcm` on AES-NI CPUs — matching Go's choice.

### Encryption

- Per-proxy data: **AES-128-CFB**, key = PBKDF2-HMAC-SHA1(token, "frp", 64).
- v2 control channel: AEAD keyed from the handshake transcript.
- AES auto-adapts: x86 **AES-NI** when available, otherwise an optimized
  **S-box** software implementation (also used on MIPS).
- Order of operations matches frp: **compress, then encrypt** on write;
  decrypt, then decompress on read.

### Compression

Snappy framed stream format (`golang/snappy` compatible): stream identifier,
data chunks with masked CRC32C, LZ77 blocks. Verified byte-for-byte in both
directions against the Go library. Typical text shrinks to ~5 % on the wire.

### TLS

- TLS 1.3 (`TLS_AES_128_GCM_SHA256`) and TLS 1.2
  (`ECDHE_RSA`/`ECDHE_ECDSA` + `AES_128_GCM_SHA256`), negotiated with 1.3
  preferred and a 1.2 fallback.
- X25519 key agreement, HKDF-SHA256 key schedule, AES-128-GCM records, a
  Finished check.
- Certificate verification: RSA (PKCS#1 / PSS) and ECDSA P-256, multi-level
  chains, DNS SAN host matching, SHA-256 signatures.
- mTLS: client certificate + CertificateVerify (RSA-PSS).
- The frp `0x17` first byte is sent only when
  `disableCustomTLSFirstByte = false`.

### KCP

kcp-go v5.6.13 wire format with FEC framing (10/3, like frp). Outgoing data
packets carry `[seqid 4B][type 0xf1][size 2B][KCP frame]`; incoming parity
packets (`0xf2`) are skipped and loss is recovered by KCP ARQ. Session settings
match frp: stream mode, `NoDelay(1,20,2,1)`, MTU 1350, window 1024/1024, conv 1.
Like frp, **TLS runs over KCP** when `transport.tls.enable` is true (the
default), so the session is encrypted and `tls.force` on the server is
satisfied. Requires `kcpBindPort` on frps (0 disables it there), and
`transport.tcpMux` must match the server (`tcpMux = false` on frps for
non-muxed KCP).

## Security notes

- **Constant-time comparisons** are used for every MAC, AEAD tag, TLS
  Finished and signature-digest check (`crypto_memcmp_ct`), so verification
  timing does not reveal how much of a value matched.
- **Sensitive data is wiped on release**: AES key schedules and CFB contexts,
  HMAC pads, PBKDF2/HKDF intermediates, TLS handshake/application traffic
  secrets and transcripts, X25519 private keys, RSA private exponents and all
  per-connection keys (`secure_zero`, which the compiler cannot elide).
- **ECDSA scalar multiplication and RSA private-key exponentiation use
  constant-time Montgomery ladders** (fixed round counts with masked swaps),
  so secret scalars/exponents do not leak through timing or branches.
- **Software AES uses a 256-byte S-box** that stays resident in L1 rather than
  a 4 KiB T-table, reducing cache-timing leakage. AES-NI platforms use the
  hardware instructions (which are constant-time). The software path costs
  throughput (~25 MB/s on x86, lower on MIPS); use an AES-capable CPU when
  throughput matters.
- Certificate chain verification compares digests in constant time, and the
  TLS `Finished` / CertificateVerify checks abort on any mismatch.
- **GHASH is software-only** (no PCLMULQDQ path). The 64-bit limb
  implementation sustains ~16 MB/s of TLS record processing on x86 and is the
  dominant cost for TLS sessions; disable `transport.tls.enable` or use
  per-proxy encryption (AES-CFB, which uses AES-NI) when throughput matters.
- **Signals are handled synchronously** by a dedicated `sigwait` thread rather
  than an asynchronous handler, so the stop flag is only touched from normal
  code with C11 atomic operations.
- Thread-shared state (stop flag, connection closed/aborted flags, yamux
  session/stream state) uses C11 atomics or mutexes; the shutdown path waits
  for worker threads and only then releases their transport.

## Limitations

- **UDP payloads larger than ~1400 bytes are truncated** — this is frp's
  `udpPacketSize` default (1500, including framing) and applies to a stock Go
  frpc too.
- **`tcpMux` must match frps** — if `transport.tcpMux = false` is set, frps
  must run with `transport.tcpMux = false` as well.
- **Half-close on tunnels** — frps tears down both directions when one side
  EOFs; a client that sends a large payload and then `shutdown(SHUT_WR)` before
  reading the reply may lose the tail of the reply. Normal request/response
  flows (HTTP, SSH) are unaffected.
- TLS certificate signatures must use **SHA-256** (SHA-384/512 are not
  verified), and ECDSA verification is **P-256** only. These cover frps'
  defaults and common CA setups (including Let's Encrypt).
- Not implemented: QUIC, xtcp/nat-hole, virtual network (vnet), plugins
  (socks5/http_proxy/static_file), visitors (stcp/sudp), the admin dashboard,
  config reload/store, YAML/INI configs.

## Testing

```sh
make test           # deterministic crypto vectors + parser fuzz (ASan/UBSan)
```

`make test` runs the in-tree unit tests: NIST/RFC vectors for SHA-256,
HMAC, HKDF, AES-GCM, AES-CFB, ChaCha20-Poly1305, XChaCha20-Poly1305,
X25519 and ECDSA P-256, plus randomized fuzz loops over the JSON, base64,
v2 UDP, X.509 DER and snappy parsers.

The client has also been verified against a real `frps` with:

- v1/v2 × `tcpMux` on/off × TCP/UDP/HTTP/HTTPS end-to-end
- 100 MB transfers, hash-verified (plain and encrypted)
- KCP through a lossy UDP relay (5 %/10 % drop), 5 MB transfers
- certificate verification matrix (correct/wrong CA, wrong hostname), mTLS
- TLS 1.2 and TLS 1.3, RSA and ECDSA certificates, multi-level chains
- AddressSanitizer + UndefinedBehaviorSanitizer stress runs (clean)
- ThreadSanitizer stress runs (clean — no data races)
- static analysis with `gcc -fanalyzer`

## Layout

```
src/
  main.c      entry point, signal handling
  config.c    TOML-subset parser
  control.c   control connection: login, register, heartbeat, reconnect
  workconn.c  work connections: tcp/http/https relay + udp forwarding
  tconn.c     unified conn (socket, yamux stream, KCP or TLS) + crypto layers
  yamux.c     minimal yamux client (flow control, ping, streams)
  kcp.c       KCP ARQ state machine (port of kcp-go v5.6.13)
  kcpconn.c   KCP session: UDP socket, FEC framing, reader/updater threads
  v2.c        wire protocol v2: frames, handshake, AEAD keys, binary UDP
  proto.c     v1 message framing + shared message builders
  tls.c       TLS 1.3 / TLS 1.2 client
  x25519.c    X25519 key agreement (RFC 7748)
  ecdsa.c     ECDSA P-256 verification
  x509.c      DER/X.509 certificate and private key parsing
  bignum.c    big integer arithmetic, RSA PKCS#1/PSS verify and sign
  snappy.c    snappy framed stream codec
  crypto.c    MD5, SHA-1/256, HMAC, PBKDF2, HKDF, AES-128/256, GCM,
              ChaCha20-Poly1305, XChaCha20-Poly1305
  json.c      minimal JSON builder/parser
  base64.c    base64
  net.c       TCP helpers
  log.c       logging
```

## License

tfrpc is released under the **GNU General Public License v3.0** — see
[LICENSE](LICENSE).

The frp protocol and its constants are from
[frp](https://github.com/fatedier/frp) (Apache-2.0). This implementation is an
independent reimplementation of the client side.
