# Coverage-guided fuzzing (libFuzzer)

Four harnesses cover different layers of the TLS client:

| harness | target | measured coverage (tls.c) |
|---|---|---|
| `fuzz_tls.c` | full handshake, plaintext records (byte 0 selects TLS 1.2/1.3) | 28.3% regions |
| `fuzz_tls_rec.c` | post-handshake record layer with fixed keys (`#include tls.c`) | 11.4% |
| `fuzz_tls_inner.c` | decrypted payload path (harness encrypts input with fixed keys) | 8.1% |
| `fuzz_tls13_hs.c` | full TLS 1.3 handshake incl. encrypted Certificate/CertificateVerify/Finished | 19.5% (50% functions) |
| `fuzz_x509.c` | DER certificate parse + chain verify + hostname (embedded RSA and ECDSA CAs) | x509.c 62%, ecdsa.c 87% |
| `fuzz_pem.c` | PEM certificate and private-key loaders (trustedCaFile / certFile / keyFile paths) | x509.c 83% |

Build (clang with libFuzzer):

```sh
# plaintext handshake
clang -fsanitize=fuzzer,address,undefined -O1 -g -std=c11 -Iinclude -o tls_fuzzer \
    test/fuzz/fuzz_tls.c src/tls.c src/crypto.c src/x25519.c src/bignum.c \
    src/x509.c src/ecdsa.c src/log.c src/net.c src/base64.c -pthread

# encrypted handshake (includes tls.c for internals)
clang -fsanitize=fuzzer,address,undefined -O1 -g -std=c11 -Iinclude -o tls13hs_fuzzer \
    test/fuzz/fuzz_tls13_hs.c src/crypto.c src/log.c src/net.c src/x25519.c \
    src/x509.c src/ecdsa.c src/bignum.c src/base64.c -pthread
# (fuzz_tls_rec.c / fuzz_tls_inner.c use the same dependency list)
```

Run:

```sh
./tls_fuzzer -dict=test/fuzz/tls.dict -max_total_time=300 corpus/
```

Total executed during the audit: ~22M runs across harnesses, 0 crashes.
