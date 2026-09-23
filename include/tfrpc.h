/*
 * SPDX-License-Identifier: GPL-3.0-only
 */
#ifndef TFRPC_H
#define TFRPC_H

#include <stdint.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdbool.h>

#define TFRPC_VERSION "0.1.0"

#define MAX_PROXIES 64
#define MAX_NAME_LEN 128
#define MAX_MSG_LEN 65536
#define UDP_PACKET_SIZE 1500
#define UDP_HEARTBEAT_INTERVAL 30
#define CONTROL_HEARTBEAT_INTERVAL 30
#define CONTROL_HEARTBEAT_TIMEOUT 90

typedef enum {
    PROXY_TCP,
    PROXY_UDP,
    PROXY_HTTP,
    PROXY_HTTPS,
} proxy_type_t;

typedef struct {
    char name[MAX_NAME_LEN];
    proxy_type_t type;
    char local_ip[64];
    int local_port;
    int remote_port;
    char custom_domains[8][128];
    int custom_domains_count;
    bool use_encryption;
    bool use_compression;
} proxy_cfg_t;

typedef struct {
    char server_addr[128];
    int server_port;
    char user[128];
    char token[128];
    char run_id[64];
    bool login_fail_exit;
    bool tcp_mux;
    int wire_v2;   /* 1 = wire protocol v2, 0 = v1 */
    int protocol_kcp; /* 1 = transport.protocol = "kcp" */
    bool tls_enable;              /* transport.tls.enable */
    bool tls_disable_first_byte;  /* transport.tls.disableCustomTLSFirstByte */
    char tls_server_name[128];    /* transport.tls.serverName (default serverAddr) */
    char tls_trusted_ca[256];     /* transport.tls.trustedCaFile */
    char tls_cert_file[256];      /* transport.tls.certFile */
    char tls_key_file[256];       /* transport.tls.keyFile */
    int pool_count; /* pre-negotiated work connection pool size for frps */
    proxy_cfg_t proxies[MAX_PROXIES];
    int proxy_count;
} tfrpc_config_t;

/* global config, filled by config.c */
extern tfrpc_config_t g_cfg;

/* global flags shared between control.c and v2.c */
extern _Atomic int g_login_rejected;   /* set when the server rejects the login */

/* ---- config.c ---- */
int config_load(const char *path);

/* ---- log.c ---- */
#define LOG_INFO 0
#define LOG_WARN 1
#define LOG_ERROR 2
#define LOG_DEBUG 3
void log_set_verbose(int v);
void log_msg(int level, const char *fmt, ...);

/* ---- net.c ---- */
int tcp_connect(const char *host, int port, int timeout_ms);
int read_full(int fd, void *buf, size_t n);
int64_t mono_ms(void);
int write_full(int fd, const void *buf, size_t n);
int random_bytes(uint8_t *buf, size_t n);

/* ---- tconn.c ---- */
/* unified connection: raw socket or yamux stream, with optional lazy AES
   (v1 CFB) or AEAD stream (v2 control channel) */
typedef struct tconn {
    int kind;   /* 0 = socket, 1 = yamux stream, 2 = kcp */
    int fd;
    void *tls;  /* tls_conn_t* when TLS wraps the socket */
    void *sess; /* yamux session (kind 1) */
    void *st;   /* yamux stream (kind 1) */
    void *kconn; /* kcp session (kind 2) */

    /* v1: AES-128-CFB with lazy IV */
    int crypto;   /* 1 = AES-128-CFB enabled */
    uint8_t ckey[16];
    void *enc_ctx;   /* NULL until first write (IV then sent) */
    int enc_iv_sent;
    void *dec_ctx;   /* NULL until first read (peer IV consumed) */
    int dec_iv_read;

    /* per-proxy snappy compression (frp useCompression) */
    int compress;   /* 1 = snappy stream enabled */
    void *zw;       /* snappy_writer_t* */
    void *zr;       /* snappy_reader_t* */

    /* v2: AEAD stream control channel */
    int aead;      /* 1 = AEAD stream enabled */
    int aead_xchacha; /* 1 = xchacha20-poly1305 (24-byte nonce), 0 = aes-256-gcm */
    uint8_t awrite_key[32];
    uint8_t aread_key[32];
    uint8_t awrite_nonce[24];      /* per-frame nonce */
    uint8_t awrite_stream_nonce[24]; /* fixed for AAD binding */
    int aead_w_header_sent;
    uint8_t aread_nonce[24];
    uint8_t aread_stream_nonce[24];
    int aead_r_header_sent;
    uint8_t *rxbuf;   /* decrypted pending bytes */
    size_t rxlen;
    size_t rxcap;
    int rx_closed;
} tconn_t;

tconn_t *tconn_socket(int fd);
tconn_t *tconn_stream(void *sess);
tconn_t *tconn_kcp(void *kconn);
tconn_t *tconn_kcp_tls(void *kconn, void *tls);
tconn_t *tconn_socket_tls(int fd, void *tls);
tconn_t *open_frp_conn(tfrpc_config_t *cfg);
void *tconn_tls_wrap(const tfrpc_config_t *cfg, int fd);
void *tconn_tls_wrap_kcp(const tfrpc_config_t *cfg, void *kconn);
void tconn_set_deadline(tconn_t *c, int timeout_ms);
int tconn_enable_crypto(tconn_t *c, const uint8_t key[16]);
int tconn_enable_compression(tconn_t *c);
int tconn_flush(tconn_t *c);
int tconn_enable_aead(tconn_t *c, const uint8_t write_key[32], const uint8_t read_key[32],
                      int xchacha);
int tconn_read_full(tconn_t *c, void *buf, size_t n);
int tconn_write_full(tconn_t *c, const void *buf, size_t n);
int tconn_read_some(tconn_t *c, void *buf, size_t n);
int tconn_wait_readable(tconn_t *c, int timeout_ms);
void tconn_close(tconn_t *c);
void tconn_abort(tconn_t *c);
void yamux_stream_abort(void *st);

/* ---- v2.c ---- */
int v2_client_handshake(tconn_t *c, tfrpc_config_t *cfg);
int v2_msg_write(tconn_t *c, uint16_t msg_type, const char *json, size_t len);
int v2_msg_read(tconn_t *c, uint16_t *msg_type, char **json, size_t *json_len);
void v2_derive_keys(const char *token, const uint8_t *client_hello, size_t ch_len,
                    const uint8_t *server_hello, size_t sh_len,
                    const char *algorithm, uint8_t c2s[32], uint8_t s2c[32]);
int v2_udp_packet_encode(uint8_t *out, size_t outcap,
                         const uint8_t *payload, size_t len,
                         const char *ip, int port);
int v2_udp_packet_decode(const uint8_t *body, size_t body_len,
                         uint8_t *payload, size_t payload_cap, size_t *payload_len,
                         char *ip, size_t ip_len, int *port);

/* ---- yamux.c ---- */
void *yamux_client_new(int fd);
void *yamux_client_new_io(int (*read_fn)(void *, void *, size_t),
                         int (*write_fn)(void *, const void *, size_t),
                         void (*shutdown_fn)(void *),
                         void (*close_fn)(void *), void *ctx);
void *yamux_open(void *sess);
int yamux_stream_read(void *st, uint8_t *buf, size_t n);
int yamux_stream_write(void *st, const uint8_t *buf, size_t n);
int yamux_stream_wait_readable(void *st, int timeout_ms);
int yamux_stream_close(void *st);
void yamux_close(void *sess);
void yamux_shutdown(void *sess);

/* ---- crypto.c ---- */
void md5_hex(const char *token, int64_t timestamp, char out[33]);
int crypto_memcmp_ct(const void *a, const void *b, size_t n);
void secure_zero(void *p, size_t n);
void *aes_cfb_new(const uint8_t *key, int key_len, const uint8_t *iv, int encrypt);
extern int tfrpc_aes_force_soft;   /* test hook: force software AES */
void aes_cfb_stream(void *ctxp, uint8_t *buf, size_t len);
void aes_cfb_free(void *ctxp);
int derive_key(const char *token, uint8_t *out, size_t out_len);
void sha256_digest(const uint8_t *data, size_t len, uint8_t out[32]);
typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t buffer[64];
} sha256_ctx_t;
void sha256_init(sha256_ctx_t *c);
void sha256_update(sha256_ctx_t *c, const uint8_t *data, size_t len);
void sha256_final(sha256_ctx_t *c, uint8_t out[32]);
void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len, uint8_t out[32]);
void hkdf_sha256(const uint8_t *secret, size_t secret_len,
                 const uint8_t *salt, size_t salt_len,
                 const uint8_t *info, size_t info_len,
                 uint8_t *out, size_t out_len);
void aes_gcm_seal(const uint8_t *key, int key_len, const uint8_t nonce[12],
                  const uint8_t *aad, size_t aad_len,
                  uint8_t *data, size_t len, uint8_t tag[16]);
int aes_gcm_open(const uint8_t *key, int key_len, const uint8_t nonce[12],
                 const uint8_t *aad, size_t aad_len,
                 uint8_t *data, size_t len, const uint8_t tag[16]);
void chacha20_poly1305_seal(const uint8_t key[32], const uint8_t nonce[12],
                            const uint8_t *aad, size_t aad_len,
                            uint8_t *data, size_t len, uint8_t tag[16]);
int chacha20_poly1305_open(const uint8_t key[32], const uint8_t nonce[12],
                           const uint8_t *aad, size_t aad_len,
                           uint8_t *data, size_t len, const uint8_t tag[16]);
void xchacha20_poly1305_seal(const uint8_t key[32], const uint8_t nonce24[24],
                             const uint8_t *aad, size_t aad_len,
                             uint8_t *data, size_t len, uint8_t tag[16]);
int xchacha20_poly1305_open(const uint8_t key[32], const uint8_t nonce24[24],
                            const uint8_t *aad, size_t aad_len,
                            uint8_t *data, size_t len, const uint8_t tag[16]);

/* ---- base64.c ---- */
size_t base64_encode(const uint8_t *in, size_t in_len, char *out);
size_t base64_decode(const char *in, size_t in_len, uint8_t *out, size_t out_cap);

/* ---- json.c ---- */
typedef struct {
    char *buf;
    size_t len;
    size_t cap;
    int comma;
} json_buf_t;
void jbuf_init(json_buf_t *b);
void jbuf_free(json_buf_t *b);
void jbuf_open(json_buf_t *b);
void jbuf_close(json_buf_t *b);
void jbuf_add_key(json_buf_t *b, const char *key);
void jbuf_append_raw(json_buf_t *b, const char *s, size_t n);
void json_escape_str(json_buf_t *b, const char *val);
void jbuf_add_str(json_buf_t *b, const char *key, const char *val);
void jbuf_add_int(json_buf_t *b, const char *key, int64_t val);
void jbuf_add_bool(json_buf_t *b, const char *key, bool val);
void jbuf_add_base64(json_buf_t *b, const char *key, const uint8_t *data, size_t len);
void jbuf_add_udpaddr(json_buf_t *b, const char *key, const char *ip, int port);

/* returns 1 if found */
int jget_str(const char *json, const char *key, char *out, size_t out_len);
int jget_int(const char *json, const char *key, int64_t *out);
int jget_bool(const char *json, const char *key, bool *out);
int jget_base64(const char *json, const char *key, uint8_t *out, size_t out_cap,
                size_t *out_len);
int jget_udpaddr(const char *json, const char *key, char *ip, size_t ip_len, int *port);

/* ---- proto.c ---- */
/* v1 message framing: 1 byte type + 8 byte big-endian length + json payload */
int msg_write_t(tconn_t *c, uint8_t type, const char *json, size_t len);
int msg_read_t(tconn_t *c, char **payload, size_t *payload_len);

int proto_send_login(tconn_t *c, tfrpc_config_t *cfg, const char *run_id);
int proto_send_new_proxy(tconn_t *c, const proxy_cfg_t *pxy);
int proto_send_new_work_conn(tconn_t *c, tfrpc_config_t *cfg);
int proto_send_ping(tconn_t *c, tfrpc_config_t *cfg);
int proto_send_udp_packet(tconn_t *c, const uint8_t *content, size_t len,
                          const char *remote_ip, int remote_port);
/* JSON builders shared by the v1 and v2 message codecs */
void proto_build_login(tfrpc_config_t *cfg, const char *run_id, json_buf_t *b);
void proto_build_new_proxy(const proxy_cfg_t *pxy, json_buf_t *b);
void proto_build_new_work_conn(tfrpc_config_t *cfg, json_buf_t *b);
void proto_build_ping(tfrpc_config_t *cfg, json_buf_t *b);

/* protocol-independent message types (mapped to v1 bytes / v2 type ids) */
typedef enum {
    FRP_LOGIN,
    FRP_LOGIN_RESP,
    FRP_NEW_PROXY,
    FRP_NEW_PROXY_RESP,
    FRP_NEW_WORK_CONN,
    FRP_REQ_WORK_CONN,
    FRP_START_WORK_CONN,
    FRP_PING,
    FRP_PONG,
    FRP_UDP_PACKET,
    FRP_UDP_PACKET_BIN,
} frp_msg_t;

int frp_send_msg(tconn_t *c, tfrpc_config_t *cfg, frp_msg_t type,
                 const char *json, size_t len);
int frp_recv_msg(tconn_t *c, tfrpc_config_t *cfg, frp_msg_t *type,
                 char **json, size_t *len);

/* ---- control.c ---- */
int control_run(tfrpc_config_t *cfg);

/* ---- workconn.c ---- */
void workconn_start(tfrpc_config_t *cfg);

#endif