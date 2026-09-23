# tfrpc — 精简 frp 客户端（Tight FRP Client）

从零实现的**纯 C frp 客户端**（`frpc`），与官方 Go
[`frps`](https://github.com/fatedier/frp) 服务端线协议兼容。**零外部依赖**——
所有加密、压缩、TLS 均为项目内自实现。

为 MIPS 路由器（MT7621/OpenWrt）而写：Go 版 frpc 有 13–20 MB，本实现编译后
约 150 KB。

[English](README.md)

## 功能特性

| 功能 | 说明 |
|---|---|
| 代理类型 | `tcp`、`udp`、`http`、`https` |
| 多用户 | `user` 属性（服务端按用户命名空间隔离） |
| 认证 | `token` —— md5(token+时间戳)，与 frp 字节兼容 |
| 线协议 | **v1 和 v2**（`transport.wireProtocol`） |
| 传输方式 | 纯 TCP、**KCP over UDP**、**yamux 多路复用**（`transport.tcpMux`） |
| 加密 | 每代理 AES-128-CFB；v2 控制信道 AEAD（AES-256-GCM / XChaCha20-Poly1305）；PBKDF2-HMAC-SHA1 与 HKDF-SHA256 密钥派生 |
| AES 加速 | 运行时自动适配：x86 用 AES-NI，否则用 256 字节 S-box 软件 AES |
| 压缩 | 每代理 **snappy**（`useCompression`），与 `golang/snappy` 字节兼容 |
| TLS | **TLS 1.3 与 TLS 1.2**，完全自包含：X25519/ECDHE 密钥协商、HKDF-SHA256 / TLS PRF、AES-128-GCM 记录层 |
| 证书 | **RSA 与 ECDSA (P-256)**；多级证书链验证；DNS SAN 主机名校验；**mTLS** 客户端证书 |
| 配置格式 | TOML（子集） |

## 平台支持

tfrpc 仅支持 **Linux**，依赖两个 Linux 特有的接口：

- `/dev/urandom`：随机数
- `SOCK_CLOEXEC`：创建 socket

支持的架构：**x86_64、aarch64、armv7/armv6、mips/mipsel、riscv64、i386**。
可针对 musl 或 glibc 构建，支持静态链接（路由器场景推荐）。

**不支持** macOS、Windows 与 BSD；移植需要替换上述两个接口
（例如改用 `getrandom()`/`arc4random()` 与 socket 标志处理）。

## 快速开始

```sh
make
./tfrpc -c tfrpc.toml
```

最小配置（`tfrpc.toml`）：

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

## 构建

依赖：C11 编译器 + pthreads，无其他依赖。

### 本机构建

```sh
make                 # 生成 ./tfrpc
make clean
```

### 交叉编译（MT7621 / OpenWrt）

用 OpenWrt SDK 的 ramips/mt7621 工具链生成动态链接的 musl 小体积二进制，
可直接在路由器上运行（路由器自带 `libc.so` 和 `libgcc_s.so.1`）：

```sh
TC=$PWD/openwrt-toolchain-25.12.5-ramips-mt7621_gcc-14.3.0_musl.Linux-x86_64
BIN=$TC/toolchain-mipsel_24kc_gcc-14.3.0_musl/bin

export PATH=$BIN:$PATH            # 编译器 wrapper 需要 bin/ 在 PATH 中
make mipsle \
     CROSS=$BIN/mipsel-openwrt-linux-musl- \
     CC=gcc
# -> ./tfrpc  （ELF 32 位 MIPS，动态链接，解释器
#              /lib/ld-musl-mipsel-sf.so.1）
```

注意事项：

- 用 `CC=gcc`，不要用 `CC=mipsel-openwrt-linux-musl-cc`：部分工具链不带
  `-cc` wrapper，但都带 `-gcc`。
- 工具链打印的 `STAGING_DIR` 警告可以忽略。
- `mipsle` 目标会先 `clean` 并**覆盖**本机二进制；再次本机测试前请重新
  执行 `make`。

静态构建（不依赖路由器 libc）：

```sh
make mipsle CROSS=$BIN/mipsel-openwrt-linux-musl- CC=gcc LIBS="-static"
```

其他交叉编译：

```sh
make CROSS=<前缀>- CC=<编译器>
```

### 其他架构

代码是可移植 C11（不依赖 x86 内建函数；AES-NI 仅在 x86 上运行时启用）。
任何 musl/glibc 工具链均可，例如 `mipsel-linux-gnu-`、
`arm-linux-gnueabihf-`、`aarch64-linux-gnu-`。

## 配置说明

### 通用

```toml
serverAddr = "your-server.example"   # frps 地址
serverPort = 7000                    # frps bindPort
user = "alice"                       # 可选，多用户前缀
loginFailExit = true                 # 服务端拒绝登录时退出（默认 true）
```

### `[auth]`

```toml
[auth]
token = "secret123"                  # 必须与 frps 的 auth.token 一致
```

### `transport.*`

```toml
transport.wireProtocol = "v2"        # "v1"（默认）或 "v2"
transport.protocol = "kcp"           # "tcp"（默认）或 "kcp"；需 frps 开 kcpBindPort
transport.tcpMux = false             # 必须与 frps 一致（默认 true）
transport.poolCount = 20             # 提高 frps 的 work 连接池（poolCount + 10）
```

### `transport.tls.*`

TLS **默认启用**，与 frp v0.50.0 起的默认一致。

```toml
transport.tls.enable = true                      # 默认
transport.tls.serverName = "your.server"         # SNI + 校验主机名（默认 serverAddr）
transport.tls.trustedCaFile = "/path/ca.pem"     # 配置后启用证书验证
transport.tls.disableCustomTLSFirstByte = true   # 默认：不发 0x17 标记（frp 默认）
transport.tls.certFile = "/path/client.crt"      # 可选客户端证书（mTLS）
transport.tls.keyFile  = "/path/client.key"      # RSA 私钥（PKCS#1 或 PKCS#8 PEM）
```

行为与官方 frpc 一致：

- **未配置 `trustedCaFile`** —— 连接加密，但不校验服务端证书
  （`InsecureSkipVerify` 语义，与未配置 CA 文件的 frpc 完全一致）。用于在
  不可信网络中隐藏 token。
- **配置 `trustedCaFile`** —— 逐级验证服务端证书链，校验
  CertificateVerify / ServerKeyExchange 签名，并按 DNS SAN 校验主机名
  （支持通配符）。任一不匹配即中止握手。

### 代理配置

```toml
[[proxies]]
name = "ssh"
type = "tcp"                         # tcp | udp | http | https
localIP = "127.0.0.1"
localPort = 22
remotePort = 6022

[proxies.transport]
useEncryption = true                 # 每代理 AES-128-CFB（默认 true）
useCompression = true                # 每代理 snappy（默认 false）
```

`http` / `https` 代理用 `customDomains = ["a.example", "b.example"]` 代替
`remotePort`。

## 协议实现

### 线协议

- **v1**（默认）：`[1B 类型][8B 长度][JSON]` 消息；登录后控制信道用
  AES-128-CFB 加密。
- **v2**：8 字节魔数 + `[2B 类型][2B 标志][4B 长度]` 帧；ClientHello /
  ServerHello 握手 + HKDF-SHA256 密钥调度；AEAD 控制信道；二进制 UDP 包
  编解码。MIPS（无 AES-NI）优先 `xchacha20-poly1305`，有 AES-NI 的 CPU 用
  `aes-256-gcm` —— 与 Go 端选择一致。

### 加密

- 每代理数据：**AES-128-CFB**，密钥 = PBKDF2-HMAC-SHA1(token, "frp", 64)。
- v2 控制信道：AEAD，密钥由握手 transcript 派生。
- AES 自动适配：x86 有 **AES-NI** 时用硬件指令，否则用优化的**查表**
  软件实现（MIPS 也走这条路）。
- 处理顺序与 frp 一致：写时**先压缩再加密**；读时先解密再解压。

### 压缩

Snappy 流格式（与 `golang/snappy` 兼容）：流标识、带掩码 CRC32C 的数据块、
LZ77 块。已与 Go 库做双向逐字节交叉验证。典型文本线上体积约为原始 5%。

### TLS

- TLS 1.3（`TLS_AES_128_GCM_SHA256`）与 TLS 1.2
  （`ECDHE_RSA`/`ECDHE_ECDSA` + `AES_128_GCM_SHA256`），优先 1.3，回退 1.2。
- X25519 密钥协商、HKDF-SHA256 密钥调度、AES-128-GCM 记录层、Finished 校验。
- 证书验证：RSA（PKCS#1 / PSS）与 ECDSA P-256，多级证书链，DNS SAN
  主机名匹配，SHA-256 签名。
- mTLS：客户端证书 + CertificateVerify（RSA-PSS）。
- 仅当 `disableCustomTLSFirstByte = false` 时才发送 frp 的 `0x17` 首字节。

### KCP

kcp-go v5.6.13 线格式，FEC 组帧（10/3，与 frp 相同）。数据包为
`[seqid 4B][type 0xf1][size 2B][KCP 帧]`；校验包（`0xf2`）跳过，丢包由 KCP ARQ
恢复。会话参数与 frp 一致：stream 模式、`NoDelay(1,20,2,1)`、MTU 1350、
窗口 1024/1024、conv 1。与 frp 一样，当 `transport.tls.enable` 为 true（默认）
时 **TLS 运行在 KCP 之上**，会话加密且可满足服务端 `tls.force`。需要 frps 配置
`kcpBindPort`（0 表示禁用），且 `transport.tcpMux` 必须与服务端一致（非 mux KCP
时 frps 需设 `tcpMux = false`）。

## 安全说明

- **常数时间比较**：所有 MAC、AEAD tag、TLS Finished、签名摘要的校验均使用
  `crypto_memcmp_ct`，校验耗时不会泄露匹配程度。
- **敏感数据用后清零**：AES 轮密钥与 CFB 上下文、HMAC 填充、PBKDF2/HKDF
  中间值、TLS 握手/应用流量密钥与 transcript、X25519 私钥、RSA 私钥指数、
  连接密钥等（`secure_zero`，编译器无法优化掉）。
- **ECDSA 标量乘法与 RSA 私钥模幂使用常数时间 Montgomery ladder**（固定轮数
  + 掩码交换），私钥不会通过时间或分支泄露。
- **软件 AES 使用 256 字节 S-box**（常驻 L1 缓存）而非 4 KiB T-table，降低
  缓存时序泄露；有 AES-NI 的平台走硬件指令（本身即常数时间）。软件路径吞吐
  较低（x86 上约 25 MB/s，MIPS 更低）；对吞吐敏感时请使用支持 AES 指令的 CPU。
- 证书链校验的摘要比较为常数时间，TLS `Finished` / CertificateVerify 校验
  任一不匹配即中止。
- **信号由专用 `sigwait` 线程同步处理**（非异步信号处理器），停止标志只在
  普通代码中用 C11 原子操作读写。
- 线程共享状态（停止标志、连接 closed/aborted 标志、yamux 会话/流状态）使用
  C11 原子或互斥锁；关停路径等待工作线程结束后才释放其底层传输。

## 已知限制

- **UDP 载荷大于约 1400 字节会被截断** —— 这是 frp 的 `udpPacketSize`
  默认值（1500，含帧开销）所致，官方 Go frpc 同样如此。
- **`tcpMux` 必须与 frps 一致** —— 若设置 `transport.tcpMux = false`，
  frps 也必须用 `transport.tcpMux = false`。
- **隧道的半关闭** —— frps 在一方 EOF 时会同时关闭两个方向；如果客户端
  发送大量数据后先 `shutdown(SHUT_WR)` 再读取响应，可能丢失响应尾部。
  正常的请求/响应流程（HTTP、SSH）不受影响。
- TLS 证书签名仅支持 **SHA-256**（不支持 SHA-384/512 校验），ECDSA 校验仅
  支持 **P-256**。覆盖 frps 默认配置和常见 CA（含 Let's Encrypt）。
- 未实现：QUIC、xtcp/nat-hole、虚拟网络（vnet）、插件
  （socks5/http_proxy/static_file）、visitors（stcp/sudp）、管理面板、
  配置热重载/存储、YAML/INI 配置。

## 测试

```sh
make test           # 确定性密码学向量 + 解析器模糊测试（ASan/UBSan）
```

`make test` 运行仓库内置单元测试：SHA-256、HMAC、HKDF、AES-GCM、
AES-CFB、ChaCha20-Poly1305、XChaCha20-Poly1305、X25519 与 ECDSA P-256
的 NIST/RFC 标准向量，以及对 JSON、base64、v2 UDP、X.509 DER、snappy
解析器的随机模糊测试。

客户端已针对真实 `frps` 验证：

- v1/v2 × `tcpMux` 开/关 × TCP/UDP/HTTP/HTTPS 端到端
- 100 MB 传输，哈希校验（明文与加密）
- KCP 经有损 UDP 中继（5%/10% 丢包），5 MB 传输
- 证书验证矩阵（正确/错误 CA、错误主机名）、mTLS
- TLS 1.2 与 TLS 1.3、RSA 与 ECDSA 证书、多级证书链
- AddressSanitizer + UndefinedBehaviorSanitizer 压力测试（干净）
- ThreadSanitizer 压力测试（干净 —— 无数据竞态）
- `gcc -fanalyzer` 静态分析

## 文件结构

```
src/
  main.c      入口、信号处理
  config.c    TOML 子集解析
  control.c   控制连接：登录、注册、心跳、重连
  workconn.c  work 连接：tcp/http/https 中继 + udp 转发
  tconn.c     统一连接抽象（socket、yamux 流、KCP 或 TLS）+ 加密层
  yamux.c     精简 yamux 客户端（流控、ping、多流）
  kcp.c       KCP ARQ 状态机（移植自 kcp-go v5.6.13）
  kcpconn.c   KCP 会话：UDP socket、FEC 帧、reader/updater 线程
  v2.c        线协议 v2：帧、握手、AEAD 密钥、二进制 UDP
  proto.c     v1 消息帧 + 共享消息构造
  tls.c       TLS 1.3 / TLS 1.2 客户端
  x25519.c    X25519 密钥协商（RFC 7748）
  ecdsa.c     ECDSA P-256 验证
  x509.c      DER/X.509 证书与私钥解析
  bignum.c    大数运算、RSA PKCS#1/PSS 验证与签名
  snappy.c    snappy 流编解码
  crypto.c    MD5、SHA-1/256、HMAC、PBKDF2、HKDF、AES-128/256、GCM、
              ChaCha20-Poly1305、XChaCha20-Poly1305
  json.c      精简 JSON 构造/解析
  base64.c    base64
  net.c       TCP 辅助
  log.c       日志
```

## 许可证

tfrpc 以 **GNU 通用公共许可证第 3 版**发布，详见 [LICENSE](LICENSE)。

frp 协议及其常量来自 [frp](https://github.com/fatedier/frp)
（Apache-2.0）。本实现是客户端侧的独立重写。
