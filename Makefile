# tfrpc - tight frp client
CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -std=c11 -pthread
LDFLAGS ?= -pthread

SRCS := src/main.c src/control.c src/workconn.c src/config.c \
        src/proto.c src/json.c src/crypto.c src/base64.c src/net.c src/log.c \
        src/tconn.c src/yamux.c src/v2.c src/kcp.c src/kcpconn.c src/snappy.c src/tls.c src/x25519.c src/bignum.c src/x509.c src/ecdsa.c
OBJS := $(SRCS:.c=.o)
HDRS := include/tfrpc.h include/kcp.h include/snappy.h include/tls.h include/x25519.h include/bignum.h include/x509.h include/ecdsa.h

TARGET := tfrpc

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

%.o: %.c $(HDRS)
	$(CC) $(CFLAGS) -Iinclude -c -o $@ $<

# Cross-compile. Example for MT7621 (MIPS little-endian soft-float):
#   make mipsle CROSS=mipsel-openwrt-linux-musl-
# Dynamically linked against the router's musl libc (the toolchain is dedicated
# to the router); use LIBS="-static" if you prefer a static build.
mipsle: clean
	$(CROSS)gcc -O2 -s -Wall -Wextra -std=c11 -pthread -Iinclude \
	  -o $(TARGET) $(SRCS) $(LDFLAGS) $(LIBS)
	file $(TARGET)

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean mipsle
TEST_SRCS := src/crypto.c src/x25519.c src/ecdsa.c src/bignum.c src/snappy.c \
             src/x509.c src/json.c src/base64.c src/log.c src/net.c src/config.c \
             src/v2.c src/tconn.c src/proto.c src/tls.c src/kcp.c src/kcpconn.c \
             src/yamux.c src/control.c src/workconn.c

test: test/unit_tests.c $(TEST_SRCS) $(HDRS)
	$(CC) $(CFLAGS) -Iinclude -fsanitize=address,undefined -o test/unit_tests test/unit_tests.c $(TEST_SRCS) -pthread
	test/unit_tests

.PHONY: test
