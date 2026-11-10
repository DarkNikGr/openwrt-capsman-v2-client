TOOLCHAIN ?= $(HOME)/openwrt-toolchain-24.10.0-ramips-mt7621_gcc-13.3.0_musl.Linux-x86_64/toolchain-mipsel_24kc_gcc-13.3.0_musl/bin
MBEDTLS   ?= $(HOME)/mbedtls-3.6.2
MBEDTLS_LIB ?= $(MBEDTLS)/library
CROSS     ?= $(TOOLCHAIN)/mipsel-openwrt-linux-musl-

CC     := $(CROSS)gcc
STRIP  := $(CROSS)strip
CFLAGS ?= -O2 -Wall -Wextra -Wno-unused-parameter
LIBS   := $(MBEDTLS_LIB)/libmbedtls.a \
          $(MBEDTLS_LIB)/libmbedx509.a \
          $(MBEDTLS_LIB)/libmbedcrypto.a

all: capagent-mipsel

capagent-mipsel: capagent.c src/*.inc
	$(CC) $(CFLAGS) -I$(MBEDTLS)/include -o $@ capagent.c $(LIBS) -static
	$(STRIP) $@
	@file $@
	@ls -lh $@

clean:
	rm -f capagent-mipsel

.PHONY: all clean
