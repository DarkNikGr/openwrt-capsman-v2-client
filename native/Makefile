# capagent — native CAPsMAN v2 CAP agent for OpenWrt (mipsel)
#
# Two ways to point the build at mbedTLS + a cross toolchain:
#
#   make SDK=/path/to/openwrt/sdk
#       uses staging_dir/toolchain-*/bin and staging_dir/target-*/usr
#       (this is how the mt7621 SDK tree builds it)
#
#   make TOOLCHAIN=... MBEDTLS=...
#       classic standalone toolchain + mbedtls source prefix
#
# `make check` runs the AES-CCM known-answer tests under qemu-mipsel.

SDK ?=

ifneq ($(SDK),)
TOOLCHAIN   ?= $(SDK)/staging_dir/toolchain-mipsel_24kc_gcc-13.3.0_musl/bin
MBEDTLS_INC ?= $(SDK)/staging_dir/target-mipsel_24kc_musl/usr/include
MBEDTLS_LIB ?= $(SDK)/staging_dir/target-mipsel_24kc_musl/usr/lib
STAGING_DIR ?= $(SDK)/staging_dir
else
TOOLCHAIN   ?= $(HOME)/openwrt-toolchain-24.10.0-ramips-mt7621_gcc-13.3.0_musl.Linux-x86_64/toolchain-mipsel_24kc_gcc-13.3.0_musl/bin
MBEDTLS     ?= $(HOME)/mbedtls-3.6.2
MBEDTLS_INC ?= $(MBEDTLS)/include
MBEDTLS_LIB ?= $(MBEDTLS)/library
endif

export STAGING_DIR

CROSS  ?= $(TOOLCHAIN)/mipsel-openwrt-linux-musl-
CC     := $(CROSS)gcc
STRIP  := $(CROSS)strip
QEMU   ?= qemu-mipsel

CFLAGS ?= -O2 -Wall -Wextra -Wno-unused-parameter
CFLAGS += -I$(MBEDTLS_INC) -Isrc
LIBS   := $(MBEDTLS_LIB)/libmbedtls.a \
          $(MBEDTLS_LIB)/libmbedx509.a \
          $(MBEDTLS_LIB)/libmbedcrypto.a

SRCS   := capagent.c src/extmux.c
HDRS   := src/*.inc src/extmux.h

all: capagent-mipsel

capagent-mipsel: $(SRCS) $(HDRS)
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LIBS) -static
	$(STRIP) $@
	@file $@
	@ls -lh $@

# AES-CCM known-answer tests (RFC 3610 + the c2 datachan header).
check: capagent-mipsel
	$(QEMU) ./capagent-mipsel --crypto-selftest

clean:
	rm -f capagent-mipsel

.PHONY: all check clean
