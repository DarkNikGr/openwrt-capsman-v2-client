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
# `make check` runs the AES-CCM known-answer tests, the W33 policy selftest,
# and the W34 ownership/parser tests under qemu-mipsel.

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
HOSTCC ?= cc

W34_TEST_DIR := $(CURDIR)/.w34-tests
W53_TEST_DIR := $(CURDIR)/.w53-tests

VERSION := $(shell cat $(CURDIR)/../VERSION)

CFLAGS ?= -O2 -Wall -Wextra -Wno-unused-parameter
CFLAGS += -I$(MBEDTLS_INC) -Isrc -DCAPAGENT_VERSION=\"$(VERSION)\"
LIBS   := $(MBEDTLS_LIB)/libmbedtls.a \
          $(MBEDTLS_LIB)/libmbedx509.a \
          $(MBEDTLS_LIB)/libmbedcrypto.a

SRCS   := capagent.c src/extmux.c
HDRS   := src/*.inc src/*.h

all: capagent-mipsel

capagent-mipsel: $(SRCS) $(HDRS)
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LIBS) -static
	$(STRIP) $@
	@file $@
	@ls -lh $@

# AES-CCM known-answer tests (RFC 3610 + the c2 datachan header) and the
# W33 ownership-policy checks, both under qemu-mipsel.
# Host-style tests built for mipsel and executed with qemu-mipsel, so they run
# in the same ABI as the target binary.
w34-tests:
	mkdir -p $(W34_TEST_DIR)/run $(W34_TEST_DIR)/tmp
	$(CC) $(CFLAGS) -Wno-unused-function -Wno-format-truncation -static -I. \
	    -DOWN_RUN_DIR="\"$(W34_TEST_DIR)/run\"" \
	    -DOWN_TMP_DIR="\"$(W34_TEST_DIR)/tmp\"" \
	    -DOWN_PROBE_MS=0 -DOWN_TEST_PID_OK \
	    -o $(W34_TEST_DIR)/test_ownership ../tests/test_ownership.c
	W34_TEST_DIR=$(W34_TEST_DIR)/run $(QEMU) $(W34_TEST_DIR)/test_ownership
	$(CC) $(CFLAGS) -Wno-format-truncation -static -I. \
	    -o $(W34_TEST_DIR)/test_netifd_status ../tests/test_netifd_status.c
	$(QEMU) $(W34_TEST_DIR)/test_netifd_status

check: capagent-mipsel w34-tests extmux-test iw-freq-test rsn-test datachan-test chan-desc-test chan6-test
	$(QEMU) ./capagent-mipsel --crypto-selftest
	$(QEMU) ./capagent-mipsel --selftest-policy
	@got=$$($(QEMU) ./capagent-mipsel --version | awk '{print $$2}'); \
	 test "$$got" = "$(VERSION)" || { \
	     echo "version-test: --version reports $$got, ../VERSION says $(VERSION)" >&2; \
	     exit 1; }; \
	 echo "version-test: capagent $$got == VERSION $(VERSION)"

# W53: host-side gate for the hostapd EXT_AUTH_TX contract (wire format +
# one-shot fallback).  extmux.c is mbedTLS/nl80211-free on purpose.
extmux-test: $(SRCS) $(HDRS) tests/test_extmux.c
	mkdir -p $(W53_TEST_DIR)
	$(HOSTCC) -O2 -Wall -Wextra -Werror -Isrc -o $(W53_TEST_DIR)/test_extmux \
	    tests/test_extmux.c src/extmux.c
	$(W53_TEST_DIR)/test_extmux

# Pure host test: no cross-toolchain, radio, or manager required.
iw-freq-test: tests/test_iw_freq.c src/iw_freq.inc
	mkdir -p $(W53_TEST_DIR)
	$(HOSTCC) -O2 -Wall -Wextra -Werror -o $(W53_TEST_DIR)/test_iw_freq \
	    tests/test_iw_freq.c
	$(W53_TEST_DIR)/test_iw_freq

# Pure host test: RSN IE -> hostapd RSN options (PSK/MFPC/MFPR/SAE/OWE,
# group-mgmt cipher, external_rsn_ie/RSNXE relay).  No radio required.
rsn-test: tests/test_rsn.c src/rsn_decide.h
	mkdir -p $(W53_TEST_DIR)
	$(HOSTCC) -O2 -Wall -Wextra -Werror -o $(W53_TEST_DIR)/test_rsn \
	    tests/test_rsn.c
	$(W53_TEST_DIR)/test_rsn

# Pure host test: 0xD00B 0x000A descriptor builder (6 GHz band byte 0x04/0x06).
chan-desc-test: tests/test_chan_desc.c src/chan_desc.inc
	mkdir -p $(W53_TEST_DIR)
	$(HOSTCC) -O2 -Wall -Wextra -Werror -o $(W53_TEST_DIR)/test_chan_desc \
	    tests/test_chan_desc.c
	$(W53_TEST_DIR)/test_chan_desc

# Pure host test: 6 GHz width/op_class/centre -> hostapd config mapping.
chan6-test: tests/test_chan6.c src/chan6.inc
	mkdir -p $(W53_TEST_DIR)
	$(HOSTCC) -O2 -Wall -Wextra -Werror -o $(W53_TEST_DIR)/test_chan6 \
	    tests/test_chan6.c
	$(W53_TEST_DIR)/test_chan6

# Pure host test: 0x500b a2/0x402b key selection per VAP.  Includes
# src/datachan.inc with test VAP helpers; no radio or manager.
datachan-test: tests/test_datachan.c src/datachan.inc src/datapath.inc
	mkdir -p $(W53_TEST_DIR)
	$(HOSTCC) -O2 -Wall -Wextra -Werror -Wno-unused-function -Isrc \
	    -o $(W53_TEST_DIR)/test_datachan tests/test_datachan.c \
	    -lmbedcrypto
	$(W53_TEST_DIR)/test_datachan

clean:
	rm -f capagent-mipsel
	rm -rf $(W34_TEST_DIR) $(W53_TEST_DIR)

.PHONY: all check clean w34-tests extmux-test iw-freq-test rsn-test datachan-test chan-desc-test chan6-test
