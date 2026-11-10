// capagent - native MikroTik CAPsMAN v2 CAP agent for OpenWrt (mipsel)
// Speaks the CAPsMAN control protocol over TLS 1.2 (TCP 5246):
//   join 0x4029, NEWPHY 0x001d, create-vap 0x500b -> 0xd00b, destroy 0x600c -> 0xe00c,
//   echo 0x402b -> 0xc02b.
// Uses mbedTLS (already present on OpenWrt as libmbedtls).
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
#include <time.h>
#include <getopt.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <poll.h>
#include <fcntl.h>
#include <signal.h>
#include <dirent.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/nl80211.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/filter.h>
#ifndef NLA_F_NESTED
#define NLA_F_NESTED (1 << 15)
#endif
#ifndef NLA_TYPE_MASK
#define NLA_TYPE_MASK (~(NLA_F_NESTED | NLA_F_NET_BYTEORDER))
#endif

#include "extmux.h"        /* W8: per-BSS hostapd external-RSN relay */

#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"
#include "mbedtls/error.h"
#include "mbedtls/build_info.h"

/* The CAPsMAN v2 datachan is AES-256-CCM (RFC 3610); fail early if the
   mbedTLS build cannot do it instead of at the first create. */
#if !defined(MBEDTLS_CCM_C)
#error "mbedTLS was built without MBEDTLS_CCM_C (datachan AES-CCM)"
#endif
#include "mbedtls/ccm.h"

#define TYPE_JOIN              0x4029
#define TYPE_JOIN_RESP         0xC029
#define TYPE_ECHO              0x402B
#define TYPE_ECHO_RESP         0xC02B
#define TYPE_NEWPHY            0x001D
#define TYPE_PROVISION         0x500B
#define TYPE_CREATEVAP_RESP    0xD00B
#define TYPE_DESTROY           0x600C
#define TYPE_DESTROY_RESP      0xE00C
#define TYPE_DISCONNECT        0x002A

/* CAPsMAN v2 station/RSN messages (T4/T5):
   0x2018 CAP->MGR  {3E = raw 802.11 assoc/reassoc request, 3F = freq u32}
   0x201B CAP->MGR  {08 = STA MAC, 3E = EAPOL frame}      (STA -> authenticator)
   0x201C MGR->CAP  {08 = STA MAC, 3E = EAPOL frame}      (authenticator -> STA)
   0x201F MGR->CAP  key descriptors (0050/005A/005B)      (PTK/GTK/IGTK)
   0x201A MGR->CAP  {08 = STA MAC}                        (DELSTA)
   Acks 0xE01C / 0xE01F. */
#define TYPE_ASSOC_FRAME       0x2018
#define TYPE_EAPOL_RX          0x201B
#define TYPE_EAPOL_TX          0x201C
#define TYPE_KEY_INSTALL       0x201F
#define TYPE_DEL_STA           0x201A
#define TYPE_ASSOC_RESP        0x6019
#define TYPE_ASSOC_RESP2       0x2019
#define TYPE_MGMT_TX_RESP      0xE019
#define TYPE_EAPOL_TX_RESP     0xE01C
#define TYPE_KEY_RESP          0xE01F
#define TYPE_START             0x6016
#define TYPE_START_RESP        0xE016
#define TYPE_POLL              0x6027

#define ETH_P_EAPOL            0x888E
#define NL_MAX_MSG             8192

/* CAPsMAN v2 data channel (optional, UDP). The manager hands the id, port,
   cookie and AES-256 key to the CAP in the 0x500b create. */
#define DC_PORT_DEFAULT    5248
#define DC_ID_DEFAULT      428
#define DC_PFX_LEN         2    /* cleartext frame header: 0x10, flags    */
#define DC_HDR_LEN         8    /* c2 datachan header ("cdh")             */
#define DC_TAG_LEN         16
#define DC_NONCE_LEN       13
#define DC_COOKIE_MAX      16
#define DC_KEY_MAX         32
#define DC_MAX_PAYLOAD     2048
#define DC_KEEPALIVE_MS    2000     /* c2.ko manager keepalive timer */

/* frame header (pfx[0..1]), prepended by c2.ko cm_frag() */
#define DC_PFX_MAGIC       0x10     /* must be 0x10                         */
#define DC_PFX_FRAG        0x01     /* fragmented: 4 more header bytes      */
#define DC_PFX_KEEPALIVE   0x02     /* cookie keepalive, no cdh, no crypto  */

#define MAX_RADIOS   8

static uint64_t g_sta_ident;   /* last manager station-level ident */
static struct extmux *g_extmux; /* W8 multi-VAP ext-auth relay, or NULL */
static int g_phy_map[MAX_RADIOS] = { 0,1,2,3,4,5,6,7 };
static int real_phy(int phy)
{
    return (phy >= 0 && phy < MAX_RADIOS) ? g_phy_map[phy] : phy;
}
#define BODY_MAX   4096

struct cfg {
    const char *manager;        /* caps-man-addresses ("auto" = discover) */
    const char *port;
    const char *cert;
    const char *key;
    const char *ca_cert;        /* ca-certificate */
    const char *manager_cn;     /* caps-man-certificate-common-names */
    const char *cert_cn;        /* --cert-cn: fixed enrolment subject CN */
    int enroll;                 /* --enroll: force a new CSR this run */
    int no_enroll;              /* --no-enroll: never generate a CSR */
    const char *identity;       /* CAP identity (WinBox "identity") */
    const char *serial;         /* CAP serial (WinBox "serial") */
    const char *discovery_if;   /* discovery-interfaces */
    const char *slaves_datapath;
    uint8_t a1[4];
    uint8_t e70[4];
    int lock_to_manager;
    int dont_verify;
    int slaves_static;
    int nradios;
    char ifnames[MAX_RADIOS][32];
    uint8_t macs[MAX_RADIOS][6];
    uint8_t dc_keyidx;          /* 0x500b TLV 0xa9, default 0 */
    int crypto_selftest;
    int datachan;
    int apply;
    int no_ack;
    int inject_assoc;
    uint16_t dc_port;
    uint16_t dc_peer_port;      /* lab: manager datachan port (QEMU hostfwd) */
    uint16_t dc_id;
    uint8_t dc_key[DC_KEY_MAX];
    size_t dc_key_len;
    uint8_t dc_cookie[DC_COOKIE_MAX];
    size_t dc_cookie_len;
    /* EAPOL relay leg: 0 = control channel 0x201B, 1 = c2 datachan,
       2 = both.  See REPORT.md §3. */
    int eapol_leg;
    /* Split-MAC data plane (U11) and hostapd external-RSN adapter (U11/U3). */
    int datapath_bridge;
    int vap_auto;               /* create VAPs the manager asks for */
    int vap_mtu;
    int bcast_flood;            /* --bcast flood */
    int mgmt_relay;             /* --mgmt-relay */
    const char *ext_auth_dir;   /* --ext-auth-dir */
    const char *ext_ctrl_dir;   /* hostapd ctrl_interface dir (W8) */
    const char *state_file;     /* key-free extmux journal (W8) */
    int fourway_ms;             /* CAP-side 4-way deadline (W8) */
    int m1_retry_ms;            /* M1 retransmit interval (W8) */
    const char *manager_spec;   /* --manager as given, before discovery */
    int mgmt_source;            /* 0 auto, 1 nl80211, 2 monitor, 3 off */
    /* Lab/hwsim harness: bring up a minimal AP and drive the MLME locally. */
    const char *lab_iface;
    const char *lab_ssid;
    int lab_chan;
    /* W36: in-CAP MLME for one manager-provisioned VAP (no hostapd). */
    int mlme;
    int mlme_port;
};

static mbedtls_x509_crt g_ca;
static int g_ca_loaded = 0;

static void put16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v & 0xff; }
static uint16_t rd16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static void put32(uint8_t *p, uint32_t v) { p[0]=v>>24; p[1]=v>>16; p[2]=v>>8; p[3]=v; }

/* ---- modules (included in dependency order) ------------------------- */
#include "src/util.inc"   /* TLV/hex/sysfs helpers, join/NEWPHY builders */
#include "src/cert.inc"   /* 0x76 CSR enrolment, 0x77/0x78, CA pinning (W16) */
#include "src/nl80211.inc"   /* generic netlink: control-port EAPOL, NEW_KEY/SET_KEY, authorize */
#include "src/apply.inc"   /* 0x77/M2 config parse and UCI apply (argv, no shell) */
#include "src/datapath.inc"   /* split-MAC VAP registry + AF_PACKET bridge (U11) */
#include "src/datachan.inc"   /* c2 datachan: AES-CCM/plain, keepalive, per-VAP keys */
#include "src/channels.inc"   /* 0x000a channels, 0x00b7 set, vapid allocation */
#include "src/mgmt.inc"   /* EAPOL/key descriptors, 0x200e/0x2015/0x2018 helpers */
#include "src/mlme.inc"   /* W36: in-CAP MLME for one VAP (no hostapd) */
#include "src/vap.inc"    /* manager-driven VAP creation + hostapd (0x500b/0x6016) */
#include "src/discovery.inc"   /* manager discovery and MAC/ifname resolution */
#include "src/stats.inc"   /* 0x200e signal + 0x2015 counters/rates */
#include "src/lab.inc"   /* CAPAGENT_LAB: hwsim AP, mgmt relay, test injection */
#include "src/main.inc"   /* run loop, options, main */
