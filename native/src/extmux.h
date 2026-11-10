/*
 * extmux -- multi-VAP hostapd external-RSN relay core (W8 reference)
 *
 * One AF_UNIX SOCK_DGRAM per BSS (VAP).  The socket identity *is* the VAP
 * identity; the relay maps ifname -> CAPsMAN port (phy<<8 | vapid).
 *
 * Session state is keyed by (port, STA MAC), never by MAC alone: the same
 * station may hold independent 4-way state on several BSSes of one CAP.
 *
 * This file is deliberately free of mbedTLS / nl80211 so that it can be
 * unit-tested on a host and linked into capagent unchanged.
 */
#ifndef EXTMUX_H
#define EXTMUX_H

#include <stdint.h>
#include <stddef.h>
#include <net/if.h>

#define EXTMUX_MAX_VAPS     16
#define EXTMUX_MAX_SESS     128
#define EXTMUX_MAX_TXN      8
#define EXTMUX_NAME_MAX     64
#define EXTMUX_EXT_MAX      4096

enum extmux_state {
    EXTMUX_FREE = 0,
    EXTMUX_ASSOC,          /* ASSOC seen, waiting for manager M1        */
    EXTMUX_WAIT_M2,        /* M1 delivered, waiting for STA M2          */
    EXTMUX_WAIT_M4,        /* M3 delivered, waiting for STA M4          */
    EXTMUX_PTK,            /* M4 seen, waiting for 0x201f PTK install   */
    EXTMUX_AUTHORIZED,     /* PTK installed and hostapd ACKed authorize */
    EXTMUX_FAILED          /* terminal until next ASSOC                 */
};

struct extmux_vap {
    int used;
    uint16_t port;                  /* CAPsMAN port = (phy << 8) | vapid */
    int ifindex;
    uint8_t bssid[6];
    char ifname[IF_NAMESIZE];
    int ext_fd;                     /* bound <dir>/ext-auth-<ifname>     */
    int ctrl_fd;                    /* bound abstract ctrl source        */
    /* one in-flight hostapd ctrl command per BSS; TX falls back to direct
     * injection instead of queuing, so EAPOL is never head-of-line blocked */
    int txn_active;
    int txn_type;                   /* 1 = TX, 2 = AUTHORIZE             */
    uint8_t txn_mac[6];
    uint64_t txn_deadline;
    unsigned txn_retries;
    /* W53: hostapd ctrl TX / authorize capability, learned once per BSS.
     * An EXT_AUTH_TX the hostapd build rejects (unknown command, FAULTY
     * parser, no associated STA) switches this BSS to direct control-port
     * TX for good: the EAPOL path never stalls on a per-frame retry and the
     * log says it exactly once. */
    int direct_tx;                  /* hostapd EXT_AUTH_TX unusable      */
    int direct_authz;               /* hostapd EXT_AUTH_AUTHORIZE unusable */
    unsigned long rx_events, tx_cmds, authz_ok, authz_fail;
};

struct extmux_sess {
    int used;
    uint16_t port;
    uint8_t mac[6];
    int state;
    int authorized;                 /* kernel/hostapd authorized         */
    int adopted;                    /* came from restart resync          */
    int stale;                      /* not confirmed by the last resync  */
    int authz_want;                 /* PTK installed, authorize pending  */
    unsigned m1, m2, m3, m4, ptk;
    unsigned retries;
    uint64_t t_assoc, t_last_rx, t_last_tx;
    uint64_t deadline;              /* hard 4-way deadline               */
    uint64_t retry_at;              /* next M1 retransmit                */
    uint8_t last_frame[512];        /* last manager->STA M1 (for retry)  */
    size_t last_frame_len;
    int last_frame_enc;
};

struct extmux_txn {
    int used;
    int type;                       /* 1 = TX, 2 = AUTHORIZE             */
    uint8_t mac[6];
    uint64_t deadline;
    unsigned retries;
};

struct extmux;

struct extmux_cb {
    void *ctx;
    void (*log)(void *ctx, const char *msg);
    /* STA -> CAP EAPOL must go to the manager as 0x201b with this port. */
    int  (*on_eapol)(void *ctx, const struct extmux_vap *v,
                     const uint8_t mac[6], const uint8_t *eapol, size_t len,
                     int encrypted);
    /* DELSTA (0x201a) to the manager. */
    int  (*on_delsta)(void *ctx, const struct extmux_vap *v,
                      const uint8_t mac[6]);
    /* Ask hostapd to deauthenticate (EXT_AUTH_DEAUTH). */
    int  (*on_deauth)(void *ctx, const struct extmux_vap *v,
                      const uint8_t mac[6], int reason);
    /* Fallback when EXT_AUTH_TX is unavailable: direct control-port TX. */
    int  (*on_direct_tx)(void *ctx, const struct extmux_vap *v,
                         const uint8_t mac[6], const uint8_t *eapol,
                         size_t len);
    /* Fallback when EXT_AUTH_AUTHORIZE is unavailable: authorize the
     * station straight through nl80211 (SET_STATION AUTHORIZED). */
    int  (*on_direct_authz)(void *ctx, const struct extmux_vap *v,
                            const uint8_t mac[6]);
    /* Raw 802.11 Auth/AssocReq from hostapd -> manager 0x2018. */
    void (*on_mgmt)(void *ctx, const struct extmux_vap *v,
                    const uint8_t *fr, size_t len);
    /* Session reached AUTHORIZED (after hostapd replied OK). */
    void (*on_authorized)(void *ctx, const struct extmux_vap *v,
                          const uint8_t mac[6]);
};

struct extmux *extmux_new(const char *ext_dir, const char *ctrl_dir,
                          const struct extmux_cb *cb);
void extmux_free(struct extmux *m);

/* Bind all VAP sockets, before hostapd starts accepting clients. */
int  extmux_add_vap(struct extmux *m, uint16_t port, const char *ifname,
                    int ifindex, const uint8_t bssid[6]);
int  extmux_del_vap(struct extmux *m, uint16_t port);
/* W33: the netdev was recreated (new ifindex); refresh the BSS and every
 * session that uses it before the next hostapd/direct transaction. */
int  extmux_set_ifindex(struct extmux *m, uint16_t port, int ifindex);
struct extmux_vap *extmux_vap_by_port(struct extmux *m, uint16_t port);
struct extmux_vap *extmux_vap_by_ifname(struct extmux *m, const char *ifname);
struct extmux_vap *extmux_vap_at(struct extmux *m, int idx);

void extmux_set_timeouts(struct extmux *m, unsigned fourway_ms,
                         unsigned m1_retry_ms, unsigned txn_ms);

/* poll() over every ext/ctrl socket; returns after <= timeout_ms. */
int  extmux_service(struct extmux *m, int timeout_ms);
/* drive timers explicitly (also called by extmux_service) */
void extmux_tick(struct extmux *m, uint64_t now_ms);

/* manager -> STA EAPOL (0x201c).  Queues EXT_AUTH_TX per VAP. */
int  extmux_tx(struct extmux *m, uint16_t port, const uint8_t mac[6],
               const uint8_t *eapol, size_t len, int encrypted);
/* manager installed the PTK for (port,mac); authorize via hostapd. */
int  extmux_ptk_installed(struct extmux *m, uint16_t port,
                          const uint8_t mac[6]);
/* manager told us the station is gone (0x201a) or hostapd said DISCONNECT */
void extmux_forget(struct extmux *m, uint16_t port, const uint8_t mac[6],
                   int notify_manager);
/* CAP-side timeout / policy wants the STA gone. */
int  extmux_deauth(struct extmux *m, uint16_t port, const uint8_t mac[6],
                   int reason);

/* --- restart recovery --- */
/* Mark all sessions stale; then adopt() every STA found in hostapd/iw. */
void extmux_resync_begin(struct extmux *m);
int  extmux_adopt(struct extmux *m, uint16_t port, const uint8_t mac[6],
                  int ifindex, int authorized);
/* Deauth stale, non-adopted sessions and clear the stale marks. */
void extmux_resync_finish(struct extmux *m);
/* Optional key-free journal: (port, mac, state, authorized, ts). */
int  extmux_save(struct extmux *m, const char *path);
int  extmux_load(struct extmux *m, const char *path);

/* Observability. */
struct extmux_stats {
    unsigned vaps, sessions, authorized, stale;
    unsigned deauth_timeouts, m1_retries, authz_retries, authz_failed;
    unsigned tx_ok, tx_fallback, tx_failed;
};
void extmux_stats(struct extmux *m, struct extmux_stats *out);

/* Debug helpers (unit test / hostapd_cli style dump). */
const char *extmux_state_name(int state);
int  extmux_session_count(struct extmux *m, uint16_t port);
void extmux_dump(struct extmux *m, void (*out)(void *, const char *),
                 void *outctx);

#endif /* EXTMUX_H */
