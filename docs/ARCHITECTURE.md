# Architecture — userspace CAP, official CAPsMAN v2

This note describes how the OpenWrt CAP fits under an official RouterOS 7.25.1
CAPsMAN v2 manager, the two datapath families (local vs split-MAC), and where
the remaining open item lives. Protocol details are in
[`FINDINGS.md`](FINDINGS.md).

## Roles

| Component | Runs on | Responsibility |
|---|---|---|
| CAPsMAN v2 (`ww2`) | RB1100 / CHR | CAP admission, radio/VAP model, channel selection, config push, VLAN, RSN authenticator, key derivation, registration table |
| `capagent` | OpenWrt AP | TLS join, NEWPHY, VAP create/destroy, channel reply, config ack, datachan, EAPOL relay, key install, statistics |
| hostapd/wpad | OpenWrt AP | beacon, 802.11 auth/assoc, RSN IE, AP-VLAN, control-port EAPOL |
| boot-pull (optional) | OpenWrt AP | one-shot REST fetch of configuration + passphrase for local forwarding |

The CAP never needs the WPA passphrase when the manager owns the RSN
authenticator. The manager never needs to know how the AP bridges client
traffic when the CAP forwards locally.

## Control plane

```
CAP                                                        Manager
 │  0x4029 join (identity, board, serial, MACs)  ──────────>  │
 │  <──────────  0xc029 join ok (+ optional cert / 0x77)     │
 │  0x001d NEWPHY (freqs, bands, ciphers, 0x84 caps)  ─────>  │
 │  <──────────  0x500b create VAP (MAC, VLAN, a2, key)      │
 │  0xd00b (vapid, ifindex, ifname, 0x000a channels)  ─────>  │
 │  <──────────  0x6016 start (SSID, RSN IE, channel)        │
 │  0xe016 ack  ─────────────────────────────────────────>    │
 │  <──────────  0x201f group keys                           │
 │  0xe01f ack  ─────────────────────────────────────────>    │
 │  <──────────  0x6027 poll (~1/s)                          │
 │  0xe027 status + 0x200e / 0x2015 statistics  ─────────>    │
```

Two CAP messages drive the manager's channel model: `0xd00b` must carry one
`0x000a` descriptor per frequency with the correct band id, and `0x00b7` must
carry the channel-number set. The manager also keys every interface off the
MAC in `0x08`, so the CAP must return a unique `vapid`.

## Datapath families

### A. Local forwarding (`on-cap`, default)

```
client ──802.11──> hostapd/mac80211 ──802.3──> kernel bridge / VLAN ──> uplink
                        │
                        └── EAPOL, keys, control: capagent ↔ manager
```

* The kernel converts 802.11 to 802.3 and bridges; userspace does not copy
  client frames.
* The CAP needs the PSK for the local 4-way (unless a remote-authenticator
  scheme is used). Static config or the boot-pull fallback supplies it.
* This is the production-recommended mode: least CPU, least RAM, no per-frame
  copy, no datachan.

### B. Split-MAC (`on-capsman` / `on-capsman-secure`)

```
client ──802.11──> hostapd (beacon/auth/assoc only)
                        │  mgmt + EAPOL
                        v
                    capagent ──TLS 5246──> manager (RSN authenticator)
                        │                  │
                        │  c2 UDP 5248     │  manager bridge / VLAN / L3
                        └──────────────────┘
```

Every client Ethernet frame crosses the c2 datachan. The manager is the only
L2 forwarder and the only RSN authenticator. Two wire variants exist:

| Manager datapath | `0x500b a2` | Payload | Notes |
|---|---|---|---|
| `on-capsman` | `1` | plaintext Ethernet | less crypto, traffic visible on the tunnel |
| `on-capsman-secure` | `2` | AES-256-CCM + 16-byte tag | requires join `0xa7` capability |

The client currently implements the **secure** codec (AES-CCM with a single
active TX key and replay watermark; the per-VAP key table is in place but
multi-VAP TX selection is still open). Rekey slot handling is proven on the
wire but not merged into the client yet. The plain variant is documented and
needs a mode branch before it can be selected. The manager never downgrades a
secure configuration to plain: it either creates the matching datachan or
none.

## Split-MAC chain, step by step

1. **Admission.** CAP joins with `0x4029`; NEWPHY advertises `0x84` bit 6
   (datachan support). Secure mode additionally needs `0xa7 = 01 00 07`.
2. **VAP + datachan.** Manager sends `0x500b` with the MAC, VLAN, `a2`, key,
   key index, UDP port and keepalive cookie. CAP replies `0xd00b` with the
   channel set and a unique vapid, and brings up the datachan.
3. **Keepalive.** CAP sends `10 02 || cookie` from UDP 5248. This keeps the
   session alive but does not install the traffic key.
4. **BSS start.** `0x6016` gives SSID, RSN IE and channel. CAP acks `0xe016`;
   manager sends GTK/IGTK in `0x201f`; CAP installs them and acks `0xe01f`.
5. **Association.** hostapd completes auth/assoc on air. CAP reports the raw
   Auth and AssocReq as `0x2018` (Auth first — it allocates the manager
   `Peer`). The manager creates the registration-table row.
6. **EAPOL.** STA EAPOL goes to the manager as `0x201b`. The manager runs the
   4-way and returns `0x201c`; CAP injects it on the cfg80211 control port.
7. **Keys + authorize.** `0x201f` PTK is installed with nl80211 `NEW_KEY`,
   then `SET_STATION AUTHORIZED`. The station can now pass data.
8. **Data.** `on-capsman`: CAP encapsulates client Ethernet into the c2
   datachan; the manager decrypts (secure), bridges and applies VLAN/L3.
9. **Stats.** `0x200e` reports station/signal, `0x2015` reports counters and
   rates on the `0x6027` poll.

### Sequence (secure mode)

```
STA            hostapd            capagent                 manager
 │  Auth/Assoc ──> │                   │                       │
 │                 │  0x2018 Auth ────>│  0x2018 ────────────> │ Peer created
 │                 │  0x2018 Assoc ───>│  0x2018 ────────────> │ regState=1
 │                 │<── 0x2019/0x6019 ─│<──────────────────────│
 │  EAPOL-Start ──>│  0x201b ─────────>│  0x201b ────────────> │ 4-way
 │<── EAPOL M1 ────│<── 0x201c ────────│<── 0x201c ────────────│
 │  EAPOL M2 ────> │  0x201b ─────────>│  0x201b ────────────> │
 │<── EAPOL M3 ────│<── 0x201c ────────│<── 0x201c ────────────│
 │  EAPOL M4 ────> │  0x201b ─────────>│  0x201b ────────────> │
 │                 │                   │<── 0x201f PTK ────────│
 │                 │                   │ NEW_KEY + AUTHORIZED  │
 │<==== CCMP data ======================> c2 datachan =========>│ bridge
```

## Where the current gate is

The CAP half is implemented and exercised. The open item is on the manager:

* In a radio-less CHR lab, the manager appends `a8/a9` to `0x500b` but never
  runs/succeeds its own `CNl::addChanKey` install (via `Cap::sendEcho`).
* It therefore sends no `0x402b` key challenge, cannot decrypt/encrypt the c2
  datachan, and never reaches `0x201c` → 4-way → `0x201f` PTK.
* Association is *not* the gate anymore: `0x2018` Auth + AssocReq already
  produces a `Peer` and a registration-table row on the stock manager.
* Whether a radio-bearing manager behaves differently, whether a
  controller-only RB needs a manager-side precondition, or whether a supported
  manager configuration/fix makes the key leg run is **under investigation**.
  The CAP cannot synthesize the manager's local key install.

This is why the docs describe the secure datachan as "implemented and proven
at the codec/control level, pending manager-side key installation", not as a
finished end-to-end product.

## Boot-pull fallback

For local forwarding, the PSK has to exist on the CAP. The fallback is a
one-shot config pull at boot:

```
CAP boot ──> cap-pull (procd oneshot)
              ├── GET /rest/interface/wifi/configuration
              ├── GET /rest/interface/wifi/provisioning
              ├── map ssid / passphrase / auth-type / vlan-id / channel
              ├── patch only `option key` (surgical) or regenerate BSS
              └── reload wifi; keep old config on failure
```

Properties and costs:

* manager remains the source of truth, but the pull is out-of-band;
* credentials (`rest.conf`, mode 600) live on the CAP;
* the REST user needs `read,api,rest-api,sensitive`;
* plain HTTP exposes the passphrase on the management network — restrict the
  service to the CAP address and prefer HTTPS;
* no persistent polling loop is required; a manual re-run handles manager
  changes;
* `on-capsman`/secure mode avoids the fallback entirely.

## Code map

| Path | Role |
|---|---|
| `native/capagent.c` | TLS client, NEWPHY/VAP/channel, datachan codec, EAPOL/key install, stats, lab harness |
| `native/deploy/capagent.init` | procd unit; maps conf to flags |
| `native/deploy/capagent.conf` | runtime config (`APPLY`, `DATACHAN`, identity, MACs) |
| `docs/FINDINGS.md` | wire reference |
| `docs/ARCHITECTURE.md` | this document |

Current tree status:

* `capagent.c` contains the datachan AES-CCM codec and keepalive,
  `0x201c`/`0x201b` EAPOL relay, `0x201f` key install, and the corrected
  `0x200e`/`0x2015` sender. Rekey is decoded/logged and acked; the slot-install
  path from T8 is still to be merged.
* `0x2018` association reporting exists in the `-DCAPAGENT_LAB` harness; the
  production hostapd/nl80211 wiring is still to be merged.
* The hostapd `external_rsn_auth` patch is a separate prototype; it is not in
  this tree yet.
* `--apply` consumes only an optional `0xc029` `0x77` tree; stock 7.25.1 does
  not send one.
