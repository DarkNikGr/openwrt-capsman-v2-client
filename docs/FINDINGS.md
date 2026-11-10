# CAPsMAN v2 control protocol — field notes

Reverse-engineered against RouterOS **7.25.1** (`ww2`, `c2.ko`, `localphy-*`),
validated against an RB1100AHx4 manager, a private CHR 7.25.1 lab, and a
Xiaomi Mi Router 4A Gigabit running this client. All multi-byte values are
**big-endian** unless stated otherwise.

These notes are a living reference. Items marked **open** are under
investigation; they are not claims that a path does not exist.

## Transport

TLS 1.2 over TCP **5246**. Every message:

```
u16 type | u16 port | 8-byte cookie/id | u16 body_len | body
```

* `port` = `(phy << 8) | vap` on create/destroy; replies echo it verbatim.
* `cookie` is copied from the request into the reply.
* body is a TLV stream: `u16 tag | u16 len | value`.
* `port` and the 64-bit id must be echoed on every reply; the manager drops
  the session otherwise (T13).

## Messages

| Type | Direction | Purpose |
|---|---|---|
| `0x4029` | CAP → manager | join (identity, board, serial, base MAC, capabilities) |
| `0xc029` | manager → CAP | join response; `0x77` is a nested opaque tree (certificate/aux data in captures), not a stock config push |
| `0x001d` | CAP → manager | NEWPHY: ciphers `0x5e`, chains `0x4b/0x4c`, bands `0x4d`, hw-type `0x83`, frequencies `0x05`, hw-caps `0x84`/`0x86` |
| `0x500b` | manager → CAP | create / configure VAP (MAC `0x08`, VLAN `0x7d`, datachan id `0x4a`, key id `0x61`); `a2` selects the datachan variant |
| `0xd00b` | CAP → manager | create response: MAC `0x08`, vapid `0x47`, ifindex `0x48`, ifname `0x49`, channels `0x000a` |
| `0x600c` / `0xe00c` | manager / CAP | destroy / ack |
| `0x402b` / `0xc02b` | both | echo / keepalive; manager→CAP with `a8/a9` is a rekey |
| `0x6016` / `0xe016` | manager / CAP | **start / config push** (SSID, RSN IE, channel); ack required |
| `0x2018` | CAP → manager | raw RX mgmt-frame report (Auth / AssocReq) |
| `0x2019` | manager → CAP | Auth response (mgmt TX) |
| `0x6019` | manager → CAP | AssocResp (mgmt TX) |
| `0x201b` | CAP → manager | EAPOL from station |
| `0x201c` / `0xe01c` | manager → CAP | EAPOL to station / ack |
| `0x201f` / `0xe01f` | manager → CAP | per-VAP key material (GTK/IGTK/PTK) / ack |
| `0x201a` | manager → CAP | station delete (DELSTA) |
| `0x6027` | manager → CAP | periodic status/traffic poll (~1/s per interface) |
| `0xe027` | CAP → manager | status response (empty ack accepted) |

## Channel provisioning

The manager builds its candidate list from the CAP's `0xd00b` reply. Each
channel descriptor is a top-level TLV `0x000a` containing:

```
000b 0004 <freq MHz BE32>      primary frequency
000c 0001 <width>              1=20, 2=40, 3=80, 4=160, 5=80+80, 6=320
000d 0004 <ccfi1 BE32>         centre frequency (required for width > 20)
0010 0001 <band>               manager band id
```

Band ids: `0x81` 2ghz-g, `0x82` 2ghz-n, `1` 5ghz-a, `2` 5ghz-n, `3` 5ghz-ac,
`4` 5ghz-ax, `6` 5ghz-be.

**The band byte is compared for equality with the configuration band.** Sending
`0x80` (the "2.4 GHz" bit used by the regulatory matcher) makes every channel
fail with `no available channels`. Use `0x81` for a `2ghz-g` configuration.

**The width byte is compared too, and there is no fallback.** A `20mhz`
configuration needs a `000c=01` descriptor, `20/40mhz` needs `02`, and
`20/40/80mhz` needs `03`. The manager does not derive band or width from the
frequency: it selects exactly the descriptor whose band and width match the
configuration and echoes that descriptor back in `0x6016`. Advertise **one**
descriptor per `(frequency, band, width)`; a duplicate triple makes the channel
unusable even though `radio print` lists both rows.

For the Xiaomi MT7603E/MT7612E (no HE) the reply therefore contains
`0x81@20`, `0x82@20/40` in 2.4 GHz and `0x01@20`, `0x02@20/40`, `0x03@20/40/80`
in 5 GHz. `0x0d` is the centre of the wider block: 40 MHz = primary ±10
(`5180→5190`, `5200→5190`, `5745→5755`), 80 MHz one of
5210/5290/5530/5610/5690/5775/5855. The 28-channel 5 GHz reply body is 4534
bytes, so the reply buffer must be at least 8 KiB.

Two more TLVs in the same `0xd00b` body are required:

* `0x0061` — current operating frequency (BE32).
* `0x00b7` — a list of **channel numbers** (u32 BE, not MHz). The manager
  filters candidates through this set; without it the candidate vector stays
  empty.

`updateHwChans()` clears and refills its vector on every reply, so channels must
be present in **every** create response (the master's reply is the one that
matters).

## Virtual interfaces

A create carries the interface identity only in the **MAC (`0x08`)**. The CAP
must answer with a **unique vapid** (`0x47`, 0..15) per `(phy, MAC)` and keep it
stable. Returning `0` for every interface makes the manager reject replies 2..N
as `CREATEVAP bad response`, and those virtual users stay in `CreatingVap`
forever.

`0x49` should be the interface name string; `0x48` is the ifindex.

## Configuration push (`0x6016`)

Sent after the master is active, and again per virtual interface. Example
(2.4 GHz, SSID `cap-hidden`):

```
0003 000a "cap-hidden"                 SSID
001f 0002 0000
000a 0012 000b ... channel descriptor   channel 2437, 20 MHz, band 0x81
0004 0007 46050300000000               RSN / security blob
0009 0001 01
0023 0004 00000064                     key id
0024 0004 00000001
```

The virtual `0x6016` (len ~240) carries `0x0003` SSID, a full `0x0004` RSN IE
(191 bytes, including vendor IEs) and `0x0026`. The RSN IE never contains the
PSK.

The CAP must answer `0xe016`; without it the manager does not proceed to the
next interface.

## VLAN

`0x500b` TLV `0x7d` is the datapath VLAN id (2 bytes), e.g. `001e` = 30. The
VLAN is per virtual interface and arrives with its create, before `0x6016`.

## Security (`0x201f`)

Per VAP, len 46 (group key):

```
0050 0021 { 0053 0001 01, 0054 0004 000fac04, 0051 0010 <16 bytes> }
005a 0005 { 0053 0001 01 }
```

Pairwise key, len 42:

```
0050 0026 { 0008 0006 <STA MAC>, 0054 0004 000fac04, 0051 0010 <16 bytes> }
```

`0x0054` is the cipher (`00-0f-ac-04` = CCMP), `0x0053` is the key index,
`0x0051` is the key material, and `0x0052` (when present) is the RSC/sequence.
Group keys use `NEW_KEY(GROUP)` + `SET_KEY(DEFAULT [, MULTICAST])`; IGTK/BIGTK
use `DEFAULT_MGMT`/`DEFAULT_BEACON`; a PTK uses `NEW_KEY(PAIRWISE, MAC)` then
`SET_STATION` with `STA_FLAGS2{mask=set=BIT(1)}`. Acknowledge with `0xe01f`.

The manager is the RSN authenticator in split-MAC mode. It validates the
passphrase and derives the PTK/GTK; the CAP only ever sees derived key bytes.

**The PMK/PSK/passphrase is never serialized by CAPsMAN v2.** No control
message and no datachan packet carries it. `0x201f` is derived key material,
`0x6016` is the SSID + RSN IE, and `0x500b` is radio/VLAN/datachan state. This
is why local forwarding needs a local key or the boot-pull fallback.

## Association (`0x2018`)

`0x2018` is the CAP→manager report of a raw received 802.11 management frame.
Body:

```
003e <len> <raw 802.11 frame, FC first, no FCS, >= 24 B>
000a 0008 { 000b 0004 <u32 freq> }       channel container
003f 0004 <i32 signal dBm>               RX signal (table "signal")
```

Rules proven live (T13):

* the frame must be a management frame (`fc & 0x0c == 0`);
* `addr2 != VAP MAC`;
* for Auth/AssocReq, `addr1 == addr3 == VAP BSSID`;
* the nested `0x0a/0x0b` frequency **must equal the VAP's current frequency**;
  missing/zero is dropped;
* the manager does **not** check the SSID IE;
* `0x3f` is the RX signal in **dBm** used by the registration table, not the
  frequency — sending the frequency makes the table show `signal=2437`.

Live proof on the production RB1100 (this project): a synthetic `0x2018`
Auth+Assoc registered rows for `cap-wifi1`, `cap-wifi1-virtual1` and
`cap-wifi2` (uptime, VLAN and `auth-type=wpa2-psk` shown). The rows disappear
when the CAP reconnects and the VAPs are recreated.

`ActAp::handleAuth` is the only path that allocates the `Peer`/`ActApSta`
object. Therefore the CAP must send the **Auth request first**, then the
AssocReq. An AssocReq for an unknown MAC logs `ActAp::handleFrame: <mac> no sta`
and is dropped. With Auth + AssocReq the manager runs `Peer::setRegistered`
(`regState` 0 → 1) and a registration-table row appears; `authorized`
(`regState` 2) waits for the real 4-way.

The manager answers with `0x2019` (Auth response) and `0x6019` (AssocResp),
and may follow with `0x6014` (station event), `0x201f` (keys) and `0x201c`
(EAPOL-TX). A CAP that sends no traffic for ~20 s is disconnected with
`activity timeout`, so `0x200e`/`0x2015` must keep flowing.

On the radio side, `NL80211_CMD_REGISTER_FRAME` with
`NL80211_ATTR_FRAME_TYPE = subtype << 4` delivers Auth/AssocReq to userspace as
`NL80211_CMD_FRAME`; no monitor interface is needed. hostapd also consumes the
same events, and multiple registrations are allowed.

## EAPOL (`0x201b` / `0x201c`)

The CAP relays EAPOL between the station and the manager:

* **STA → manager:** `0x201b`, body `{0008 STA MAC, 003e EAPOL}`. The default
  leg is the TLS control channel; a c2-datachan Ethernet `0x888e` leg is
  available as an option.
* **manager → STA:** `0x201c`, same body. The CAP injects the bare EAPOL with
  `NL80211_CMD_CONTROL_PORT_FRAME` (`FRAME`, `MAC`,
  `CONTROL_PORT_ETHERTYPE = 0x888e`, `CONTROL_PORT_NO_ENCRYPT`) and acks with
  `0xe01c`.

Control-port **RX** is exclusive to the socket that owns it. With hostapd
running, use the `external_rsn_auth` hostapd patch to forward RX EAPOL to the
CAP daemon (UNIX dgram), or run a minimal nl80211 AP daemon. Control-port TX,
`NEW_KEY`/`SET_KEY` and `SET_STATION` do not require ownership.

A full WPA2 4-way has been completed on hwsim with the EAPOL physically
crossing the userspace relay: msg2/msg4 arrive before authorization, msg1/msg3
are injected before a key exists, then the PTK/GTK are installed and the
station is authorized. Data then flows CCMP-encrypted.

## Datachan (c2, UDP 5248)

The manager creates the key-bearing datachan (`0x500b` with `a2`) only when
the VAP datapath is split-MAC **and** NEWPHY `0x84` byte 0 has bit 6 set
(`40 00 00 00`, little-endian; bit 7 must stay clear).

The variant is chosen by the manager's **datapath configuration**, not by
NEWPHY:

| `datapath.traffic-processing` | `a2` | payload after `cdh` |
|---|---|---|
| `on-cap` (or unset) | absent | no datachan |
| `on-capsman` | `01` | bare Ethernet frame (plaintext) |
| `on-capsman-secure` | `02` | AES-256-CCM ciphertext + 16-byte tag |

Secure mode is additionally gated by the join version vector `0xa7`. The
manager copies the first matching capability into `cap+0x450/+0x454`; the
whitelist is `{0x01, 0x00}`, so `0xa7 = 01 00 07` advertises support. If secure
is configured but the CAP is not eligible, the manager creates **no datachan**
rather than downgrading to plain.

### Create fields

`a2` is accompanied by:

```
00aa 16  keepalive cookie
00a6  2  UDP port (0x1480 = 5248)
00a8 32  AES-256-CCM key (16 B would be AES-128)
00a9  1  key index (0/1)
```

Every VAP gets its own key and cookie on the shared datachan. The create
carries the **master** MAC for all VLANs, so the VAP must be derived from the
VLAN (`0x7d`), not the MAC. The key is random, generated by the manager, and
sent in cleartext; it is not derived from TLS or the certificate, and there is
no CAP→manager key-install handshake.

### UDP framing

```
10 | flags | cdh[8] | body
cdh[0]      radio id
cdh[1]      bit7 keyidx | bits6..4 flags | bits3..0 vapid
cdh[2..7]   sequence, 48-bit little-endian
```

* `flags` bit0 = fragment, bit1 = keepalive; bits 2..7 are uninitialised on
  the wire and must be ignored.
* **Keepalive:** `10 02 || cookie` (unencrypted, no cdh, no tag). The manager
  matches the cookie to the VAP; without it the session ends with a
  "data channel timeout". Send it from source port 5248 — the manager expects
  that port (T9).
* **Data, plain (`a2=1`):** `body` is a bare Ethernet frame (≥ 14 B).
* **Data, secure (`a2=2`):** AES-CCM with a 16-byte tag, key = `0xa8` verbatim,
  AAD = `cdh[0..7]`, nonce13 = `cdh[0..7] || 00 00 00 00 00`. Ciphertext is
  `body[0 .. n-17]`; tag is the last 16 bytes.
* There is no on-wire encrypted/plaintext bit. `c2.ko` branches on a per-VAP
  `crypt` flag (`wlan+0x08`) set from the datapath mode. The robust receiver
  rule is: if a key is configured, try CCM (slot from `cdh[1]` bit7, then the
  other slot); on success it was encrypted, otherwise require a structurally
  valid Ethernet frame and treat it as plain; else drop.
* **Fragmentation** (`flags` bit0): `BE16(index+1) 00 00 | chunk`. The 7.25.1
  `cm_defrag` reads the descriptor too far, so reassembly does not complete;
  drop fragments.
* The sequence is written LE48 but `c2.ko`'s receive comparison reads BE48;
  the two disagree after seq `0xff` (a real 7.25.1 quirk). Keep sequences
  monotonic and do not wrap in practice.

### Rekey (`0x402b`)

The manager sends a 41-byte body:

```
00a8 0020 <32-byte AES-256-CCM key> 00a9 0001 <slot 0|1>
```

Header `402b 0000 00 <8B id> 0029`, port 0. The key is installed before the
ACK; the reply is `0xc02b` with the same port/id and **empty body**. A failure
body is 40 B: `0001 0004 00000002` + `0002 001c "Failed to rekey data channel"`;
send it only if the local install really fails.

Slot rules mirror `c2.ko`: two slots, an active index, one TX sequence and one
RX replay watermark. A changed slot resets TX sequence; the same slot with new
material keeps it. The old slot lives for 1000 ms after a changed slot, then
is deleted. RX uses `cdh[1]` bit7, and deleting the non-active slot resets the
replay watermark. The cookie and UDP port are untouched by a rekey.

### Manager-side association/key gate

The association half now works on the stock manager: `0x2018` Auth + AssocReq
creates the `Peer` and the registration-table row. The key half is still open
on a radio-less manager. On a radio-less CHR, the manager appends `a8/a9` to
`0x500b` but never runs its own `Cap::sendEcho` → `CNl::addChanKey` install,
never sends a `0x402b` challenge, and cannot decrypt/encrypt the datachan.
Keepalives still work, so the datachan looks "up" while the traffic key is
absent. This is the remaining hard gate; see the architecture notes. It is a
manager-side precondition, not a CAP framing issue.

## Status / traffic

All CAP→manager statistics travel on the TLS control channel, not the
datachan:

| Type | Contents |
|---|---|
| `0x200e` | station appeared/updated: MAC `07`, channel `0a`, age `15`, station-info `16`, `17/18`, signal dBm `19`, `1a` |
| `0x2015` | `PEERSTATSRESULT`: MAC `08`, BASIC `3d`, LIVERATE `40`, optional `a2`/`43` |
| `0x2013` | ACS/channel scan: channel `0a`, load `2a`, RSSI `2b/2c`, noise `2d`, radar `32`, rank `33` |

`0x200e` creates/updates a phy-level station-info record (signal at `+0x38`,
last-activity `+0x34`, present `+0x40`, MAC `+0x48`). It has **no** `regState`;
it cannot create a registration-table row.

`0x2015` is the counter/rate update. The 44-byte `0x3d` BASIC blob is:

| `0x3d` off | type | meaning | manager slot | console field |
|---|---|---|---|---|
| `+0x00` | u32 | channel frequency, MHz | link+0x20 | band detect, not printed |
| `+0x04` | u32 | TX PHY rate, kbit/s | link+0x18 (`×1000`) | `tx-rate` |
| `+0x08` | u32 | RX PHY rate, kbit/s | link+0x10 (`×1000`) | `rx-rate` |
| `+0x0c` | u64 | TX packets | link+0x28 | `packets` → tx |
| `+0x14` | u64 | RX packets | link+0x30 | `packets` → rx |
| `+0x1c` | u64 | TX bytes | link+0x38 | `bytes` → tx |
| `+0x24` | u64 | RX bytes | link+0x40 | `bytes` → rx |

The 8-byte `0x40` LIVERATE blob is TX bytes/s (`+0x00`) and RX bytes/s
(`+0x04`); the manager stores them at `link+0x48`/`link+0x50` (`<<3`, i.e.
bits/s). `uptime` and `last-activity` are manager-local and are never carried
in `0x2015`.

The manager's `Peer::updateStats` requires an existing Peer; the counters do
not create one. A registration-table row needs the association path above.
The per-field mapping and the corrected sender are proven by T7/T15; the
console table itself still needs a real Peer.

## Boot-pull fallback (config plane)

CAPsMAN v2 does not deliver the PSK, so `on-cap` deployments need a local key.
The supported fallback pulls it once at boot over the manager's REST API:

```
GET /rest/interface/wifi/configuration
GET /rest/interface/wifi/provisioning
Authorization: Basic <user:password>
```

The user needs `read,api,rest-api,sensitive`; without `sensitive` the
passphrase is omitted. The surgical variant rewrites only `option key`
(idempotent, no polling); the full variant regenerates SSID/VLAN/bridge
configuration. If the manager is unreachable or returns 401, the old
configuration is kept.

This is an out-of-band compatibility path, not a CAP-native feature. It places
the passphrase on the CAP and on the REST transport: restrict the REST service
to the CAP address, keep credentials mode 600, and prefer HTTPS. The
`on-capsman`/secure mode does not need it, because the manager authenticates.

## Gotchas

* `0x77` in `0xc029` is a nested opaque tree (certificate/aux data in the
  captures). Stock 7.25.1 sends no config tree there. Do not parse it as SSID
  or key data.
* `0x000a` channel TLVs must be contiguous with the rest of the body. An
  off-by-one in the running length inserts zero bytes and makes the manager's
  TLV walker stop before `0x0061`/`0x00b7`.
* A reply larger than 1 s is dropped by the manager's stale-request reaper.
* `updateHwChans()` only runs for the base radio user, i.e. the master reply;
  virtual replies do not wipe the vector.
* `0x500b` with `a2=0` is a pure VAP apply. Our client replies with `0xd00b`
  carrying the channel set; the manager consumes it for channel selection.
* The manager tears down a CAP after ~20 s without traffic; keep
  `0x200e`/`0x2015` flowing at ≤1.5 s while a station exists.
* A `0x2015` with a MAC that does not resolve to an existing Peer is dropped.
* Secure datachan and plain datachan are not interchangeable: sending CCM on
  `a2=1` (or plain on `a2=2`) is silently dropped by the receiver.
