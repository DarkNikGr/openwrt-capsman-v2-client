# CAPsMAN v2 control protocol — field notes

Reverse-engineered against RouterOS **7.25.1** (`ww2`), validated live against
an RB1100AHx4 manager and a Xiaomi Mi Router 4A Gigabit running this client.
All multi-byte values are **big-endian** unless stated otherwise.

## Transport

TLS 1.2 over TCP **5246**. Every message:

```
u16 type | u16 port | 8-byte cookie/id | u16 body_len | body
```

* `port` = `(phy << 8) | vap` on create/destroy; replies echo it verbatim.
* `cookie` is copied from the request into the reply.
* body is a TLV stream: `u16 tag | u16 len | value`.

## Messages

| Type | Direction | Purpose |
|---|---|---|
| `0x4029` | CAP → manager | join (identity, board, serial, base MAC, capabilities) |
| `0xc029` | manager → CAP | join response; `0x77` is an **issued certificate**, not config |
| `0x001d` | CAP → manager | NEWPHY: ciphers `0x5e`, chains `0x4b/0x4c`, bands `0x4d`, hw-type `0x83`, frequencies `0x05`, hw-caps `0x84`/`0x86` |
| `0x500b` | manager → CAP | create / configure VAP (MAC `0x08`, VLAN `0x7d`, datachan id `0x4a`, key id `0x61`) |
| `0xd00b` | CAP → manager | create response: MAC `0x08`, vapid `0x47`, ifindex `0x48`, ifname `0x49`, channels `0x000a` |
| `0x600c` / `0xe00c` | manager / CAP | destroy / ack |
| `0x402b` / `0xc02b` | both | echo / keepalive |
| `0x6016` / `0xe016` | manager / CAP | **start / config push** (SSID, RSN IE, channel); ack required |
| `0x201f` | manager → CAP | per-VAP security material |
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

Per VAP, len 46:

```
0050 0021 { 0053 0001 01, 0054 0004 000fac04, 0051 0010 <16 bytes> }
005a 0005 { 0053 0001 01 }
```

`0x0054` is the cipher (`00-0f-ac-04` = CCMP) and `0x0051` is 16 bytes of key
material (GTK/IGTK in our captures). The PMK/PSK has not been observed in any
control message yet; the manager validates the passphrase and appears to run
the RSN authenticator role. `0x201f` should be acknowledged with `0xe01f`.

## Status poll (`0x6027`)

The manager sends `0x6027` (empty body) about once per second per interface.
The genuine CAP answers `0xe027` with `{0x08 MAC, 0x47 vap, 0x48 ifindex,
0x49 ifname, 0x61 freq}`; the manager reads only `0x61`. No traffic counters or
station list have been observed in this reply yet; they may travel over the c2
datachan, which is still under investigation.



## Datachan (c2, UDP 5248)

The manager creates the key-bearing datachan (`0x500b` with `a2=1`) only when
the VAP's datapath is `traffic-processing=on-capsman` **and** NEWPHY `0x84`
byte 0 has bit 6 set (`40 00 00 00`, little-endian; bit 7 must stay clear).
Otherwise it reports "data channel not supported".

`a2=1` adds:

```
00aa 16  keepalive cookie
00a6  2  UDP port (0x1480 = 5248)
00a8 32  AES-256-CCM key
00a9  1  key index (0/1)
```

Every VAP gets its own key and cookie on the shared datachan. The create
carries the **master** MAC for all VLANs, so the VAP must be derived from the
VLAN (`0x7d`), not the MAC.

UDP payload:

```
10 | flags | cdh[8] | body
cdh[0]      radio id
cdh[1]      bit7 keyidx | bits6..4 flags | bits3..0 vapid
cdh[2..7]   sequence, 48-bit little-endian
```

Keepalive: `10 02 || cookie` (unencrypted). The manager matches the cookie to
the VAP and keeps the datachan alive; without it the session ends with a
"data channel timeout".

The manager sends plain Ethernet frames on the datachan (observed: IPv6 ND
from the VAP MAC). The datachan has a **no-encryption** variant and a secure
AES-CCM variant; which one is used is a separate manager capability
(`cap+0x450/0x454`), not the `0x84` bit. The lab CHR selected the
no-encryption variant, which is why captured frames were plaintext. The CAP
has to bridge them to/from the local interface for `on-capsman` forwarding.
EAPOL is the same: RX over the datachan, TX to the CAP via `0x201c` over TLS.

Rekey: the manager sends `0x402b` with `0xa8` (32-byte key) and `0xa9` (slot)
and expects an empty `0xc02b`; install the new key at the slot and reset the
sequence state.

## Status / traffic

All CAP→manager statistics travel on the TLS control channel, not the
datachan:

| Type | Contents |
|---|---|
| `0x200e` | station appeared/updated: MAC `07`, channel `0a`, age `15`, station-info `16`, `17/18`, signal dBm `19`, `1a` |
| `0x2015` | `PEERSTATSRESULT`: MAC `08`, BASIC `3d` (3×u32 + 4×u64 counters), LIVERATE `40` (2×u32 bytes/s) |
| `0x2013` | ACS/channel scan: channel `0a`, load `2a`, RSSI `2b/2c`, noise `2d`, radar `32`, rank `33` |

`0x200e` creates the station on the manager and carries the signal; `0x2015`
updates its counters and rates. The manager's registration table only reflects
stations it authenticates itself, so these are most useful in the split-MAC
datachan mode.

## Gotchas

* `0x77` in `0xc029` is an X.509 certificate, not a config tree. Do not parse
  it as SSID/key data.
* `0x000a` channel TLVs must be contiguous with the rest of the body. An
  off-by-one in the running length inserts zero bytes and makes the manager's
  TLV walker stop before `0x0061`/`0x00b7`.
* A reply larger than 1 s is dropped by the manager's stale-request reaper.
* `updateHwChans()` only runs for the base radio user, i.e. the master reply;
  virtual replies do not wipe the vector.
