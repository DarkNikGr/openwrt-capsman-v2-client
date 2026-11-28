# 6 GHz / WiFi 6E–7 and MLO CAP bring-up plan

Repository: `deco-luci/cap-client` @ v0.6.6. Research date: 2026-11-28. The plan
is read-only; it was produced on a copy and did not touch the live Xiaomi, the
MikroTik manager, the original repo or the host kernel modules.

This note answers one question: **what does it take to move the CAP from the
mt7603e/mt76x2e reference to a real 6 GHz / WiFi 6E–7 / MLO radio on OpenWrt
24.10, and what should be bought or built first?**

The short answer:

* The current CAP already has a *working 6 GHz HE* path on `mac80211_hwsim`
  with `channel.band=6ghz-be` (F78), but it has **no EHT and no MLO**.
* The cheapest *real* 6 GHz AP is an **MT7916 (AW7916-NPD)**; it is HE-only,
  LPI-only (no AFC), and enabling 6 GHz takes the card's 5 GHz band away.
* The only credible 24.10 EHT/MLO path is **MT7996 (BPi-R4 + BE14)** on
  24.10.3-or-later (24.10.5 is current), with a hostapd 2.12 backport. It is a
  lab project, not a drop-in.
* The **manager is the biggest unknown**. RouterOS 7.25.1 understands
  "wifi7 cap" and `6ghz-be`, but it is not proven to provision an MLD. Run the
  CHR + hwsim MLO probe below **before** buying MLO hardware.

---

## 1. What the current code already proves, and where it stops

The existing 6 GHz work is documented in [`6GHZ-HWSIM.md`](6GHZ-HWSIM.md)
(F78/F78b/F79) and summarized in
[`OPEN-PROBLEMS.md`](OPEN-PROBLEMS.md#L62-L63) and
[`CAPSMAN-COVERAGE.md`](CAPSMAN-COVERAGE.md#L114-L115).

Proven on a virtual radio:

* Manager builds the 6 GHz channel list from the CAP and provisions a
  `6ghz-be` VAP at 5955 MHz (`6GHZ-HWSIM.md:143-169`).
* SAE + PMF + the 4-way + datapath at 20 and 80 MHz, `authorized: yes`,
  ping 0 % (`6GHZ-HWSIM.md:143-169`).
* Beacon-protection capability bit `0x84` byte 1 bit 1 (bit 9) is required or
  the manager refuses a WiFi 7 CAP (`6GHZ-HWSIM.md:107-120`).
* Patch `9999h` is required because the manager sends M1 before hostapd has
  associated the station on 6 GHz (`patches/README.md:22`).

Not proven / not implemented:

* `channel.band=6ghz-ax` is live on hwsim with descriptor band `0x04`
  (F85); the reference Xiaomi has no 6 GHz radio, so real RF/AFC and
  regulatory power are untested.
* 160 MHz is advertised but not exercised; **320 MHz is not generated**
  (`6GHZ-HWSIM.md:171-178`, `6GHZ-HWSIM.md:186-188`).
* **MLO / EHT multi-link is not implemented**; no MLD is established
  (`6GHZ-HWSIM.md:175-176`, `CAPSMAN-COVERAGE.md:115`).
* Real RF, AFC / standard-power 6 GHz, and regulatory power modes cannot be
  proven with hwsim (`6GHZ-HWSIM.md:177-183`).

Where the code stops, precisely:

| Concern | Current code | File:line |
|---|---|---|
| 6 GHz hostapd config | `hw_mode=a`, `op_class=131..134`, `ieee80211ax=1`, `he_6ghz_reg_pwr_type=0`; **no `ieee80211be`, no `mld_ap`, no `beacon_prot`** | `native/src/vap.inc:185-210` |
| 6 GHz channel descriptors | 20/40/80/160 only (`width` 1–4); **no 320 (`width` 6), no 80+80 (`width` 5)** | `native/src/channels.inc:31-49`, `native/src/channels.inc:104-112` |
| 6 GHz channel-number set `0x00b7` | derived from the same frequency list, so 6 GHz is included | `native/src/channels.inc:770-785` |
| 6 GHz NEWPHY band | `0x4d` band `0x06`; `CAPAGENT_BAND6` sweep hook | `native/src/util.inc:500-535`, `native/src/util.inc:623-645` |
| HE/EHT detection | parses `HE Iftypes: AP` / `EHT Iftypes: AP` from `iw phy` | `native/src/util.inc:438-441` |
| `0x84` caps | byte 0 `0x40` (datachan), byte 1 `0x02` on 6 GHz (beacon prot); **bit 7 (MLO) deliberately clear** | `native/src/util.inc:648-675` |
| `0x86` | only emitted when `CAPAGENT_NEWPHY_86` is set; default absent | `native/src/util.inc:676-686` |
| RSN / PMF | `ieee80211w` from the manager RSN caps; **no `beacon_prot=1`** | `native/src/rsn_decide.h:179-181`, `native/src/rsn_decide.h:190-212` |
| Build artefacts | mipsel + aarch64 only; no x86_64 artifact | `native/Makefile:49-55`, `scripts/build-aarch64.sh:2-12` |

The manager-side channel model is exact-match on `(frequency, band, width)`;
a duplicate triple makes a channel unusable (`FINDINGS.md:50-80`). That matters
for a tri-band EHT radio: `build_newphy()` currently emits `0x4d band 0x06`
for *both* 5 GHz EHT and 6 GHz EHT, and `read_phy_bands()` also adds `0x06`
for 6 GHz. On a 2.4+5+6 EHT wiphy this produces repeated `0x06` entries; on a
5+6 EHT wiphy it can produce three. This needs a dedupe / correct 5 GHz EHT id
before tri-band EHT is trusted.

---

## 2. Software support matrix (OpenWrt 24.10 + hostapd 2.11/2.12)

Facts that frame the matrix:

* **OpenWrt 24.10 ships hostapd 2024-09-15** (`PKG_RELEASE` 2 in 24.10.0, 3 in
  the 24.10 branch), i.e. the 2.11-era tree, not 2.12
  ([24.10.0 Makefile](https://github.com/openwrt/openwrt/blob/v24.10.0/package/network/services/hostapd/Makefile),
  [24.10 branch Makefile](https://github.com/openwrt/openwrt/blob/openwrt-24.10/package/network/services/hostapd/Makefile)).
  Main is on a 2026-08-07 snapshot, i.e. post-2.12
  ([main Makefile](https://github.com/openwrt/openwrt/blob/main/package/network/services/hostapd/Makefile)).
* 24.10 **can build** `CONFIG_IEEE80211BE` hostapd; the package sets it from
  `CONFIG_DRIVER_11BE_SUPPORT` (same Makefile). But the **UCI wifi-scripts are
  shell-based and have zero EHT/MLO handling** in 24.10.0 and the 24.10 branch
  (`grep -c 'ieee80211be\|mld_ap' hostapd.sh` = 0). The CAP writes its own
  hostapd config, so this is not fatal, but netifd/UCI cannot be used to
  configure EHT/MLO.
* **24.10.0 mt76 is 2025-01-14**, which has mt7996 MLD TLVs but **no
  `WIPHY_FLAG_SUPPORTS_MLO`**. 24.10.3+ (mt76 2025-09-15) and 24.10.5+
  (2025-11-06) do advertise MLO (`WIPHY_FLAG_SUPPORTS_MLO`,
  `IEEE80211_EML_CAP_EMLSR_SUPP`). So "24.10" is not one answer: **use
  24.10.3 or later for EHT/MLO**, not the pinned 24.10.0.
* **hostapd 2.12 fixes a pre-2.12 MLO association bounds-check**
  (CVE-2026-58374, `hostapd_process_ml_assoc_req()` in
  `src/ap/ieee802_11_eht.c`) and adds "more complete EHT" support. 24.10's
  2.11 tree has the bug unless the fix was backported. Treat 2.12 (or a
  backport) as mandatory for MLO ([NVD](https://nvd.nist.gov/vuln/detail/cve-2026-58374)).
* `iw` 6.9 is in 24.10 and does print EHT iftypes, which the CAP's parser
  needs.

| Driver / chip | AP mode | 6 GHz AP | HE | EHT | MLO AP | In 24.10 | Notes |
|---|---|---|---|---|---|---|---|
| **mt7915 (MT7915)** | ✅ | ➖ | ✅ | ➖ | ➖ | ✅ `kmod-mt7915e` | 2.4/5 only |
| **mt7915 (MT7916 / MT7976)** | ✅ | 🟡 | ✅ | ➖ | ➖ | ✅ `kmod-mt7915e` + `kmod-mt7916-firmware` | 6 GHz needs `enable_6ghz=1` on a 5+6 EEPROM (a 6 GHz-only EEPROM needs no param); **global module param**, and a 5+6 EEPROM card becomes 6 GHz *instead of* 5 GHz ([mt76 eeprom.c](https://github.com/openwrt/mt76/blob/8e4f72b682e9070108536507c5e2720b18c3816d/mt7915/eeprom.c#L9-L11), [mt76#979](https://github.com/openwrt/mt76/issues/979)). No AFC. |
| **mt7981 (MT7981 + MT7976C)** | ✅ | ➖ | ✅ | ➖ | ➖ | ✅ `kmod-mt7981-firmware` | 2.4/5 only; Xiaomi AX3000T / WR30U class |
| **mt7986 (MT7986 + MT7975/7976)** | ✅ | ➖ | ✅ | ➖ | ➖ | ✅ `kmod-mt7986-firmware` | 2.4/5 only; Redmi AX6000, GL-MT6000, BPi-R3. PCIe can host a 6 GHz card. |
| **mt7996 (MT7996/MT7992)** | ✅ | ✅ | ✅ | ✅ | 🟡 (24.10.3+) | ✅ `kmod-mt7996e` (24.10.0 already has it) | Tri-band; `WIPHY_FLAG_SUPPORTS_MLO` from 24.10.3. Hostapd 2.11 MLO is preliminary and has the pre-2.12 CVE; use 2.12. End-to-end AP MLD on 24.10 is not proven here. |
| **mt7990 / mt7991 (BE3600/5000)** | ✅ | ➖ | ✅ | ✅ | 🟡 | ✅ `kmod-mt7996e` | 2.4+5 only; AsiaRF AW7990/AW7991 are **not 6 GHz** ([AW7990 spec](https://asiarf.com/product/wifi-7-be3600-mini-pcie-ap-module-aw7990-npd/): 2.4 + 5.18–5.905 GHz) |
| **ath11k IPQ8074 (integrated)** | ✅ | ➖ | ✅ | ➖ | ➖ | ✅ | 2.4/5 only; WAX620/WAX630 class |
| **ath11k QCN9074** | ✅ | ✅ | ✅ | ➖ | ➖ | ✅ `kmod-ath11k-pci` | 6 GHz-only or 5 GHz variants; 4x4; needs `ath11k-firmware-qcn9074` + `board-2.bin`; x86 bring-up is historically fiddly ([openwrt#17071](https://github.com/openwrt/openwrt/issues/17071)) |
| **ath12k QCN9274** | ✅ | ✅ | ✅ | ✅ | 🟡 (ath12k) | 🟡 `kmod-ath12k` exists (PCI, `@DRIVER_11BE_SUPPORT`) | QCN9274 supports AP + STA ([LWN](https://lwn.net/Articles/915152/)); MLO AP works on QCN9274 but OpenWrt integration is DIY (DR9574 port, 3-link MLD recipe). 24.10's 6.12 backport may lag the mainline MLO fixes. |
| **ath12k WCN7850** | ➖ | ➖ | ✅ | ✅ | STA-side only | 🟡 | **STA-only** in ath12k; not an AP choice ([LWN](https://lwn.net/Articles/915152/)) |
| **mac80211_hwsim** | ✅ | ✅ (virtual) | ✅ | ✅ | 🟡 | ✅ `kmod-mac80211-hwsim` | 6.12 has an `mlo` module parameter ("Support MLO") and EHT; no RF/AFC ([hwsim 6.12](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/drivers/net/wireless/virtual/mac80211_hwsim.c?h=v6.12), line 70) |

Hostapd config facts for the plan (from the current 2.11/2.12-era sample config):

* EHT: `ieee80211be=1`, `eht_oper_chwidth`,
  `eht_oper_centr_freq_seg0_idx`, `eht_bw320_offset=1|2`, `punct_bitmap`.
* MLO: `mld_ap=1`, `mld_addr=...`; hostapd auto-assigns `mld_link_id` for the
  co-hosted BSSes (the 2023 "Add basic MLO support for AP" series and the 2024
  "scale up MLO flows" series). All links must be EHT — a 2.4 GHz MLO link must
  be EHT20 even if you wanted HE20 ([openwrt#25414](https://github.com/openwrt/openwrt/issues/25414)).
* 6 GHz: `hw_mode=a`, `op_class=131..137`,
  `he_6ghz_reg_pwr_type=0` (LPI), `ieee80211ax=1`; PMF `ieee80211w=2`;
  beacon protection `beacon_prot=1` (requires driver support).
* AFC: the 2.12-era hostapd sample has `afc_op_class` and AFC request fields;
  MT7916 does **not** implement AFC, so only LPI/VLP-style 6 GHz is usable on
  that card ([openwrt#16548](https://github.com/openwrt/openwrt/issues/16548),
  comment about MT7916AN lacking AFC).

---

## 3. `patches/` — generic vs mt76-specific

**All of `999…9999j` are generic hostapd/mac80211 patches.** None of them
mentions mt76, MT7915 or MT7996; they touch `src/ap/ext_auth.c`,
`src/ap/ieee802_1x.c`, `src/ap/ieee802_11.c`, `hostapd/config_file.c`,
`hostapd/ctrl_iface.c`, `src/ap/hostapd.c` and `src/drivers/driver_nl80211.c`.
They apply equally to mt76, ath11k and ath12k.

| Patch | Layer | Driver-specific? | 6 GHz / MLO relevance |
|---|---|---|---|
| `999-external-rsn-auth` | hostapd core + ext_auth | no | required for split-MAC on any band |
| `9997-external-rsn-ie` | hostapd config/RSN | no | required; also preserves RSNXE trailing elements (`9999a` hunk) |
| `9998-external-rsn-eapol-rx` | `ieee802_1x_receive()` | no | required |
| `9999-external-rsn-no-psk` | hostapd config | no | required |
| `9999a-external-rsn-sae` | SAE + `EXT_AUTH_MGMT_TX` | no | **required on 6 GHz** (WPA3/SAE is mandatory) |
| `9999b-external-rsn-tx-retval` | EAPOL TX return | no | required |
| `9999c-hostapd-use-existing-bss` | nl80211 BSS lifecycle | no (motivated by mt76x02) | required because the CAP pre-creates the AP netdev, on every driver |
| `9999d-hostapd-set-mode-ealready` | nl80211 `SET_INTERFACE` | no | required for CAP-created BSS |
| `9999e-external-rsn-null-wpa-sm` | hostapd WPA SM | no | required |
| `9999f` / `9999g` / `9999i` / `9999j` | 11k/11v action + IE | no | optional; unrelated to 6 GHz/MLO |
| `9999h-external-rsn-queue-early-eapol` | ext_auth queue | no | **required on 6 GHz** (early M1) |

The mt76-specific behaviour is **outside** `patches/`:

* BSS MAC/index constraints on mt76x02 (W54, F73/F74) — not relevant to
  MT7916/MT7996, but the CAP's MAC plan still has to respect the driver.
* `enable_6ghz=1` module parameter (mt7915).
* EHT/MLO capability advertisement (`WIPHY_FLAG_SUPPORTS_MLO`) and firmware.
* `phy_hwtype()` reports the kernel module name (`mt7915e`, `mt7996e`,
  `ath11k_pci`, `ath12k`) as NEWPHY `0x83`; the manager may or may not care
  (`native/src/util.inc:340-359`, `native/src/util.inc:601-602`). Test this
  before assuming it is cosmetic.

### What a 6 GHz/MLO CAP still needs from this code

1. **NEWPHY band model.** Keep `0x05` frequencies from `iw phy`; fix the
   tri-band EHT `0x4d 0x06` duplication; decide whether 5 GHz EHT needs a
   distinct id (the current comment says `0x06` is `5ghz-be`; the 6 GHz default
   is also `0x06` — see `FINDINGS.md:59-62` and `native/src/util.inc:623-645`).
2. **`0x84`/`0x86`.** Set `0xC0 0x02` (datachan + beacon prot) today. For MLO,
   the next experiment is `0x84` byte 0 bit 7 (the code explicitly keeps it
   clear, `native/src/util.inc:648-657`). `0x86` is unknown; capture a genuine
   WiFi 7 CAP's NEWPHY or sweep it with `CAPAGENT_NEWPHY_86`.
3. **Channel descriptors.** Add `width=6` (320 MHz) and `c320_6g()`; optionally
   `width=5` (80+80). The descriptor body is already 16 KiB (`BODY_MAX`,
   `native/capagent.c:155`); 59 × 6 GHz frequencies × 6 widths is close to the
   limit, so raise `BODY_MAX` or stop emitting unsupported widths.
4. **Beacon protection.** The CAP *claims* `0x84` bit 9 but `rsn_conf_write()`
   never writes `beacon_prot=1` (`rsn_decide.h:190-212`). Add it and verify the
   driver supports it; otherwise the claim is only a manager gate.
5. **MLO hostapd config.** `vap.inc:185-210` hardcodes HE. A `6ghz-be` or
   EHT BSS needs `ieee80211be=1` plus `eht_oper_*`; an AP MLD needs
   `mld_ap=1`/`mld_addr` on every link BSS in one hostapd process. The current
   architecture is already one hostapd per real phy with all VAPs as `bss=`
   sections (`native/src/phy.inc:1-12`), which is the right shape for a
   co-hosted MLD — but `vap_phy_bss()` has no per-link grouping.
6. **MLO data path.** `nl80211.inc` installs keys/authorizes with
   `NL80211_ATTR_MAC` only (`native/src/nl80211.inc:432-436`,
   `native/src/nl80211.inc:494-516`). An MLD peer needs the MLD address/link
   id and per-link station state. This is the largest CAP-side change and it
   cannot be validated until the manager sends MLD provisioning.

---

## 4. Hardware matrix (ranked for this project)

Prices are approximate, 2026-11, before shipping. "6 GHz AP" means the driver
exposes a 6 GHz wiphy with `HE/EHT Iftypes: AP`, not just a 6 GHz-capable chip.

| Rank | Candidate | Radio / host | Bands | 6 GHz AP | EHT / MLO | 24.10 status | Cost | Verdict |
|---|---|---|---|---|---|---|---|---|
| **1** | **BPi-R4 + BE14** | MT7988 + MT7996 (2×2 + 3×3 + 3×3) | 2.4/5/6 | ✅ | ✅ / ✅ | device includes `kmod-mt7996-firmware` + `kmod-mt7996-233-firmware`; MLO needs 24.10.3+ and hostapd 2.12 | ~$180–250 | **Only credible EHT/MLO lab.** High effort; 6 GHz txpower/EEPROM quirks; manager MLO still unknown |
| **2** | **x86_64 or BPi-R4 + AW7916-NPD** | MT7916AN (2×2 + 2×3) | 2.4 + 5 **or** 6 | ✅ | ➖ / ➖ | ✅ `kmod-mt7915e` + `kmod-mt7916-firmware`; `enable_6ghz=1` | ~$50 card + host | **Cheapest real 6 GHz HE CAP.** 5 GHz is lost when 6 GHz is enabled; global param; no AFC |
| **3** | **BPi-R4 or x86 + DR9074-6E** | QCN9074 (4×4) | 6 only | ✅ | ➖ / ➖ | ✅ `kmod-ath11k-pci` + `ath11k-firmware-qcn9074`; x86 firmware/board-2 pain | ~$120–180 card | Best 6 GHz RF, no 5 GHz fallback, no MLO; hostapd 6 GHz-only quirks |
| **4** | **x86_64 + DR9274-6G / 8devices Noni** | QCN9274 (2×2/4×4) | 6 (or 5+6) | ✅ | ✅ / ✅ | 🟡 `kmod-ath12k` exists; OpenWrt device support DIY | ~$180–300 | MLO research only; ath12k AP MLO + firmware + hostapd 2.12 |
| **5** | **BPi-R3 + AW7916-NPD** | MT7986 + MT7916 via M.2→mini PCIe adapter | 2.4/5 + 6 | ✅ | ➖ / ➖ | ✅ but adapter/PCIe fiddly; the R3 has no native mini PCIe | ~$120–150 | Works, but the R4 is a better host for the same card |
| **6** | **Xiaomi AX3000T / WR30U / Redmi AX6000 / GL-MT6000** | MT7981 / MT7986 + MT7976 | 2.4/5 | ➖ | ➖ / ➖ | ✅ | $30–130 | **No 6 GHz.** Cheap 2.4/5 CAPs or hosts; not a 6 GHz answer |
| **7** | **Netgear WAX630** | IPQ8074, 2.4 + 5L + 5H | 2.4/5/5 | ➖ | ➖ / ➖ | ✅ (`netgear_wax630` in `ipq807x.mk`) | ~$100 used | ath11k, no 6 GHz. **WAX630E (6E) is not in the 24.10 tree** |
| **8** | **GL.iNet Flint 3 (GL-BE9300)** | IPQ5332 + QCN9274 | 2.4/5/6 | ✅ hardware | ✅ / ✅ hardware | ❌ no official OpenWrt support (TOH) | ~$210 | Do not buy for OpenWrt; the port is not merged |

Notes:

* BPi-R4 has **2× mini PCIe (PCIe 3.0 2-lane)** for a WiFi 7 NIC and the BE14
  uses two PCIe lanes ([BPi-R4 docs](https://docs.banana-pi.org/en/BPI-R4/GettingStarted_BPI-R4)).
  That makes it the clean host for BE14, AW7916-NPD, or DR9074-6E.
* BPi-R3 is MT7986 + MT7975N/MT7975P, 2.4/5 only; adding a 6 GHz card needs an
  M.2/M.2→mini PCIe adapter ([BPi-R3 docs](https://docs.banana-pi.org/en/BPI-R3/BananaPi_BPI-R3),
  [forum adapter thread](https://forum.banana-pi.org/t/bpi-r3-which-m2-mpcie-adapter/15424)).
* Xiaomi/Redmi MT7981 and MT7986 devices use `kmod-mt7915e` +
  `kmod-mt7981-firmware` / `kmod-mt7986-firmware`; there is no 6 GHz
  calibration/firmware in those packages (see `filogic.mk` device entries,
  e.g. `xiaomi_mi-router-ax3000t` at
  [filogic.mk:1441-1456](https://github.com/openwrt/openwrt/blob/v24.10.0/target/linux/mediatek/image/filogic.mk)).
* The DECO BE65 is an ath12k WiFi 7 device and is read-only in this project;
  it is a useful reference for what a real MLD looks like, not a test target
  (`README.md:317-320`).

---

## 5. No-hardware tests vs hard hardware gates

### Can be tested without 6 GHz hardware

**A. `mac80211_hwsim` (host or on the AP).**

* 6 GHz HE/EHT iftypes, NEWPHY encoding, `0x84`/`0x86` sweeps, 0x000a
  descriptors (including 320), hostapd EHT/MLO config generation, AP MLD
  bring-up, SAE/PMF/EAPOL relay, and a virtual station's MLO association.
* `hwsim` 6.12 has `mlo=1` and EHT ([hwsim source](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/drivers/net/wireless/virtual/mac80211_hwsim.c?h=v6.12), line 70);
  the repo's existing recipe uses a 7.x host module (`6GHZ-HWSIM.md:10-40`).
* On OpenWrt itself, `kmod-mac80211-hwsim` is available and depends on
  `@DRIVER_11BE_SUPPORT` (`package/kernel/mac80211/Makefile:171-177`), so a
  24.10.3+ x86/aarch64 image can load `mac80211_hwsim radios=2 mlo=1` and run
  the CAP on the target OS.

**B. CHR (RouterOS Cloud Hosted Router) as the manager.**

* CHR is radio-less: it tests **manager protocol only**, not RF or the CAP
  driver.
* It is the right tool to answer: does 7.25.1 provision an MLD when the CAP
  advertises `0x84` bit 7 and/or `0x86`? Does it accept `6ghz-be` at 320 MHz?
  Does it send new link TLVs?
* This is the **go/no-go for buying MLO hardware**.

### Hard hardware gates (hwsim/CHR cannot prove)

1. A real 6 GHz radio with `HE/EHT Iftypes: AP` and 6 GHz frequencies with
   `IR` in the selected country (`iw phy`).
2. Regulatory / AFC: LPI vs standard power, txpower limits, channel
   availability. MT7916 has **no AFC**; only LPI-style operation is possible.
3. Real per-link MLO: link add/remove, per-link RSSI/rate, EAPOL/keys over
   multiple links, roaming. Requires an EHT radio with `SUPPORTS_MLO` and
   firmware.
4. Throughput/RF: 160/320 MHz, beamforming, MU-MIMO, coexistence.
5. The manager's actual MLO provisioning (see CHR test) — a protocol gate, but
   only observable with a CAP that advertises the right capabilities.

---

## 6. Exact next tests (ordered)

### Phase 0 — no new hardware (host hwsim + CHR)

**T0. Baseline.** `make -C native check` and
`scripts/patches-check.sh --tarball … --openwrt-patches …` must stay green
before touching anything.

**T1. 6 GHz EHT (no MLO) on hwsim.** Reuse `6GHZ-HWSIM.md`; add
`ieee80211be=1` to the 6 GHz hostapd block (a new `CAPAGENT_EHT=1` switch in
`vap_write_channel()`). Pass: `AP-ENABLED` at 5955, a WiFi 7 station shows
EHT (not just HE), ping 0 %. This separates "6 GHz HE" from "6 GHz EHT".

**T2. 320 MHz descriptor.** Add `width=6` and `c320_6g()` to
`add_chan_desc()`; emit 320 only when the phy advertises it. Pass: the 0xD00B
body contains a width-6 descriptor with a 320 MHz centre (31/63/95/127/159/
191/223), the manager does not reject the reply, and `hostapd` starts with
`op_class=137`/320 (hwsim may not actually transmit 320 — that is a hardware
gate; the descriptor test is still valid).

**T3. Tri-band EHT NEWPHY dump.** Run `build_newphy()` on a wiphy with 2.4, 5
and 6 GHz and `has_eht=1`; dump the `0x001d` body. Pass: no duplicate
`0x4d` entries, one band id per band, and a documented decision for the 5 GHz
EHT id (0x05 vs 0x06). File the result next to F79.

**T4. `0x84` bit 7 / `0x86` sweep.** Join a fresh identity with
`CAPAGENT_NEWPHY_84=c002` (byte 0 `0xC0`: datachan + MLO; byte 1 `0x02`:
beacon prot). Compare the manager log and the first `0x500b`/`0x6016` with the
baseline. Pass: the manager stays joined and either (a) sends MLD/link TLVs or
(b) provably does not — both are useful. Repeat with plausible `0x86` values
and record which one changes the manager's VAP state.

**T5. AP MLD on hwsim.** One hostapd process, two or three `bss=` sections on
one wiphy, each with `ieee80211be=1`, `mld_ap=1`, `mld_addr=…`,
`beacon_prot=1`; 2.4 GHz link at EHT20, 5/6 GHz at EHT. Station:
`wpa_supplicant` with MLO. Pass: `AP-ENABLED`, an MLD address, the station
shows multiple links, ping 0 %. Do this on 24.10.5's 2.11 hostapd **and** on a
2.12 build; the difference tells you whether a backport is enough.

**T6. CHR manager MLO probe.** With the T4/T5 CAP, point CHR at the CAP and
try a WiFi 7/MLO profile (or the closest `be` profile). Capture the manager's
`0x500b`/`0x6016`/new TLVs. Pass: either an MLD is provisioned, or the absence
is documented. **Do not buy MLO hardware before this test.**

### Phase 1 — real 6 GHz HE (cheap)

**T7. Driver gate.** On the chosen host (BPi-R4 + AW7916-NPD, or x86_64 +
AW7916-NPD):
`modprobe mt7915e enable_6ghz=1`; `iw phy` must show `Band 4`,
`HE Iftypes: AP`, and 5955 MHz with `IR` after `iw reg set <country>`.
Record whether 5 GHz disappeared (expected on a 5+6 EEPROM) and whether
`enable_6ghz` is global to both cards (mt76#979).

**T8. CAP end-to-end.** Run `capagent` with `--country` and a `6ghz-be`
profile at 5955. Pass: NEWPHY has `0x06` + `0x84/9`; VAP `MDB`; hostapd
`AP-ENABLED`; SAE station `authorized: yes`; ping 3/3 0 % at 20/80/160 MHz;
`iw link` shows 5955. This is the first **real-hardware** proof and it uses
the existing code path.

**T9. Regulatory/txpower.** `iw reg get`, `iwinfo <dev> txpowerlist`,
`iw phy` flags. Pass: 6 GHz channels usable in the lab country; txpower sane
(issue #16548 reports `255 dBm`; that is a reporting/LuCI issue, but confirm
the actual `iw` value); document that this is LPI, not AFC/SP.

### Phase 2 — EHT/MLO hardware (only if T6 says the manager can do MLO)

**T10. BPi-R4 + BE14 on 24.10.5+.** `iw phy` shows 6 GHz + EHT; hostapd 2.12
(or a backport) with `ieee80211be=1`/`mld_ap=1`; AP MLD on 2.4+5+6; client
MT7925/BE200. Pass: MLD association with at least two links, ping 0 %,
`iw link` per link. Then integrate the CAP: NEWPHY bit 7/0x86, per-link
descriptors, per-link EAPOL/keys, manager MLD config.

---

## 7. Blockers (ranked)

| # | Blocker | Severity | Who fixes |
|---|---|---|---|
| 1 | **RouterOS 7.25.1 may not provision an MLD at all.** `0x86` is unknown and `0x84` bit 7 is untested. | critical | CHR + hwsim probe (T4/T6); then manager-side if needed |
| 2 | **hostapd 2.11 in 24.10** has the pre-2.12 MLO CVE and incomplete EHT. MLO needs 2.12 or a backport. | high | hostapd package / backport |
| 3 | **24.10.0 mt76 has no `WIPHY_FLAG_SUPPORTS_MLO`.** Use 24.10.3+ (mt76 2025-09-15+) or main. | high | image version |
| 4 | **UCI wifi-scripts in 24.10 have no EHT/MLO.** The CAP writes its own config, so this only blocks netifd-based provisioning. | medium | CAP config writer (already the design) |
| 5 | **MT7916 `enable_6ghz` is global and 5-or-6.** A 5+6 card cannot do both; two cards both flip. | medium | mt76 patch / per-card parameter (mt76#979) |
| 6 | **MT7916 has no AFC.** No standard-power 6 GHz; LPI only. | medium | hardware choice (MT7996/QCN9274) |
| 7 | **6 GHz descriptors stop at 160; 320 and 80+80 missing.** | medium | `channels.inc` + `BODY_MAX` |
| 8 | **`0x06` is used for both 5 GHz EHT and 6 GHz.** Tri-band EHT NEWPHY may be ambiguous. | medium | `util.inc` band model |
| 9 | **`0x84` bit 9 is claimed but `beacon_prot=1` is never written.** | medium | `rsn_decide.h` / hostapd config |
| 10 | **QCN9074 x86 bring-up** needs firmware + `board-2.bin` and a 6 GHz-only hostapd path. Main has a wifi-scripts (ucode) fix for 6 GHz-only radios; 24.10 is shell-based, and the CAP bypasses netifd anyway. | medium | image/firmware; CAP config writer |
| 11 | **No x86_64 capagent artifact.** | low | add `scripts/build-x86_64.sh` (aarch64 already exists) |
| 12 | **`phy_hwtype()` reports `mt7915e`/`mt7996e`/`ath11k_pci`.** The manager may key band policy off it (F84). | low | test/spoof if needed |

---

## 8. What to buy / what to build

### Buy

1. **Now, for a real 6 GHz HE CAP (recommended first purchase):**
   **AsiaRF AW7916-NPD** (~$40) + mini PCIe→PCIe adapter (~$9) + a host.
   The host can be a BPi-R4 (aarch64, existing `capagent-aarch64` works) or a
   cheap x86_64 box running OpenWrt 24.10.5. Expect 2.4 + **6 GHz only**
   (5 GHz disappears), HE, 160 MHz, LPI, no MLO. This closes the "real 6 GHz"
   gate with the current CAP code.
2. **Only if T6 passes, for EHT/MLO:** **BPi-R4 + BPI-R4-NIC-BE14**
   (~$180–250 total) + an MT7925/BE200 client. This is the only documented
   cheap 2.4+5+6 EHT/MLO OpenWrt bench.
3. **Do not buy** Flint 3 (no official OpenWrt), WAX630E (not in 24.10),
   Xiaomi/Redmi BE or MT7981/MT7986 routers for 6 GHz (no 6 GHz radio).
   WAX630 is supported but is 2.4+5+5, not 6 GHz.

### Build

1. **`capagent` for x86_64** (musl static, same as the aarch64 script), or
   standardize on BPi-R4/aarch64 to reuse `capagent-aarch64`.
2. **EHT/MLO config generation** in `vap.inc`: `ieee80211be=1`,
   `eht_oper_*`, `mld_ap`/`mld_addr`, `beacon_prot=1`; keep the one-hostapd-
   per-phy architecture.
3. **Channel model**: width 6/320, `c320_6g`, dedupe the tri-band `0x4d`
   entries, raise `BODY_MAX` if needed.
4. **NEWPHY caps**: `0x84` bit 7, `0x86`, and a documented 6 GHz band id.
5. **hostapd 2.12 backport** to 24.10 (or move the CAP image to 25.x/main).
6. **MLO data path** only after T6: per-link EAPOL, `NL80211_ATTR_MLD_ADDR`/
   link id, per-link station/key handling, and the manager's MLD TLVs.

### Bottom line

* **6 GHz HE CAP:** buy AW7916-NPD, use 24.10.5, run T7–T9. Low risk, ~$50 +
  host, no CAP-protocol changes beyond `enable_6ghz=1` and the 6 GHz profile.
* **6 GHz EHT/MLO CAP:** treat it as a research project. BPi-R4 + BE14 is the
  hardware; hostapd 2.12 and the CAP's per-link plumbing are the software;
  the manager's MLD provisioning is the unknown that decides whether it is
  worth buying.

---

## 9. Sources

Repo (copy at `/tmp/ag7-hardware`):

* `docs/6GHZ-HWSIM.md:10-40` (hwsim recipe), `:107-120` (`0x84` bit 9),
  `:122-141` (early M1), `:171-190` (open items / limits)
* `docs/OPEN-PROBLEMS.md:62-63` (F79/F78), `:136-141` (6 GHz/MLO blockers)
* `docs/CAPSMAN-COVERAGE.md:114-115` (6 GHz virtual only; MLO not implemented)
* `docs/FINDINGS.md:50-80` (descriptor/band/width semantics), `:227-229`
  (`0x84` datachan bit)
* `patches/README.md:9-24` (patch inventory), `patches/9999a-*.patch`,
  `patches/9999h-*.patch`
* `native/src/vap.inc:185-210` (6 GHz hostapd), `native/src/channels.inc:31-49`,
  `:104-112` (descriptors), `native/src/util.inc:500-535`, `:623-686`
  (NEWPHY bands/caps), `native/src/rsn_decide.h:179-212` (RSN/PMF)
* `native/Makefile:49-55`, `scripts/build-aarch64.sh:2-12`

OpenWrt:

* 24.10.0 hostapd:
  https://github.com/openwrt/openwrt/blob/v24.10.0/package/network/services/hostapd/Makefile
* 24.10 branch hostapd:
  https://github.com/openwrt/openwrt/blob/openwrt-24.10/package/network/services/hostapd/Makefile
* main hostapd:
  https://github.com/openwrt/openwrt/blob/main/package/network/services/hostapd/Makefile
* 24.10.0 mt76:
  https://github.com/openwrt/openwrt/blob/v24.10.0/package/kernel/mt76/Makefile
* 24.10.5 mt76:
  https://github.com/openwrt/openwrt/blob/v24.10.5/package/kernel/mt76/Makefile
* 24.10.0 mac80211 (backports 6.12.6):
  https://github.com/openwrt/openwrt/blob/v24.10.0/package/kernel/mac80211/Makefile
* ath12k package definition:
  https://github.com/openwrt/openwrt/blob/v24.10.0/package/kernel/mac80211/ath.mk
* 24.10.0 wifi-scripts (shell):
  https://github.com/openwrt/openwrt/blob/v24.10.0/package/network/config/wifi-scripts/files/lib/netifd/hostapd.sh
* filogic devices (BPi-R3/R4, Xiaomi):
  https://github.com/openwrt/openwrt/blob/v24.10.0/target/linux/mediatek/image/filogic.mk
* ipq807x devices (WAX620/630):
  https://github.com/openwrt/openwrt/blob/v24.10.0/target/linux/qualcommax/image/ipq807x.mk

Kernel / hostapd:

* hwsim 6.12 (MLO parameter):
  https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/drivers/net/wireless/virtual/mac80211_hwsim.c?h=v6.12
* mt76 `enable_6ghz`:
  https://github.com/openwrt/mt76/blob/8e4f72b682e9070108536507c5e2720b18c3816d/mt7915/eeprom.c
* ath11k supported devices:
  https://wireless.docs.kernel.org/en/latest/en/users/drivers/ath11k.html
* ath12k:
  https://wireless.docs.kernel.org/en/latest/en/users/drivers/ath12k.html
* QCN9274 AP + STA, WCN7850 STA-only:
  https://lwn.net/Articles/915152/
* hostapd 2.11 announcement:
  https://lists.infradead.org/pipermail/hostap/2024-July/042847.html
* hostapd 2.11 sample config (EHT/MLO/beacon_prot):
  https://github.com/greearb/hostap-ct/blob/master/hostapd/hostapd.conf
* CVE-2026-58374 (pre-2.12 MLO assoc):
  https://nvd.nist.gov/vuln/detail/cve-2026-58374

Hardware / field reports:

* BPi-R4:
  https://docs.banana-pi.org/en/BPI-R4/GettingStarted_BPI-R4
* BPi-R3:
  https://docs.banana-pi.org/en/BPI-R3/BananaPi_BPI-R3
* AW7916-NPD:
  https://asiarf.com/product/wi-fi-6e-mini-pcie-module-mt7916-aw7916-npd/
* AW7916-AED:
  https://asiarf.com/product/wifi-6e-ax3000-module-aw7916-aed-package/
* AW7990 (2.4+5 only, not 6 GHz):
  https://asiarf.com/product/wifi-7-be3600-mini-pcie-ap-module-aw7990-npd/
* DR9074-6E (QCN9074, 6 GHz 4×4):
  https://www.wallystech.com/Network_Card/DR9074-6E-Wifi6E-Qualcomm-QCN9074-Single-Band-6GHz-4T4R-M-2-E-Key-Interface-802-11ax.html
* MT7916 6 GHz txpower / AFC:
  https://github.com/openwrt/openwrt/issues/16548
* mt7916 per-card `enable_6ghz`:
  https://github.com/openwrt/mt76/issues/979
* MLO on HE htmode rejected:
  https://github.com/openwrt/openwrt/issues/25414
* Flint 3 (no official OpenWrt):
  https://openwrt.org/toh/gl.inet/gl-be9300
* Wallys DR9574 3-card MLO guide:
  https://wifi5.eu/dls/Wallys/DR9574/DR9574%20User%20Manual%20MLO-draft.pdf
