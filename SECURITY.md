# Security

## Reporting

Please report vulnerabilities privately via GitHub Security Advisories
("Security" → "Report a vulnerability") rather than a public issue.

## Fixed in v0.2.1

* **Shell injection (critical).** Manager-supplied SSID/passphrase values were
  interpolated into `/tmp/capapply.sh` and executed with `system("sh …")`.
  A value such as `x'; id>/tmp/pwned; #'` gave network-to-root code execution.
  UCI is now invoked with `execvp()` and the value as a single argv element;
  no shell is involved.
* **World-readable dumps.** Datachan keys, EAPOL and decrypted payloads were
  written under `/tmp` with mode 0644. Debug dumps are now 0600 and decrypted
  datachan payloads are no longer persisted.
* **Key logging.** Passphrases are no longer printed to syslog/stdout.

## Known considerations

* **TLS verification.** The example config uses
  `DONT_VERIFY_CERTIFICATE=yes` for the self-signed CAPsMAN CA. In production
  install the manager CA and set `CA_CERT`; pin the manager certificate or CA.
  Without verification a rogue CAP holding a CA-signed client certificate can
  impersonate the manager.
* **Datachan encryption.** The manager can select a plain datachan (`a2=1`) or
  AES-256-CCM (`a2=2`, `on-capsman-secure`). Plain mode exposes frames on the
  LAN. Prefer `on-capsman-secure` and reject `a2=1` if that is acceptable for
  your deployment.
* **REST boot-pull (fallback).** If used, create a dedicated RouterOS user with
  only `read,api,rest-api,sensitive`, restrict the source address, use HTTPS,
  keep credentials mode 0600 and never log them. The split-MAC datachan path
  does not need REST credentials.
* **hostapd external-authenticator patch.** The `AUTHORIZE` control must only
  be honoured after a successful key install, and the relay socket must be
  root-only (not in a world-writable directory).
* **Certificates.** `client.key`, `client.pem`, `ca.pem` and any private key
  are excluded by `.gitignore`; never commit them. The repository is verified
  to contain no secrets.

## Trust model

The manager is trusted to provide SSID, VLAN, channel and data-path policy.
It is **not** trusted to execute code on the CAP (the v0.2.1 fix). A
compromised CAP cannot impersonate the manager if TLS verification is enabled.
