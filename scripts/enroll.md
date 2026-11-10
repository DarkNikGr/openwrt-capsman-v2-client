# Certificate enrollment

CAPsMAN v2 authenticates the CAP with an X.509 client certificate. The manager
issues it after a join that carries a CSR (TLV `0x76`); the response `0x77` is
the DER certificate and `0x78` the CA chain.

## Using the helper

`native/enroll.py` performs a join with a CSR and writes the issued certificate:

```sh
python3 native/enroll.py \
    --manager 10.0.0.1 \
    --cn OpenWrt-CAP3 \
    --outdir ./certs
```

Then copy the result to the device:

```sh
scp certs/client.pem root@10.0.0.2:/etc/cap/client.pem
scp certs/client.key root@10.0.0.2:/etc/cap/client.key
```

Check `python3 native/enroll.py --help` for the remaining options
(`--ec`, `--identity`, `--port`).

## Using an existing certificate

If the manager already trusts a certificate (for example one created on the
manager and exported), install it as `/etc/cap/client.pem` +
`/etc/cap/client.key`. The common name is what the manager shows as the CAP
identity.

## Verify

```sh
openssl x509 -in /etc/cap/client.pem -noout -subject -issuer -dates
```

On the manager, `/certificate print` should list the CAP common name as
trusted/issued.
