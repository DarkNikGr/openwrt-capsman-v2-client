#!/usr/bin/env python3
"""Enroll a new CAP client certificate with the MikroTik CAPsMAN manager.

Sends the join (0x4029) with a 0x76 = CSR element; the manager replies with
0x77 = issued client certificate (DER) and 0x78 = CA certificate (DER).
"""
import argparse
import os
import socket
import ssl
import struct
import subprocess
import sys
import time

PORT_CAP = 5246


def el(i, d):
    return struct.pack('>HH', i, len(d)) + d


def msg(t, body=b'', port=0):
    return struct.pack('>HH', t, port) + b'\x00' * 8 + struct.pack('>H', len(body)) + body


def parse_tlv(buf):
    out = []
    i = 0
    while i + 4 <= len(buf):
        t, ln = struct.unpack('>HH', buf[i:i + 4])
        if i + 4 + ln > len(buf):
            break
        out.append((t, buf[i + 4:i + 4 + ln]))
        i += 4 + ln
    return out


def der_to_pem(der, label='CERTIFICATE'):
    import base64
    b64 = base64.encodebytes(der).decode().replace('\n', '')
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return '-----BEGIN %s-----\n%s\n-----END %s-----\n' % (label, '\n'.join(lines), label)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--manager', default='10.0.0.1')
    ap.add_argument('--port', type=int, default=PORT_CAP)
    ap.add_argument('--cn', default='OpenWrt-CAP3')
    ap.add_argument('--outdir', default='/tmp/opencode/certs')
    ap.add_argument('--identity', default='CHR')
    ap.add_argument('--ec', action='store_true')
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)
    key = os.path.join(args.outdir, 'client.key')
    csr = os.path.join(args.outdir, 'client.csr.der')
    if args.ec:
        subprocess.run(['openssl', 'req', '-new', '-newkey', 'ec',
                        '-pkeyopt', 'ec_paramgen_curve:secp384r1', '-nodes',
                        '-keyout', key, '-outform', 'DER', '-out', csr,
                        '-subj', '/CN=' + args.cn],
                       check=True, capture_output=True)
    else:
        subprocess.run(['openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', key, '-outform', 'DER', '-out', csr,
                        '-subj', '/CN=' + args.cn],
                       check=True, capture_output=True)

    csr_der = open(csr, 'rb').read()
    body = b''.join([
        el(0x6e, b'\x00\x01'),
        el(0x6f, args.identity.encode()),
        el(0x46, bytes.fromhex('ce9e1a1727347326')),
        el(0x70, b'\x00\x00\x00\x02'),
        el(0xa7, b'\x01\x00\x07'),
        el(0x71, args.identity.encode()),
        el(0x72, b''),
        el(0x73, bytes.fromhex('07196601')),
        el(0x74, bytes.fromhex('6ae88499')),
        el(0x75, bytes.fromhex('c9978f198320')),
        el(0xa1, b'\x00\x00\x02\x32'),
        el(0x76, csr_der),
    ])

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    sock = socket.create_connection((args.manager, args.port), timeout=10)
    ss = ctx.wrap_socket(sock)
    ss.sendall(msg(0x4029, body))
    print('sent join with CSR CN=%s' % args.cn)

    ss.settimeout(3)
    cert = None
    ca = None
    deadline = time.time() + 8
    while time.time() < deadline:
        try:
            hdr = ss.recv(14)
        except socket.timeout:
            continue
        if not hdr or len(hdr) < 14:
            break
        t, port, ln = struct.unpack('>HHH', hdr[0:2] + hdr[2:4] + hdr[12:14])
        data = b''
        while len(data) < ln:
            chunk = ss.recv(ln - len(data))
            if not chunk:
                break
            data += chunk
        print('rx type=0x%04x len=%d' % (t, len(data)))
        if ln:
            for i, v in parse_tlv(data):
                print('  el 0x%04x len=%d %s' % (i, len(v), v[:8].hex()))
                if i == 0x77 and v[:1] == b'\x30':
                    cert = v
                elif i == 0x78 and v[:1] == b'\x30':
                    ca = v
        if cert:
            break

    if not cert:
        print('no certificate issued')
        return 1

    open(os.path.join(args.outdir, 'client.pem'), 'w').write(der_to_pem(cert))
    if ca:
        open(os.path.join(args.outdir, 'ca.pem'), 'w').write(der_to_pem(ca))
    print('saved %s/client.pem (%d bytes DER)' % (args.outdir, len(cert)))
    subprocess.run(['openssl', 'x509', '-in', os.path.join(args.outdir, 'client.pem'),
                    '-noout', '-subject', '-issuer'])
    return 0


if __name__ == '__main__':
    sys.exit(main())
