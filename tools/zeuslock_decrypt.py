#!/usr/bin/env python3
"""Decrypt the ZEUSLOCK trailer of a protected exe, given the licensed USB drive's parameters.

Recovered from zeuslock/internal/lock (Go 1.22) in the unpacked image:
  trailer : [nonce 12][ciphertext+tag 16][salt 16]["ZEUSLOCK"][u64 BE size of preceding three]
  device  : h = sha512(drive + hostname); A, B, C = hex(h[0:16]), hex(h[16:24]), hex(h[24:32])
  usbhash : hex(sha512("A|B|C|<volume label>|<volume serial %08X>|<total bytes>"))
  key     : sha512(salt + usbhash)[:32], AES-256-GCM

Usage: zeuslock_decrypt.py <exe> <out> <drive e.g. E:\\> <hostname> <label> <serial hex> <total bytes>   (run with -I)
"""
import sys, hashlib
from Crypto.Cipher import AES

exe, out, drive, host, label, serial, size = sys.argv[1:8]
d = open(exe, 'rb').read()
assert d[-16:-8] == b'ZEUSLOCK', 'no ZEUSLOCK trailer'
n = int.from_bytes(d[-8:], 'big')
blob = d[-16 - n:-16]
nonce, ct, salt = blob[:12], blob[12:-16], blob[-16:]

h = hashlib.sha512((drive + host).encode()).digest()
fields = [h[0:16].hex(), h[16:24].hex(), h[24:32].hex(), label, '%08X' % int(serial, 16), str(int(size))]
usb = hashlib.sha512('|'.join(fields).encode()).hexdigest()
key = hashlib.sha512(salt + usb.encode()).digest()[:32]

pt = AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct[:-16], ct[-16:])
open(out, 'wb').write(pt)
print(f'ok: {len(pt)} bytes -> {out}')
