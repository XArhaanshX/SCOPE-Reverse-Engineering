#!/usr/bin/env python3
"""Static unpack of the ZEUSLOCK outer layers (no execution).

  EP stub (ahbtcmsa)  : per-dword (c ^ 0xA018003) + 0x705F000 over first 0x1000 of kqihfdgz
  stage 1 (kqihfdgz)  : aPLib depacker, src RVA 0x6bd2ba -> dst RVA 0x32a014, then jmp there
  stage 2 (0x32a014)  : Themida 3.x loader/VM (string "Themida" present)

Usage: unpack_stage1.py <exe> <out-dir>   (run with -I)
Writes stage1_image.bin (mapped image after the dword cipher) and stage2.bin.
"""
import sys, os, struct
import pefile


def depack(src, off=0):
    s=off; dst=bytearray(); tag=0; bits=0
    def bit():
        nonlocal tag,bits,s
        if bits==0:
            tag=src[s]; s+=1; bits=8
        bits-=1; b=(tag>>7)&1; tag=(tag<<1)&0xff; return b
    def gamma():
        v=1
        while True:
            v=(v<<1)+bit()
            if not bit(): return v
    dst.append(src[s]); s+=1
    lwm=0; R0=0
    while True:
        if not bit():
            dst.append(src[s]); s+=1; lwm=0; continue
        if not bit():
            o=gamma()
            if lwm==0 and o==2:
                o=R0; l=gamma()
            else:
                o-= 3 if lwm==0 else 2
                o=(o<<8)+src[s]; s+=1
                l=gamma()
                if o>=32000: l+=1
                if o>=1280: l+=1
                if o<128: l+=2
                R0=o
            for _ in range(l): dst.append(dst[-o])
            lwm=1; continue
        if not bit():
            o=src[s]; s+=1; l=2+(o&1); o>>=1
            if o==0: return bytes(dst), s
            for _ in range(l): dst.append(dst[-o])
            R0=o; lwm=1; continue
        o=0
        for _ in range(4): o=(o<<1)+bit()
        dst.append(dst[-o] if o else 0); lwm=0


exe, outdir = sys.argv[1], sys.argv[2]
os.makedirs(outdir, exist_ok=True)
pe = pefile.PE(exe)
img = bytearray(pe.get_memory_mapped_image())
o = 0x6bd000
for i in range(0, 0x1000, 4):
    v = struct.unpack_from('<I', img, o + i)[0]
    struct.pack_into('<I', img, o + i, ((v ^ 0xA018003) + 0x705F000) & 0xffffffff)
open(os.path.join(outdir, 'stage1_image.bin'), 'wb').write(img)
out, end = depack(img, 0x6bd2ba)
open(os.path.join(outdir, 'stage2.bin'), 'wb').write(out)
print(f"stage2: {len(out)} bytes (src consumed up to RVA 0x{end:x}), loaded at RVA 0x32a014")
