#!/usr/bin/env python3
"""List Go functions from pclntab in a memory-dumped image (base 0x400000) and disassemble
the named ones with call/string annotations.
Usage: IMAGE=<stitched image.bin> go_pclntab.py [func ...]   (IMAGE defaults to /tmp/zl/image.bin)"""
import os, struct, sys
img=open(os.environ.get('IMAGE', '/tmp/zl/image.bin'),'rb').read(); BASE=0x400000
i=0
while True:
    i=img.find(b'\xf1\xff\xff\xff\x00\x00\x01\x08',i)
    if i<0: break
    nfunc,nfiles,text,fno,cuo,fto,pco,plo=struct.unpack_from('<8Q',img,i+8)
    if 0x401000<=text<0x500000: break
    i+=1
hdr=i; print('pcHeader @', hex(BASE+hdr), 'nfunc',nfunc,'text',hex(text))
ft=hdr+plo; names=hdr+fno
out=[]
for k in range(nfunc):
    entry,fo=struct.unpack_from('<II',img,ft+8*k)
    nameoff=struct.unpack_from('<i',img,ft+fo+4)[0]
    e=img.index(b'\0',names+nameoff); out.append((text+entry,img[names+nameoff:e].decode()))
for k,(a,n) in enumerate(out):
    end=out[k+1][0] if k+1<len(out) else a
    if 'zeuslock' in n or n.startswith('main.'): print(hex(a),hex(end-a),n)

import capstone
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
addrs=dict(out)
def strat(a,n):
    o=a-BASE
    try: return img[o:o+n].decode('utf-8')
    except: return None
for fn in sys.argv[1:]:
    k=[j for j,(a,n) in enumerate(out) if n==fn][0]; a=out[k][0]; end=(out[k+1][0] if k+1<len(out) and out[k+1][0]>a else a+0x600)
    print(f'\n==== {fn}')
    last_lea=None
    for ins in md.disasm(img[a-BASE:end-BASE],a):
        s=f"{ins.address:x}: {ins.mnemonic} {ins.op_str}"
        if ins.mnemonic=='call':
            try: s+='   ; '+addrs.get(int(ins.op_str,16),'?')
            except: pass
        if ins.mnemonic=='lea' and 'rip' in ins.op_str:
            disp=int(ins.op_str.split('rip')[1].strip(' +]-'),16)*(-1 if '- 0x' in ins.op_str else 1)
            t=ins.address+ins.size+disp; s+=f'   ; ->{t:x} {addrs.get(t,"")}'
            last_lea=t
        if ins.mnemonic=='mov' and last_lea and ins.op_str.endswith(('ebx, ','ecx')):
            pass
        m=__import__('re').search(r'(e[bc]x|edi), (0x[0-9a-f]+)$',ins.op_str)
        if m and last_lea and ins.mnemonic=='mov':
            st=strat(last_lea,int(m.group(2),16)) if int(m.group(2),16)<200 else None
            if st: s+=f'   ; str={st!r}'
        print(s)
