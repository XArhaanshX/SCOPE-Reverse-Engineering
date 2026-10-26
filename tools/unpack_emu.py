#!/usr/bin/env python3
"""Statically unpack a ZEUSLOCK-protected PE by emulating its self-decrypt
stub with Unicorn until it either calls out to a Windows API (unmapped fetch)
or an instruction budget is hit, then scan emulated memory for a freshly
materialized MZ/PE image and dump it.  No real process is ever executed.

Usage:  unpack_emu.py <exe> <out-dir>     (run with -I)
"""
import sys, os, struct
import pefile
from unicorn import *
from unicorn.x86_const import *

PAGE = 0x1000
def align_down(x): return x & ~(PAGE - 1)
def align_up(x):   return (x + PAGE - 1) & ~(PAGE - 1)

exe, outdir = sys.argv[1], sys.argv[2]
os.makedirs(outdir, exist_ok=True)
pe = pefile.PE(exe)
ib = pe.OPTIONAL_HEADER.ImageBase
siz = align_up(pe.OPTIONAL_HEADER.SizeOfImage)
ep = ib + pe.OPTIONAL_HEADER.AddressOfEntryPoint

uc = Uc(UC_ARCH_X86, UC_MODE_64)
# ---- map image ----
uc.mem_map(ib, siz)
hdr = pe.header
uc.mem_write(ib, hdr)
for s in pe.sections:
    d = s.get_data()
    if d:
        uc.mem_write(ib + s.VirtualAddress, d)

# ---- stack ----
STACK = 0x7ff000000000
SSZ = 0x200000
uc.mem_map(STACK, SSZ)
rsp = STACK + SSZ // 2
uc.reg_write(UC_X86_REG_RSP, rsp)
# dummy return address so a final 'ret' lands somewhere we can catch
RETPAD = 0x10000
uc.mem_map(RETPAD, PAGE)
uc.mem_write(rsp, struct.pack('<Q', RETPAD))

mapped = set(range(ib, ib + siz, PAGE)) | set(range(STACK, STACK + SSZ, PAGE)) | {RETPAD}
state = {'stop_reason': None, 'stop_pc': None, 'icount': 0}

def ensure(addr, size):
    a = align_down(addr)
    end = align_up(addr + size)
    while a < end:
        if a not in mapped:
            try:
                uc.mem_map(a, PAGE)
                mapped.add(a)
            except UcError:
                pass
        a += PAGE

def hook_mem_unmapped(uc, access, address, size, value, u):
    # lazily back stray reads/writes with zero pages so decryption loops proceed
    ensure(address, size)
    return True

def hook_fetch_unmapped(uc, access, address, size, value, u):
    # execution tried to jump into unmapped space -> almost certainly an API
    # stub (dynamic import) or the real OEP of a non-image region: stop here.
    state['stop_reason'] = 'fetch_unmapped'
    state['stop_pc'] = address
    uc.emu_stop()
    return False

def hook_intr(uc, intno, u):
    state['stop_reason'] = f'intr {intno}'
    state['stop_pc'] = uc.reg_read(UC_X86_REG_RIP)
    uc.emu_stop()

def hook_code(uc, address, size, u):
    state['icount'] += 1
    if address == RETPAD:
        state['stop_reason'] = 'returned to pad'
        state['stop_pc'] = address
        uc.emu_stop()

uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_unmapped)
uc.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, hook_fetch_unmapped)
uc.hook_add(UC_HOOK_INTR, hook_intr)
uc.hook_add(UC_HOOK_CODE, hook_code)

# snapshot original image bytes to detect what got decrypted
orig = uc.mem_read(ib, siz)

print(f"EP=0x{ep:x}  ImageBase=0x{ib:x}  SizeOfImage=0x{siz:x}")
try:
    uc.emu_start(ep, 0, count=20_000_000)
except UcError as e:
    state['stop_reason'] = state['stop_reason'] or f'UcError {e}'
    state['stop_pc'] = state['stop_pc'] or uc.reg_read(UC_X86_REG_RIP)

print(f"stopped: reason={state['stop_reason']} pc=0x{(state['stop_pc'] or 0):x} icount={state['icount']}")

# ---- scan emulated memory for MZ/PE that appeared (or changed) ----
now = bytes(uc.mem_read(ib, siz))
found = []
for off in range(0, len(now) - 0x200, 0x4):
    if now[off:off+2] == b'MZ':
        e_lfanew = struct.unpack_from('<I', now, off + 0x3c)[0]
        if 0 < e_lfanew < 0x400 and off + e_lfanew + 4 <= len(now):
            if now[off+e_lfanew:off+e_lfanew+4] == b'PE\x00\x00':
                changed = now[off:off+0x40] != orig[off:off+0x40]
                found.append((ib + off, changed))
print("MZ/PE images in memory:", [(hex(a), 'NEW' if c else 'orig') for a, c in found])

# dump any NEW PE image (the unpacked payload)
for va, changed in found:
    if not changed:
        continue
    off = va - ib
    # size: read SizeOfImage from this PE's own optional header
    nt = struct.unpack_from('<I', now, off + 0x3c)[0] + off
    psize = struct.unpack_from('<I', now, nt + 0x18 + 0x38)[0]  # OptionalHeader.SizeOfImage
    psize = min(align_up(psize) if psize else 0x400000, len(now) - off)
    out = os.path.join(outdir, f"payload_{va:x}.bin")
    open(out, 'wb').write(now[off:off+psize])
    print(f"dumped NEW PE @0x{va:x} size={psize} -> {out}")

# also dump the whole post-emulation image for manual inspection
open(os.path.join(outdir, "image_after.bin"), 'wb').write(now)
print("wrote image_after.bin")
