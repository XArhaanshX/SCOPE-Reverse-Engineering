#!/usr/bin/env python3
"""Static unpack of the ZEUSLOCK-protected PE using Qiling.

Qiling emulates the Windows process environment (PEB, loaded-module list, DLL
export tables) on top of Unicorn, so ZEUSLOCK's dynamic import resolution
(PEB walk -> kernel32 export parse) succeeds and the stub decrypts the embedded
payload PE in emulated memory. The real binary is never executed as a process.

Approach:
  * emulate from the entry point,
  * watch for execution leaving the protector region into the (formerly empty)
    unpack section = the real OEP,
  * at that point dump a memory snapshot and carve the freshly-materialized
    MZ/PE, then stop.

Usage:  unpack_qiling.py <exe> <rootfs> <out-dir>   (run with -I)
"""
import sys, os, struct

exe, rootfs, outdir = sys.argv[1], sys.argv[2], sys.argv[3]
os.makedirs(outdir, exist_ok=True)

from qiling import Qiling
from qiling.const import QL_VERBOSE

# protector image layout (from static recon)
IMAGE_BASE = 0x400000
# RVA of the big zero-filled "unpack destination" section and kqihfdgz blob;
# OEP will land somewhere in the image but outside the original EP stub.
EP_STUB_LO = 0x8b0000      # ahbtcmsa (entry stub) RVA
EP_STUB_HI = 0x8b7000

ql = Qiling([exe], rootfs, verbose=QL_VERBOSE.OFF)

state = {"dumped": False, "oep": None, "maxpc": 0}

def scan_and_dump(ql, tag):
    """Scan emulated image memory for a NEW MZ/PE and write it out."""
    try:
        data = ql.mem.read(IMAGE_BASE, 0x8b7000)
    except Exception:
        return False
    for off in range(0, len(data) - 0x200, 4):
        if data[off:off+2] != b"MZ":
            continue
        e_lfanew = struct.unpack_from("<I", data, off + 0x3c)[0]
        if not (0 < e_lfanew < 0x400) or off + e_lfanew + 4 > len(data):
            continue
        if data[off+e_lfanew:off+e_lfanew+4] != b"PE\x00\x00":
            continue
        # skip the outer protector image at base 0
        if off == 0:
            continue
        nt = off + e_lfanew
        psize = struct.unpack_from("<I", data, nt + 0x18 + 0x38)[0]  # SizeOfImage
        psize = min(psize or 0x400000, len(data) - off)
        out = os.path.join(outdir, f"payload_{IMAGE_BASE+off:x}_{tag}.bin")
        open(out, "wb").write(data[off:off+psize])
        print(f"[+] carved payload PE @0x{IMAGE_BASE+off:x} size={psize} -> {out}")
        return True
    return False

def hook_code(ql, address, size):
    state["maxpc"] = max(state["maxpc"], address)
    # OEP heuristic: PC is inside the image but below the EP stub (real code
    # regions are lower), after the stub has run. Try carving periodically.
    if not state["dumped"] and address < EP_STUB_LO and address >= IMAGE_BASE + 0x1000:
        if scan_and_dump(ql, "oep"):
            state["dumped"] = True
            state["oep"] = address
            print(f"[+] suspected OEP transfer at 0x{address:x}; stopping")
            ql.emu_stop()

ql.hook_code(hook_code)

try:
    ql.run()
except Exception as e:
    print("[emu stopped]", type(e).__name__, e)

if not state["dumped"]:
    print("[*] no OEP transfer caught; carving from final memory state")
    scan_and_dump(ql, "final")
print(f"[*] maxpc seen = 0x{state['maxpc']:x}  oep = {state['oep'] and hex(state['oep'])}")
