#!/usr/bin/env python3
"""Static recon of a PE: entry point, sections, entropy, TLS, imports, overlay.
Usage: pe_recon.py <path-to-exe>   (run with -I; treats the file as data only)
"""
import sys, math
import pefile

def entropy(b: bytes) -> float:
    if not b:
        return 0.0
    from collections import Counter
    n = len(b)
    return -sum((c / n) * math.log2(c / n) for c in Counter(b).values())

path = sys.argv[1]
data = open(path, "rb").read()
pe = pefile.PE(data=data, fast_load=False)

ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
ib = pe.OPTIONAL_HEADER.ImageBase
print(f"ImageBase=0x{ib:x}  EntryPointRVA=0x{ep:x}  EP VA=0x{ib+ep:x}")
print(f"Subsystem={pe.OPTIONAL_HEADER.Subsystem}  DllChar=0x{pe.OPTIONAL_HEADER.DllCharacteristics:x}")

print("\n== sections ==")
ep_sec = None
for s in pe.sections:
    nm = s.Name.rstrip(b"\x00").decode("latin1", "replace")
    raw = s.get_data()
    e = entropy(raw)
    inep = s.contains_rva(ep)
    if inep:
        ep_sec = nm
    print(f"  {nm:10s} VA=0x{s.VirtualAddress:08x} vsize={s.Misc_VirtualSize:>8} "
          f"raw={s.SizeOfRawData:>8} ent={e:5.2f} flags=0x{s.Characteristics:08x}"
          f"{'  <-- EP' if inep else ''}")
print(f"EP is in section: {ep_sec}")

print("\n== imports ==")
if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
    for d in pe.DIRECTORY_ENTRY_IMPORT:
        names = [imp.name.decode() if imp.name else f"ord{imp.ordinal}" for imp in d.imports]
        print(f"  {d.dll.decode():16s} ({len(names)}): {', '.join(names[:25])}")
else:
    print("  (no import directory)")

print("\n== TLS callbacks ==")
if hasattr(pe, "DIRECTORY_ENTRY_TLS") and pe.DIRECTORY_ENTRY_TLS:
    print("  TLS present (callbacks run before EP):", hex(pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks))
else:
    print("  none")

# overlay
ov = pe.get_overlay_data_start_offset()
if ov:
    print(f"\n== overlay ==  starts@{ov} size={len(data)-ov} ent={entropy(data[ov:]):.2f}")

# PyInstaller cookie in last 24 bytes?
tail = data[-24:]
print("\n== tail 24 bytes ==", tail)
print("PyInstaller MEI cookie in file:", b"MEI\x0c\x0b\x0a\x0b\x0e" in data)
