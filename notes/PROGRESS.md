# SCOPE Reverse Engineering — progress

**Track:** Reverse engineering — recover the original, human-readable source of a provided application.
**Target:** `ppqqcc.exe` (from the hackathon repo).

## Summary so far

`ppqqcc.exe` is a **post-quantum crypto tool** (the generator behind the crypto-track
file `pass.txt.pqenc`), wrapped in a **custom protector we've named "ZEUSLOCK"** (magic
string `ZEUSLOCK` in the file footer; the same family protects the other repo binary
`zeusfinal.exe`).

### Fingerprint
- PE32+ (x86-64) console, 7 sections, ~8 MB.
- Randomized section names (`kqihfdgz`, `ahbtcmsa`), a 3.7 MB zero-filled section
  (unpack destination), two high-entropy blobs (`kqihfdgz` 2 MB + a 4.4 MB overlay,
  entropy ~8.0), and a near-empty import table (`kernel32!lstrcpy`,
  `comctl32!InitCommonControls`) — everything else resolved at runtime.
- Footer at EOF: `<16-byte key/IV> "ZEUSLOCK" <big-endian size 0x43a83c>`.

### Protector behaviour (reversed statically)
- **Anti-debug:** `call/int3/pop` RIP trick + `cmp byte[ret],0xCC` self-check, and a
  later `cmp byte,0xE9` jmp-hook check.
- **Stage-1 cipher** (recovered): per-dword `plain = (cipher ^ 0xA018003) + 0x705F000`,
  applied to the first 0x1000 bytes of `kqihfdgz`. Decrypts to valid x86-64.
- **Stage 1** is a position-independent loader that scans memory for an embedded
  `MZ`/`PE` (checks `MZ` = 0x5A4D and `PE\0\0` via `e_lfanew`) — i.e. the real
  `ppqqcc.exe` is an **embedded PE** decrypted and mapped at runtime.
- **Import resolution is dynamic** (PEB / kernel32 export walk).

### Why pure Unicorn emulation stalls
The stub walks the PEB to resolve APIs. With no Windows process environment (no PEB,
no mapped `kernel32` export table) the scan never terminates — the in-process Unicorn
harness spins out its instruction budget without materializing the payload. Confirmed,
not a bug in the harness.

### Decision
Proceeding with **Qiling** (a Windows emulation layer — PEB + stub DLLs — on top of
Unicorn) so the unpack runs entirely on Linux, statically, without ever executing the
real binary as a process. Expected output: the embedded payload PE, which we then
decompile (likely .NET→C# or PyInstaller→.py, given "human-readable source").

### Linked finding (crypto track, not ours but relevant)
`pass.txt.pqenc` is a KEM/DEM hybrid: **ML-KEM-1024** (`kem_cipher` 1568 B) +
**ML-DSA-87** (`public_key` 2592 B, `signature` 4627 B) + **AES-256-GCM**
(`nonce` 12 B, `auth_tag` 16 B, `ciphertext` 229 B). The crib (`msbj`) only reveals
4 bytes of GCM keystream; decryption needs the KEM secret key or a key recovered from
`ppqqcc.exe` — another reason the two tracks are linked.

## Repo layout
- `tools/pe_recon.py` — static PE recon (sections, entropy, imports, TLS, overlay).
- `tools/unpack_emu.py` — Unicorn unpack attempt (stalls at API resolution; kept for record).
- `challenges/task3_ppqqcc/ppqqcc.exe` — target binary.
- `challenges/task1_pqenc/`, `challenges/task2_qr/` — other-track inputs for reference.
- `tools/re-venv/` and `challenges/**/unpacked/` are gitignored (regenerable).

## Next
1. Set up Qiling + minimal Windows rootfs.
2. Emulate the unpack, dump the embedded payload PE at OEP, rebuild IAT.
3. Identify payload runtime and decompile to source.
