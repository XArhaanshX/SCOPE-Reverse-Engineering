# SCOPE Reverse Engineering — Dortress Hackathon 2026

Reverse-engineering track. The goal is to recover the original, human-readable source of the provided application, `challenges/task3_ppqqcc/ppqqcc.exe`.

## Result in one paragraph

`ppqqcc.exe` is a Windows program protected by three layers: a small entry stub, an aPLib decompressor, and Themida 3.x. Inside is a Go 1.22 program, module `zeuslock`, package `cmd/zeuslock-run`. It is a **USB-licence launcher**. It reads an AES-256-GCM encrypted executable appended to its own file, derives the key from a removable drive's properties plus the PC's hostname, decrypts the executable to the temp directory and runs it. The readable Go source of that launcher is in [`reconstruction/`](reconstruction/). The encrypted payload itself stays locked, because its key needs the licensed drive's label, serial and size and the target hostname, and none of these are available.

## Repository layout

| Path | Contents |
| --- | --- |
| `reconstruction/` | The deliverable: the launcher rewritten as readable Go. Has its own README with a function map. |
| `notes/PROGRESS.md` | Full analysis log: what worked, what we got wrong, how each layer was opened. |
| `notes/progress_readable.md` | The same story explained from scratch for readers new to reverse engineering. |
| `challenges/task3_ppqqcc/ppqqcc.exe` | The target binary. |
| `tools/` | Analysis scripts (see below). |

`challenges/task1_pqenc/` and `challenges/task2_qr/` belong to other tracks and are not part of this work.

## The protection layers

1. **Entry stub.** Decrypts the first 0x1000 bytes of section `kqihfdgz`, one dword at a time: `(c ^ 0xA018003) + 0x705F000`.
2. **aPLib stage.** The decrypted code is a standard aPLib depacker. It expands 3,743,564 bytes from RVA `0x6bd2ba` to RVA `0x32a014` and jumps there.
3. **Themida 3.x.** The depacked stage is the Themida loader and VM. It resists static unpacking and emulation (Unicorn and Qiling attempts stalled), so we ran the binary under Wine in a network-less bubblewrap sandbox and dumped process memory while it waited at "Press Enter". The dump at `0x400000` holds the unpacked Go program.

## The recovered launcher

Go keeps function names in `pclntab`, so `tools/go_pclntab.py` lists and disassembles the program's functions from the dump. The functions are in `zeuslock/internal/lock`: `ExtractSelfTrailer`, `ExtractTrailerFromFile`, `GetUSBCandidates`, `getVolumeInfo`, `getDeviceInfo`, `getDriveSize`, `GenerateUSBHash`, `DecryptPayload`, `RunEmbeddedExecutable`, plus `main.main`, `main.fail` and `main.pause`.

Behaviour of `main`:

1. Parse the trailer from the running executable. On error: "This application is not set up correctly: <err>".
2. List removable drives. On error: "No licensed USB drive was detected. Please connect it and try again."
3. For each drive, derive the key and try to decrypt. Drives that fail the GCM tag check are skipped. On the first success, run the payload with the program's own arguments. On error: "Error running the application: <err>".
4. If no drive matches: "This USB drive is not licensed for this application. Access denied."

Every failure message goes to stdout, then "Press Enter to close." is shown, and the program exits with code 1.

### Trailer format

```
[nonce 12][ciphertext + GCM tag 16][salt 16]["ZEUSLOCK"][size u64 big-endian]
```

`size` counts the nonce, ciphertext and salt. In this file it is 4,433,980 (0x43A83C).

### Key derivation

```
h        = sha512(drive_root + hostname)             # drive_root such as "E:\"
A, B, C  = hex(h[0:16]), hex(h[16:24]), hex(h[24:32])
usbhash  = hex(sha512("A|B|C|<volume label>|<volume serial %08X>|<total bytes>"))
key      = sha512(salt + usbhash)[:32]               # AES-256-GCM
```

`tools/zeuslock_decrypt.py` implements this. The GCM tag check tells you immediately whether a set of drive parameters is correct.

## What is not recovered

The embedded payload. Its key depends on the licensed drive's volume label, serial and total size, the drive letter, and the hostname of the target PC. None of these are in the file and the organisers have not supplied them. The serial alone is a 32-bit unknown, so guessing blind is not realistic. The key scheme is fully documented, so anyone with the parameters can decrypt it with `tools/zeuslock_decrypt.py`.

## Building the reconstruction

```sh
cd reconstruction
go vet ./... && go build ./...                              # builds on Linux using a stub for drive enumeration
GOOS=windows GOARCH=amd64 go build -o zeuslock-run.exe ./cmd/zeuslock-run
```

Checks done: `go vet` and `go build` are clean, the Windows cross-build produces a PE32+ console executable, and a build with the original's trailer appended parses the trailer and prints the same "No licensed USB drive was detected..." message and exit code as the original when no licensed drive is present. The USB enumeration code (`usb_windows.go`) was written from the disassembly of the Windows API calls and has not been run against a real removable drive.

## Reproducing the analysis

All commands run from the repo root. The analysis machine is Linux with Wine and bubblewrap.

```sh
# 1. Python environment
python3 -m venv tools/re-venv
tools/re-venv/bin/pip install pefile capstone unicorn pycryptodome

# 2. Static recon and the two outer layers (no execution)
tools/re-venv/bin/python -I tools/pe_recon.py challenges/task3_ppqqcc/ppqqcc.exe
tools/re-venv/bin/python -I tools/unpack_stage1.py challenges/task3_ppqqcc/ppqqcc.exe challenges/task3_ppqqcc/unpacked

# 3. Sandbox run and memory dump (the only step that executes the binary)
mkdir -p /tmp/zlsb/work /tmp/zlsb/scripts
cp challenges/task3_ppqqcc/ppqqcc.exe /tmp/zlsb/work/
cp tools/sandbox/dump.py /tmp/zlsb/scripts/
tools/sandbox/run.sh sh -c 'wineboot -i'                    # first run only, creates the Wine prefix
tools/sandbox/run.sh python3 -I /scripts/dump.py ppqqcc.exe 15 /work/dump

# 4. Join the regions of the unpacked image (0x400000 to 0xcb7000)
mkdir -p /tmp/zl
cd /tmp/zlsb/work/dump && cat 000000400000-* 000000401000-* 000000594000-* 000000728000-* \
  000000729000-* 00000072a000-* 000000cb1000-* > /tmp/zl/image.bin && cd -

# 5. List and disassemble the Go functions
IMAGE=/tmp/zl/image.bin tools/re-venv/bin/python -I tools/go_pclntab.py
IMAGE=/tmp/zl/image.bin tools/re-venv/bin/python -I tools/go_pclntab.py main.main zeuslock/internal/lock.DecryptPayload
```

Region file names in step 4 come from our run; if yours differ, check `dump/maps.txt` for the regions belonging to `/work/ppqqcc.exe` and the anonymous regions right after it.

Before step 3, confirm the sandbox is isolated: `tools/sandbox/run.sh sh -c 'cat /proc/net/dev; ls /home'` should list only `lo` and fail to find `/home`.

## Tools

| Script | Purpose |
| --- | --- |
| `tools/pe_recon.py` | Static PE recon: sections, entropy, imports, TLS, overlay. |
| `tools/unpack_stage1.py` | Reproduces the entry-stub decrypt and the aPLib stage without running anything. |
| `tools/sandbox/run.sh`, `tools/sandbox/dump.py` | Run the binary under Wine in bubblewrap and dump its memory. |
| `tools/go_pclntab.py` | List and disassemble Go functions from the dump. Assumes Go 1.20+ pclntab and base `0x400000`. |
| `tools/zeuslock_decrypt.py` | Decrypt the trailer given the drive parameters. |
| `tools/unpack_emu.py`, `tools/unpack_qiling.py` | Abandoned emulation attempts, kept for the record. |

## Dead ends

- Reading the entry stub as an embedded-PE loader. It is an aPLib depacker.
- Emulating the unpack in Unicorn or Qiling. The next stage is Themida, which defeats emulation.
- Treating the 16 bytes before `ZEUSLOCK` as an AES key. They are a salt.

Details of each are in `notes/PROGRESS.md`.
