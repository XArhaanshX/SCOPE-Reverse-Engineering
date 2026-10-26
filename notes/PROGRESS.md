# SCOPE reverse engineering progress

Track: reverse engineering. The goal is to recover the original, human-readable source of a provided application.
Target: `challenges/task3_ppqqcc/ppqqcc.exe`.

## Handoff status (2026-10-26)

The protection layers and the launcher's behaviour are fully mapped. The Go source rewrite, which is the actual deliverable, has not started, and there is no Go toolchain on the analysis machine yet.

| Item | State |
| --- | --- |
| Entry stub and stage-1 cipher | Done, reproduced statically |
| aPLib stage | Done with our script. aplib-ripper documented below but not yet checked against it |
| Themida layer | Bypassed by running under Wine in a sandbox and dumping memory |
| Go launcher, function list and behaviour | Done, see "The recovered launcher" |
| Overlay key derivation | Done, `tools/zeuslock_decrypt.py` |
| Embedded payload | Out of scope. Locked to a specific USB drive, no drive details exist |
| Readable Go source of the launcher | Not started |

What `main` does, from the disassembly: it calls `lock.ExtractSelfTrailer()`, and on error prints "This application is not set up correctly: " plus the error. It then calls `lock.GetUSBCandidates()`, and on error prints "No licensed USB drive was detected. Please connect it and try again." For each candidate it calls `GenerateUSBHash` and `DecryptPayload`, skipping drives that fail. On the first success it calls `RunEmbeddedExecutable(payload, os.Args[1:])`, and on error prints "Error running the application: " plus the error. If no drive matches it prints "This USB drive is not licensed for this application. Access denied." `main.fail` prints its message to stdout, calls `main.pause`, and exits with code 1. `main.pause` prints "\nPress Enter to close." and reads one line from stdin. `lock.init` sets `ErrNoTrailer` to "no protected payload is embedded in this executable". `ExtractSelfTrailer` wraps `os.Executable` errors as "locating own executable: %w". `ExtractTrailerFromFile` wraps read errors as "reading executable: %w" and rejects bad sizes with "corrupt trailer".

## Reproducing everything

All commands run from the repo root. The analysis machine is Arch-based Linux with Wine 11.20 and bubblewrap.

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
tools/sandbox/run.sh sh -c 'wineboot -i'                        # first run only, creates the Wine prefix
tools/sandbox/run.sh python3 -I /scripts/dump.py ppqqcc.exe 15 /work/dump

# 4. Join the regions that make up the unpacked image (0x400000 to 0xcb7000)
mkdir -p /tmp/zl
cd /tmp/zlsb/work/dump && cat 000000400000-* 000000401000-* 000000594000-* 000000728000-* \
  000000729000-* 00000072a000-* 000000cb1000-* > /tmp/zl/image.bin && cd -

# 5. List and disassemble the Go functions
IMAGE=/tmp/zl/image.bin tools/re-venv/bin/python -I tools/go_pclntab.py
IMAGE=/tmp/zl/image.bin tools/re-venv/bin/python -I tools/go_pclntab.py main.main zeuslock/internal/lock.DecryptPayload
```

The region file names in step 4 come from our run. If a later run maps memory differently, check `dump/maps.txt` for the regions belonging to `/work/ppqqcc.exe` and the anonymous regions right after them.

Before running step 3, confirm the sandbox is isolated: `tools/sandbox/run.sh sh -c 'cat /proc/net/dev; ls /home'` should list only `lo` and fail to find `/home`. Docker would work equally well. We used bubblewrap only because our account has no access to the Docker socket.

Known rough edges for whoever continues:

- `tools/go_pclntab.py` assumes Go 1.20+ pclntab (magic `F1 FF FF FF`) and image base `0x400000`. Its string annotation is a heuristic that also fires on unrelated `mov` instructions.
- Address-to-name resolution for `call` only covers function entry points, so calls into the middle of runtime helpers show as `?`. Those are Go's `duffcopy` and `duffzero` struct-copy helpers.
- The disassembly listing for the last function in the table (`main.main`) runs into padding after its `ret` at `0x4c3cf3`.

## Where we are

`ppqqcc.exe` has three layers, and we have now opened all of them:

1. A small entry stub decrypts the first 0x1000 bytes of section `kqihfdgz`.
2. That code is an aPLib decompressor, which unpacks the protector.
3. The protector is Themida 3.x. Inside it is a Go 1.22 program, module `zeuslock`, package `cmd/zeuslock-run`.

The Go program is a USB-licence launcher. It reads an AES-256-GCM encrypted executable from the end of its own file. It derives the key from the properties of a removable drive and the PC's hostname, then decrypts the executable into the temp directory and runs it. On a machine without the licensed drive it prints "No licensed USB drive was detected" and waits for Enter.

We have recovered the full decryption scheme. We cannot decrypt the embedded executable because we don't know the licensed drive's parameters, and the organisers have given us no drive details. Our task is the human-readable source of the application itself, which is the launcher, so the encrypted payload is out of scope.

## What we tried, and what we got wrong

### Treating the stub as a PE loader

We decrypted the entry stub correctly. Each dword in the first 0x1000 bytes of `kqihfdgz` becomes `(c ^ 0xA018003) + 0x705F000`. The decrypted code then scans backwards in memory for `MZ` and `PE\0\0`, and we read that as a search for an embedded PE that it would map and run.

That was wrong. The scan only finds the module's own image base. The rest of the code is the standard aPLib depacker (`aP_depack`). It decompresses 3,743,564 bytes from RVA `0x6bd2ba` to RVA `0x32a014` and jumps there.

For the aPLib step we use the decompressor from [herrcore/aplib-ripper](https://github.com/herrcore/aplib-ripper), `aplib.decompress(data[0x6bd2ba:]).do()`, run on the image after the dword decrypt. Its command-line mode does not work here. `aprip` only searches for aPLib-packed PE files by their `M8Z` marker, and this stage is raw code that starts with a `jmp`, not an `MZ` header. The repo is Python 2, so under Python 3 it needs `xrange` mapped to `range` and the data passed as a latin-1 `str`. We have not yet checked its output against `tools/unpack_stage1.py`, which does the dword decrypt and the decompression in one step without running anything.

### Emulating the unpack with Unicorn, then planning Qiling

Our Unicorn harness (`tools/unpack_emu.py`) never produced a payload, and we blamed the missing PEB and kernel32 export table. We planned to move to Qiling to supply those.

The real reason is that the depacked stage is Themida 3.x. The string `Themida` appears in it. The import table holds only `lstrcpy` and `InitCommonControls`, the section names are random, and a 3.7 MB section is empty. Themida runs its unpacking in a virtual machine with anti-emulation checks, so Qiling would most likely have stalled the same way. We dropped the emulation approach.

### Attacking the overlay as if the footer held the key

The file ends with a 4.4 MB overlay and a footer: 16 bytes, then `ZEUSLOCK`, then a big-endian size. We assumed the 16 bytes were an AES-128 key. We tried AES in ECB, CBC, CFB, OFB, CTR and GCM, plus ChaCha20, Salsa20, RC4 and XOR. We used the raw bytes and MD5, SHA-1 and SHA-256 derivations of them. Nothing decrypted.

The 16 bytes are a salt, not a key. The real key depends on the USB drive, so no amount of guessing from the file alone would have worked.

### Running the binary in a sandbox

We stopped trying to unpack Themida statically. Instead we ran the program under Wine 11.20 inside bubblewrap. The sandbox has no network (only loopback), a read-only root filesystem, no home directory, no display and a cleared environment. Its only writable directory is a scratch directory. Docker was not an option because our user has no access to the Docker socket.

Themida unpacked normally under Wine. While the program waited at "Press Enter", `tools/sandbox/dump.py` read every mapped region of the process through `/proc/<pid>/mem`. The dump at `0x400000` holds the unpacked Go program.

## The recovered launcher

Go binaries keep function names in `pclntab`. `tools/go_pclntab.py` parses it from the dump and disassembles functions with call targets and string references marked. The interesting functions are in `zeuslock/internal/lock`:

| Function | Purpose |
| --- | --- |
| `ExtractSelfTrailer`, `ExtractTrailerFromFile` | Read the program's own file and parse the trailer |
| `GetUSBCandidates` | List drives that `GetDriveTypeW` reports as removable |
| `getVolumeInfo` | Get the volume label and serial (`GetVolumeInformationW`, serial formatted `%08X`) |
| `getDeviceInfo` | Run `sha512Sum16(drive + os.Hostname())` |
| `getDriveSize` | Get total bytes (`GetDiskFreeSpaceExW`) |
| `GenerateUSBHash` | Return the hex SHA-512 of `"%s\|%s\|%s\|%s\|%s\|%d"` over the fields below |
| `DecryptPayload` | Decrypt with AES-256-GCM using the key below |
| `RunEmbeddedExecutable` | Write the plaintext to the temp directory and run it with `os/exec` |

The trailer layout is `[nonce 12][ciphertext + GCM tag 16][salt 16]["ZEUSLOCK"][u64 BE size]`. The size counts the nonce, ciphertext and salt. Here it is 0x43a83c.

The key derivation:

```
h        = sha512(drive_root + hostname)            # drive_root such as "E:\"
A, B, C  = hex(h[0:16]), hex(h[16:24]), hex(h[24:32])
usbhash  = hex(sha512("A|B|C|<volume label>|<volume serial %08X>|<total bytes>"))
key      = sha512(salt + usbhash)[:32]
```

The `USBInfo` struct is 0x68 bytes. It holds A, B and C, the label, the serial, the size as an `int64`, and the drive root. The hash uses every field except the drive root, which enters through `h` instead.

`tools/zeuslock_decrypt.py` implements this. It takes the drive root, hostname, label, serial and size. The GCM tag check tells us right away whether the parameters are correct.

## Linked crypto-track files

`challenges/task1_pqenc/pass.txt.pqenc` is a KEM/DEM hybrid. It uses ML-KEM-1024 (`kem_cipher`, 1568 bytes), ML-DSA-87 (`public_key` 2592 bytes, `signature` 4627 bytes) and AES-256-GCM (12-byte nonce, 16-byte tag, 229-byte ciphertext). The launcher contains no post-quantum code, so the PQ tool is probably the encrypted embedded executable.

`challenges/task2_qr/sentinel_qr_0007.png` decodes to a URL with a Fernet token in the `cipher` parameter. It belongs to another track, and we have not followed the URL.

## Next steps

1. Rewrite the launcher as readable Go source from the disassembly, one function at a time: `main.main`, `main.fail`, `main.pause` and everything in `zeuslock/internal/lock`.
2. Check the rewrite by building it and comparing its behaviour with the original under the sandbox. Both should print the same messages, and both should fail the same way on the same trailer.
3. The payload stays encrypted. The organisers have given no drive details, so `tools/zeuslock_decrypt.py` is only there to document the scheme.

## Repo layout

- `tools/pe_recon.py` does static PE recon (sections, entropy, imports, TLS, overlay).
- `tools/unpack_emu.py` is the abandoned Unicorn attempt, kept for the record.
- `tools/unpack_qiling.py` is the Qiling attempt. We never ran it to completion and abandoned it once we identified Themida. Its docstring still describes the old "embedded PE" theory.
- `tools/unpack_stage1.py` statically reproduces the stub decrypt and the aPLib stage.
- `tools/sandbox/run.sh` and `tools/sandbox/dump.py` run the binary under Wine in bubblewrap and dump its memory.
- `tools/go_pclntab.py` lists and disassembles Go functions from the dump.
- `tools/zeuslock_decrypt.py` decrypts the trailer given the USB parameters.
- `notes/progress_readable.md` explains every term in this file and how each fact was found, for readers new to reverse engineering.
- `tools/re-venv/` and `challenges/**/unpacked/` are gitignored and can be regenerated.
