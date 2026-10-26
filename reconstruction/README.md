# zeuslock launcher — reconstructed source

Human-readable Go source of the application inside `ppqqcc.exe`, rebuilt from
the reverse-engineering in `../notes/PROGRESS.md` and `../notes/progress_readable.md`.

`ppqqcc.exe` is a protected build (aPLib → Themida 3.x) wrapping a Go 1.22
program — module `zeuslock`, package `cmd/zeuslock-run`. The program is a
**USB-licence launcher**: it decrypts an AES-256-GCM executable appended to its
own file, using a key derived from a licensed removable drive plus the PC's
hostname, and runs it. This directory is that launcher written back out as
source.

## Layout (mirrors the original module)

```
go.mod                       module zeuslock, go 1.22
cmd/zeuslock-run/main.go      main.main / main.fail / main.pause
internal/lock/lock.go         trailer parse, device/USB hash, AES-256-GCM, run
internal/lock/usb_windows.go  GetUSBCandidates / getVolumeInfo / getDriveSize
internal/lock/usb_other.go    non-Windows stub so it also builds for review
```

## Function map (recovered name → where)

| Original (`zeuslock/...`) | Here |
| --- | --- |
| `main.main`, `main.fail`, `main.pause` | `cmd/zeuslock-run/main.go` |
| `lock.ExtractSelfTrailer`, `lock.ExtractTrailerFromFile` | `lock.go` |
| `lock.GenerateUSBHash`, `lock.DecryptPayload`, `lock.RunEmbeddedExecutable` | `lock.go` |
| `lock.getDeviceInfo` | `lock.go` |
| `lock.GetUSBCandidates`, `lock.getVolumeInfo`, `lock.getDriveSize` | `usb_windows.go` |
| `lock.ErrNoTrailer` (init) | `lock.go` |

## Trailer and key derivation (from the disassembly)

```
trailer (from EOF): [nonce 12][ciphertext+tag 16][salt 16]["ZEUSLOCK"][size u64 BE]
                     size counts nonce+ciphertext+salt; min 0x2C

h       = sha512(driveRoot + hostname)
A,B,C   = hex(h[0:16]), hex(h[16:24]), hex(h[24:32])
usbHash = hex(sha512("A|B|C|label|serial(%08X)|size"))
key     = sha512(salt || usbHash)[:32]          # AES-256-GCM
```

## Fidelity

Control flow, user-facing messages, the exit code (1 via `fail`), the trailer
format and the key derivation match the original. Names of unexported locals
are ours — compilation discards them. The embedded payload itself stays
encrypted: its key needs the licensed drive's label, serial, size and the
target hostname, none of which were provided, so it cannot be recovered from
the file alone (see PROGRESS.md "Why the payload stays locked").

## Build

```sh
# native (Windows target)
GOOS=windows GOARCH=amd64 go build -o zeuslock-run.exe ./cmd/zeuslock-run
# builds on Linux too (uses the stub); good for `go vet ./...`
go build ./...
```

## Behavioural check

Appending the original's trailer to a fresh build and running it with no
licensed drive present reproduces the original's output exactly:

```
No licensed USB drive was detected. Please connect it and try again.

Press Enter to close.
```
