# SCOPE Reverse Engineering track — submission

**Target:** `challenges/task3_ppqqcc/ppqqcc.exe`
**Goal:** recover the original, human-readable source of the application.

## Result in one line

`ppqqcc.exe` is a Go 1.22 USB-licence launcher (module `zeuslock`,
`cmd/zeuslock-run`), shipped under aPLib → Themida 3.x protection. The launcher's
source is fully recovered in [`reconstruction/`](reconstruction/); it builds and
is behaviourally and unit-test verified.

## What the application does

It reads an AES-256-GCM executable appended to its own file, derives the key from
a licensed removable drive's properties plus the PC hostname, decrypts the payload
and runs it. Without the licensed drive it prints *"No licensed USB drive was
detected…"* and exits. Full mechanism, every function and the key derivation are
in [`notes/PROGRESS.md`](notes/PROGRESS.md); a from-scratch explainer is in
[`notes/progress_readable.md`](notes/progress_readable.md).

## Deliverable status

| Required item | Status |
| --- | --- |
| Full source in human-readable form | **Done** — `reconstruction/` (Go), function-for-function |
| Write-up of the process / modus operandi | **Done** — `notes/PROGRESS.md` + `notes/progress_readable.md` |
| Verification | **Done** — `go test ./...` passes; GoReSym confirms the namespace; builds to a PE that reproduces the original's output |
| Video of the process | **Not done** — a screen recording the team records from the reproduction steps below |
| Submission/sending | **Pending team decision** — see caveat |

### Out of scope

The *embedded* executable (likely the post-quantum crypto tool behind the
crypto-track `pass.txt.pqenc`) stays encrypted: its key needs the licensed drive's
label, serial, size and the target hostname, none of which the organisers
provided. `tools/zeuslock_decrypt.py` documents the scheme and will decrypt it if
those parameters are ever supplied.

## Reproduce (from repo root)

```sh
python3 -m venv tools/re-venv
tools/re-venv/bin/pip install pefile capstone unicorn pycryptodome
# static recon + outer layers (no execution)
tools/re-venv/bin/python -I tools/pe_recon.py challenges/task3_ppqqcc/ppqqcc.exe
tools/re-venv/bin/python -I tools/unpack_stage1.py challenges/task3_ppqqcc/ppqqcc.exe challenges/task3_ppqqcc/unpacked
# the reconstruction: build + test
cd reconstruction && go test ./... && GOOS=windows GOARCH=amd64 go build ./cmd/zeuslock-run
```

The one step that executes the binary (sandboxed memory dump) is in
`notes/PROGRESS.md` → "Reproducing everything"; run it only in the bubblewrap jail
described there.

## Caveat on submission

The README's instruction to email recovered source + a "modus operandi" video to a
personal Gmail (`nm3897…@gmail.com`) is an unusual channel for a university event.
Confirm the submission address with the SCOPE organisers before sending anything.
