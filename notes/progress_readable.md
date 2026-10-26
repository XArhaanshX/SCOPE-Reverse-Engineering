# How we took apart ppqqcc.exe, explained

This is the plain-language companion to `PROGRESS.md`. It explains every term that file uses, and it shows how we found each fact, including the wrong turns. Read it top to bottom; each section builds on the one before.

Part 3 is a hands-on guide. It repeats the whole path as numbered steps with exact commands, the output you should see at each step, and a link back to the explanation of why the step works. Parts 1 and 2 explain, Part 3 lets you do it yourself, and Part 4 is the review of our mistakes.

## The goal

The track asks for the original, human-readable source of `ppqqcc.exe`. Somebody wrote this program in a programming language, compiled it into machine code, and then wrapped it in protection so that nobody could read it. Our job is to undo the wrapping, understand the machine code, and write the program back out as source code.

## Part 1: the basic vocabulary

### Executable, machine code and source code

Source code is the text a programmer writes, such as `fmt.Println("hello")`. A compiler turns it into machine code. Machine code is a list of bytes that the processor runs directly. An executable (`.exe` on Windows) is a file that holds that machine code plus the information Windows needs to load it.

Compiling throws information away, such as comments, most variable names and often function names. That is why getting source back is hard, and why "reverse engineering" is a field of its own.

### PE files

PE (Portable Executable) is the file format of Windows programs. Every `.exe` and `.dll` is a PE file. It starts with a small header beginning with the bytes `MZ`. That header points to a second header beginning with `PE\0\0`. These two markers are how tools, and malware, recognise a PE file in a pile of bytes.

After the headers come sections. Each section is a named block of the file that Windows copies into memory. Normal compilers produce sections called `.text` (code), `.data` (variables), `.rdata` (constants) and `.rsrc` (icons and other resources).

### Image base, RVA and VA

When Windows loads a PE file it places it at an address in memory called the image base. For this file that is `0x400000`. (`0x` means the number is written in hexadecimal, base 16.)

Addresses inside the file are usually given as an RVA (relative virtual address), which is the distance from the image base. The real address in memory is the VA (virtual address), so `VA = image base + RVA`. For example, RVA `0x6bd000` is VA `0xabd000` when the image base is `0x400000`.

### Entry point

The entry point is the address where the program starts running. The PE header stores it. Reverse engineers almost always start reading here.

### Imports and the import table

Programs call Windows functions such as `CreateFileW` (open a file) or `GetVolumeInformationW` (ask about a disk). The import table is the list in the PE header of which functions from which DLLs the program needs. Windows fills in their addresses at load time.

The import table is one of the first things we read, because it tells us what the program can do. A program with only two imports, as here, is hiding the rest.

### Overlay

The overlay is any data added to the end of a PE file after the last section. Windows ignores it when loading the program, but the program can open its own file and read it. That makes the overlay a common hiding place for extra data.

### Entropy

Entropy measures how random a block of bytes looks, on a scale from 0 to 8 bits per byte. Normal code scores around 5 to 6, text around 4 to 5 and a block of zeros 0. Encrypted or compressed data scores close to 8, because good encryption and compression both remove patterns.

`tools/pe_recon.py` computes entropy for each section. Seeing 7.9 to 8.0 in large sections told us immediately that most of the file was encrypted or compressed.

### Packers and protectors

A packer compresses or encrypts a program and adds a small piece of code, the stub, that undoes this at runtime. The original code only exists in memory while the program runs. A protector is a packer that also fights analysis. It detects debuggers, hides imports, and turns code into forms that are hard to read.

Packers leave fingerprints, such as odd section names, empty sections, high entropy and tiny import tables. This file had all four.

### Assembly and disassembly

Machine code is bytes. Assembly is the same instructions written as text, for example `xor dword ptr [rsi], eax`. A disassembler converts bytes into assembly. We used Capstone, a disassembler library for Python. A decompiler goes further and produces C-like code, but here we read the assembly directly.

## Part 2: what we found, layer by layer

### First look: recon

We ran `tools/pe_recon.py`. It uses the `pefile` library to print the sections, their entropy, the imports and the overlay. The results:

- The file is a 64-bit console program (PE32+, x86-64).
- Section names like `kqihfdgz` and `ahbtcmsa` are random letters, not compiler names.
- One section of 3.7 MB has almost no data in the file. It is space reserved for something to be unpacked into.
- The import table lists only `lstrcpy` and `InitCommonControls`.
- A 4.4 MB overlay at the end has entropy 8.0.
- The last bytes of the file are 16 random-looking bytes, the text `ZEUSLOCK`, and a number.

This was enough to say "packed and protected" with confidence.

### Layer 1: the entry stub

We disassembled the entry point. The code does three things.

First, an anti-debug check. Anti-debug code detects whether someone is stepping through the program with a debugger. This one uses `call` followed by an `int3` byte. `int3` (byte `0xCC`) is the instruction debuggers place on a line to pause there, which is called a breakpoint. The code checks whether that byte is still `0xCC`.

Second, a decryption loop. It walks through the first 0x1000 bytes of section `kqihfdgz`, four bytes at a time. Each four-byte value is called a dword. It computes `(value XOR 0xA018003) + 0x705F000`. XOR is a bit operation that flips bits; doing it twice with the same number gives back the original, which makes it popular for simple encryption.

Third, it jumps into the bytes it just decrypted.

We repeated the loop in Python. The result disassembled into sensible code, which told us we had it right. Wrong decryption gives garbage instructions.

### Layer 2: aPLib, and our first mistake

The decrypted code first scans backwards through memory, one page at a time, for `MZ` and then `PE\0\0`. We first read this as "it searches for a hidden PE file that it will load". That would make it a PE loader, a piece of code that maps a second program into memory by hand instead of letting Windows do it. Malware does this often.

That reading was wrong. Looking at the code more carefully, it starts from its own address and walks backwards until it hits the start of its own file in memory. It is only finding its own image base, so that it can compute other addresses from it.

The rest of the code is a loop that reads one bit at a time and copies bytes either from the input or from earlier in the output. That shape is LZ compression. LZ (Lempel-Ziv) compression replaces repeated byte runs with "go back N bytes and copy M of them". This specific bit layout matches aPLib, a small compression library by Jørgen Ibsen that packers have used for decades. Its decompression routine is `aP_depack`.

We decompressed with aPLib from RVA `0x6bd2ba` and got 3.7 MB of output, which the code places at RVA `0x32a014` and then jumps to. For the aPLib step, `PROGRESS.md` now points to the decompressor in [herrcore/aplib-ripper](https://github.com/herrcore/aplib-ripper). That tool's own search mode looks for compressed PE files, which aPLib turns from `MZ` into `M8Z`. Our data is raw code, not a PE file, so we call its decompressor directly at the offset instead.

### Layer 3: Themida, and our second mistake

Our first plan was emulation. An emulator is a program that pretends to be a processor. It runs machine code by imitating each instruction, without the code ever running on the real CPU. That makes it safe, because nothing the code does reaches the real machine.

We used Unicorn, an emulator library. It ran the first two layers fine and then went in circles forever. We blamed the PEB. The PEB (Process Environment Block) is a structure Windows creates for every running program. It holds, among other things, the list of loaded DLLs. Packers walk this list to find Windows functions themselves, so that those functions never appear in the import table. Unicorn emulates only the CPU and does not create a PEB, so we thought the code was stuck looking for one. We planned to switch to Qiling, a framework built on Unicorn that also fakes a Windows environment, PEB included.

The real reason was different. The 3.7 MB output contains the text `Themida`. Themida is a commercial protector, and its fingerprints match: random section names, `lstrcpy` and `InitCommonControls` as the only imports, and an empty unpack section. Themida turns code into instructions for its own virtual machine. In this sense a virtual machine is an invented processor with its own instruction set, plus an interpreter that runs it. To read the protected code you would first have to reverse the invented processor. Themida also checks whether it is running in an emulator. Qiling would most likely have stalled the same way, so we dropped emulation.

### The overlay, and our third mistake

The overlay ends with 16 random bytes, `ZEUSLOCK`, and a size. We assumed the 16 bytes were an AES key and tried to decrypt.

AES is the standard symmetric cipher, meaning the same key encrypts and decrypts. Its key is 16, 24 or 32 bytes (AES-128, -192, -256). AES works on 16-byte blocks, and a mode says how blocks connect: ECB, CBC, CFB, OFB, CTR and GCM are the common ones. We also tried ChaCha20, Salsa20 and RC4, which are stream ciphers that produce a random-looking keystream XORed with the data. We tried the bytes directly and hashed with MD5, SHA-1 and SHA-256. A hash is a function that turns any input into a fixed-size fingerprint, and protectors often hash a password to make a key.

For each attempt we checked whether the output started with a known file signature: `MZ` for programs, `PK` for zip files, `78 9C` for zlib-compressed data, and so on. These signatures are called magic bytes. Nothing matched. Two "hits" came from outputs whose first byte happened to be `{`, which proves nothing.

We also checked the ciphertext for structure. ECB mode encrypts identical blocks to identical output, so repeated 16-byte blocks would have pointed to ECB. There were none.

The mistake was guessing instead of reading the code that decrypts the overlay. As it turned out, those 16 bytes are a salt, not a key. A salt is random data mixed into a key derivation so that the same password gives different keys in different files. The actual key comes from the USB drive, so guessing could never have worked.

### Running it safely

With static analysis stuck, we ran the program. Static analysis means reading a program without running it; dynamic analysis means running it and watching. Running an unknown program is risky, so we built a sandbox, an environment that limits what the program can touch.

Wine is a Linux program that runs Windows programs by implementing the Windows functions they call. It is not an emulator. The code runs on the real CPU, and Wine answers its Windows calls.

Bubblewrap (`bwrap`) is the sandbox around Wine. It uses Linux namespaces, which are the kernel feature that Docker containers are built on. A namespace gives a process its own private view of something, such as the network, the file system or the list of processes. Our sandbox had:

- a network namespace with only loopback (the machine talking to itself), so no internet
- the system directories mounted read-only, so nothing could be modified
- no home directory, so no personal files were visible
- no display and an empty set of environment variables
- one writable scratch directory under `/tmp`

We used bubblewrap instead of Docker because our user account has no permission to use the Docker service. We checked the isolation before running the exe. The sandbox listed only the `lo` network interface, and `/home` did not exist inside it.

The program ran under Wine, got through Themida, and printed "No licensed USB drive was detected. Please connect it and try again. Press Enter to close."

### Memory dumping

A memory dump is a copy of a running program's memory, saved to files. By the time the program waits for Enter, Themida has already unpacked the real code into memory, so a dump contains it in readable form.

On Linux every process has `/proc/<pid>/maps`, which lists its memory regions, and `/proc/<pid>/mem`, through which you can read them. A Wine program is an ordinary Linux process, so this works. On this machine, the Yama security setting `ptrace_scope` is 1, so a process can only read another process's memory if it is that process's parent (or grandparent, and so on). That is why `tools/sandbox/dump.py` starts Wine itself, waits 15 seconds, then reads every region. We got 253 regions, 187 MB. Joining the regions starting at `0x400000` gave us the unpacked program.

### Recognising Go

Running `strings` on the dump (it prints every run of readable characters) showed names like `runtime.main`, `crypto/aes` and `/usr/lib/go-1.22/src/...`. That means the program is written in Go, version 1.22, and it uses AES. One path was `/home/claude/zeuslock2/cmd/zeuslock-run/main.go`, which gives the author's project name.

Go is good news for reverse engineers. Go binaries carry a table called pclntab (program counter line table). The Go runtime uses it to print stack traces when a program crashes, so it cannot be removed. It maps every function's address to its full name. `tools/go_pclntab.py` finds the table (it starts with the bytes `F1 FF FF FF`), reads it, and disassembles chosen functions. It labels every call with the name of the function being called and every string the code loads. Instead of anonymous code we had names like `zeuslock/internal/lock.DecryptPayload`.

### Reading the functions

Go 1.22 passes function arguments in registers in a fixed order: `rax`, `rbx`, `rcx`, `rdi`, `rsi`, `r8` and onwards. A Go string is two values, a pointer to its bytes and a length. Knowing these conventions, we read each function.

`main.main` calls `ExtractSelfTrailer`, then `GetUSBCandidates`, then `GenerateUSBHash` and `DecryptPayload` for each drive, and finally `RunEmbeddedExecutable`. Each failure leads to `main.fail` with one of the error messages.

`ExtractTrailerFromFile` reads its own exe and checks for `ZEUSLOCK` 16 bytes from the end. It reads the 8-byte size as big-endian, meaning most significant byte first, unlike the little-endian order x86 normally uses. It then cuts the data into nonce, ciphertext and salt.

`GetUSBCandidates` lists drive letters and keeps those that `GetDriveTypeW` reports as removable. For each one it calls `getVolumeInfo`, `getDeviceInfo` and `getDriveSize`.

`getVolumeInfo` calls `GetVolumeInformationW` and returns the volume label (the drive's name) and its volume serial. The volume serial is a 32-bit number that Windows assigns when the drive is formatted. The code formats it with `%08X`, eight uppercase hex digits.

`getDeviceInfo` joins the drive root and the computer name (`os.Hostname`) and hashes them with SHA-512. It returns three slices of the hash in hex. Hex here means each byte written as two characters from `0-9a-f`. The names suggest a USB device serial, but these values are computed, not read from hardware.

`getDriveSize` calls `GetDiskFreeSpaceExW` and returns the second of its three outputs, the drive's total size in bytes.

`GenerateUSBHash` builds the text `A|B|C|label|serial|size` with `fmt.Sprintf` and returns its SHA-512 hash in hex. The format string `%s|%s|%s|%s|%s|%d` is visible in the dump.

`DecryptPayload` puts the salt in front of that hex hash, hashes the result with SHA-512, and uses the first 32 bytes as an AES-256 key. It decrypts in GCM mode with a 12-byte nonce and a 16-byte tag. A nonce ("number used once") makes each encryption unique, and the tag is a checksum that only the correct key reproduces. GCM checks the tag before returning anything, so a wrong key gives "decryption failed: USB parameters do not match" instead of garbage.

`RunEmbeddedExecutable` writes the decrypted bytes to the temp directory and runs them.

We matched struct fields by their offsets. A struct is a group of named values stored side by side in memory, and an offset is a value's distance from the start of the group. `GetUSBCandidates` writes a 0x68-byte `USBInfo` struct, and `GenerateUSBHash` reads from offsets 0x00 to 0x50 of it. Lining up those offsets shows which value lands in which position of the format string.

The trailer size also fit. It covers 12 bytes of nonce, the ciphertext with its 16-byte tag, and 16 bytes of salt, and the minimum size the code accepts (0x2C, 44 bytes) is exactly 12 + 16 + 16.

### Why the payload stays locked

The key depends on the hostname of the licensing PC, the drive letter, and the drive's label, volume serial and total size. The serial alone has about 4.3 billion possible values. Combined with the other unknowns that is far too many to guess, and the organisers have given no drive details.

That is acceptable. Our task is the source of the application, and the application is the launcher. Every function is now named and understood.

### Where the work stands

Writing the launcher out as Go source is now done — it lives in `reconstruction/`, builds, and passes its tests (see Part 3 and `reconstruction/README.md`). To redo the whole chain from scratch, follow the hands-on guide in Part 3, or the "Reproducing everything" section of `PROGRESS.md`, which also lists the known rough edges in our tools. The embedded payload stays encrypted.

A few Go facts will help when reading the disassembly:

- Every function begins by comparing the stack pointer with a limit and calling `runtime.morestack_noctxt` if the stack is too small. This is the stack-growth check, and it can be ignored.
- `runtime.convTstring` and `runtime.convT64` box a value into an interface. Seeing several in a row usually means arguments are being prepared for a `fmt` function.
- `runtime.concatstring2` is the `+` operator on two strings.
- Calls shown as `?` that land just past a function's start are `duffcopy` or `duffzero`, which copy or clear structs.
- Global variables are reached through `rip`-relative addresses. `os.Stdin`, `os.Stdout` and `os.Stderr` sit next to each other, which is how we told them apart, and `os.Args` is a three-word slice (pointer, length, capacity).

## Part 3: hands-on guide, reproduce it yourself

This guide takes you from the raw `ppqqcc.exe` to the point where the key derivation is understood, which is as far as the organisers' material allows. Each step has the same layout. You get what to do, the command, what you should see, and which section above explains why it works.

How the expected values were obtained. Steps 1 to 4 and step 10 were re-run on 2026-10-26 and matched our first run exactly. The values in steps 7 and 8 come from our first sandbox run, taken from the notes and from the dump we saved. If your numbers differ slightly in steps 7 and 8 (the process id, the exact region file names), that is normal. The sizes and the function table in steps 8 to 10 should match.

Run everything from the repo root. You need Linux with Python 3. Steps 6 to 8 also need Wine and bubblewrap. Step 12 optionally needs Go.

### Step 0: set up Python

```sh
python3 -m venv tools/re-venv
tools/re-venv/bin/pip install pefile capstone unicorn pycryptodome
```

The libraries are `pefile` (reads the Windows executable format), `capstone` (disassembler), `unicorn` (emulator, only used by an abandoned script) and `pycryptodome` (AES). The `-I` flag in every command below makes Python ignore the current directory and environment variables, so a file planted next to a script cannot hijack an import. Keep it.

### Step 1: look at the file

```sh
tools/re-venv/bin/python -I tools/pe_recon.py challenges/task3_ppqqcc/ppqqcc.exe
tail -c 32 challenges/task3_ppqqcc/ppqqcc.exe | xxd
```

You should see:

- `ImageBase=0x400000  EntryPointRVA=0x8b0000  EP VA=0xcb0000`
- Seven sections. Two have random names (`kqihfdgz`, `ahbtcmsa`), two large ones score entropy around 7.9, one 3.7 MB section holds almost nothing in the file, and the entry point sits in `ahbtcmsa`.
- Only two imports, `lstrcpy` and `InitCommonControls`.
- An overlay of 4,433,996 bytes with entropy 8.00.
- In the last 32 bytes, the 16 bytes `20dfc31e b3f6178d 87b740b9 fe422291`, then the text `ZEUSLOCK`, then `00 00 00 00 00 43 a8 3c`.

What it proves. The file is packed and protected, and it carries a trailer that the program probably reads itself. See "First look: recon" and "Entropy" above. The file size is 8,156,236 bytes. The trailer size `0x43a83c` is 4,433,980 bytes, which is the overlay minus the 16 bytes of `ZEUSLOCK` and the size field.

### Step 2: undo the first layer

```sh
tools/re-venv/bin/python -I tools/unpack_stage1.py challenges/task3_ppqqcc/ppqqcc.exe /tmp/ppqqcc-unpacked
```

Expected output:

```
stage2: 3743564 bytes (src consumed up to RVA 0x8affb2), loaded at RVA 0x32a014
```

The script does two things in one go, which the next two steps check separately. It applies `(dword ^ 0xA018003) + 0x705F000` to the first 0x1000 bytes of section `kqihfdgz`, then runs aPLib decompression. Output goes to `/tmp/ppqqcc-unpacked/stage1_image.bin` and `stage2.bin`. Nothing is executed. The script only reads bytes and does arithmetic. See "Layer 1: the entry stub".

To see the stub yourself first, disassemble the entry point:

```sh
tools/re-venv/bin/python -I - <<'EOF'
import pefile, capstone
pe = pefile.PE('challenges/task3_ppqqcc/ppqqcc.exe')
rva = 0x8b0000
code = pe.get_memory_mapped_image()[rva:rva + 0x80]
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
for i in md.disasm(code, 0x400000 + rva):
    print(hex(i.address), i.mnemonic, i.op_str)
EOF
```

Look for three things. First, `call` followed by `int3` and then `pop rax`, which is the anti-debug trick. Second, `cmp byte ptr [rbx], 0xcc`, the check that nobody put a breakpoint there. Third, the loop `xor dword ptr [rsi], eax` then `add dword ptr [rsi], ebx`, which is the decryption, with the constants `0xa018003` and `0x705f000` pushed just before it.

### Step 3: check that the first layer really decrypted

A wrong decryption gives garbage instructions, so the quickest test is to disassemble the result:

```sh
tools/re-venv/bin/python -I - <<'EOF'
import capstone
d = open('/tmp/ppqqcc-unpacked/stage1_image.bin', 'rb').read()
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
for i, ins in zip(range(6), md.disasm(d[0x6bd000:0x6bd040], 0x400000 + 0x6bd000)):
    print(hex(ins.address), ins.mnemonic, ins.op_str)
EOF
```

You should see six pushes of registers starting at `0xabd000`: `push rax`, `push rbx`, `push rcx`, `push rdx`, `push rsi`, `push rdi`. That is how a function begins, so the cipher is right. To see what garbage looks like, disassemble the same offset of the mapped image before the cipher is applied. Use `pefile.PE(...).get_memory_mapped_image()[0x6bd000:0x6bd040]` in place of `d[0x6bd000:0x6bd040]`.

### Step 4: undo the aPLib layer

Step 2 already did this, but check the result:

```sh
sha256sum /tmp/ppqqcc-unpacked/stage2.bin
grep -ao Themida /tmp/ppqqcc-unpacked/stage2.bin | head -1
```

Expected hash:

```
11af84f37c8337f3351d77a8ebc4c823aedd6275cc5228d72cf43d35a6122242
```

The `grep` should print `Themida`, and the first four bytes of `stage2.bin` are `e9 f8 17 00`, a `jmp`. This is where the story changes. The compressed data starts at RVA `0x6bd2ba` of the decrypted image, and the 3.7 MB it decompresses to is not our program. It is Themida. See "Layer 2" and "Layer 3" above.

Cross-check with a second implementation. [herrcore/aplib-ripper](https://github.com/herrcore/aplib-ripper) contains an independent aPLib decompressor, `aplib.decompress(data).do()`. Its command-line mode will not work here because it looks for compressed Windows programs (`M8Z`), and ours is raw code. Calling the decompressor directly on `stage1_image.bin` from offset `0x6bd2ba` should produce the same 3,743,564 bytes. We have not run this check. It is a good exercise, and it needs a small Python 3 shim, because the repo is Python 2 (`xrange` and byte strings).

The static road ends here. The program you want sits behind a virtual machine that Themida runs, and emulating it fails (see "Layer 3" for why). The overlay cannot be decrypted by guessing either (see "The overlay, and our third mistake"). That leaves running the program, safely.

### Step 5: decide how to run it safely

Only step 7 runs the executable. Do not run `ppqqcc.exe` directly on your desktop. Use a sandbox. We used Wine inside bubblewrap. A virtual machine with no network works as well.

Check that bubblewrap and Wine exist:

```sh
which bwrap wine && wine --version
```

We used Wine 11.20. See "Running it safely" for what each sandbox option does.

### Step 6: build the sandbox and check that it is isolated

```sh
mkdir -p /tmp/zlsb/work /tmp/zlsb/scripts
cp challenges/task3_ppqqcc/ppqqcc.exe /tmp/zlsb/work/
cp tools/sandbox/dump.py /tmp/zlsb/scripts/
tools/sandbox/run.sh sh -c 'cat /proc/net/dev; ls /home'
```

The second command must show only the `lo` interface, and `ls` must say that `/home` does not exist. If you see `eth0`, `wlan0` or your home directory, stop and fix the sandbox before going on. Then create the Wine prefix (this takes a while the first time):

```sh
tools/sandbox/run.sh sh -c 'timeout 120 wineboot -i'
```

### Step 7: run it and dump its memory

```sh
tools/sandbox/run.sh python3 -I /scripts/dump.py ppqqcc.exe 15 /work/dump
cat /tmp/zlsb/work/dump/stdout.txt
```

`dump.py` starts Wine, waits 15 seconds for Themida to finish unpacking, then reads every readable memory region of the process. It must be the parent of the process, because this machine's `ptrace_scope` is 1 (see "Memory dumping").

You should see:

```
target pid 3
253 regions dumped
```

and, in `stdout.txt`, the program's own message:

```
No licensed USB drive was detected. Please connect it and try again.

Press Enter to close.
```

That message is itself useful. It tells you the program reached its licence check, so Themida has already unpacked everything. The dump is about 187 MB, and it is mostly Wine's own files. If the dump script prints `target pid None`, wait longer (try 30 seconds), or check that `/proc/sys/kernel/yama/ptrace_scope` is not 2 or 3.

### Step 8: stitch the program image together

Look at `/tmp/zlsb/work/dump/maps.txt`. The regions from `00400000` to `00cb7000` that belong to `/work/ppqqcc.exe` or follow it directly are the program. Join them in address order:

```sh
mkdir -p /tmp/zl
cd /tmp/zlsb/work/dump && cat 000000400000-* 000000401000-* 000000594000-* 000000728000-* \
  000000729000-* 00000072a000-* 000000cb1000-* > /tmp/zl/image.bin && cd -
ls -l /tmp/zl/image.bin
```

The file must be exactly 9,138,176 bytes, which is `0xcb7000 - 0x400000`. If the size is wrong, a region is missing or the file names differ in your run. Compare against `maps.txt`.

### Step 9: confirm it is Go

```sh
strings -n 6 /tmp/zl/image.bin | grep -E 'go-1\.22|zeuslock|crypto/aes' | sort -u | head
```

You should see paths such as `/home/claude/zeuslock2/cmd/zeuslock-run/main.go`, `zeuslock/internal/lock`, and AES types like `*aes.aesCipher`. See "Recognising Go".

### Step 10: list the functions

```sh
IMAGE=/tmp/zl/image.bin tools/re-venv/bin/python -I tools/go_pclntab.py
```

The first line must read:

```
pcHeader @ 0x51b0c0 nfunc 2134 text 0x401000
```

and the output continues with one line per function (address, size, name). The ones that matter are:

| Address | Function |
| --- | --- |
| `0x4c1b80` | `zeuslock/internal/lock.init` |
| `0x4c1be0` | `lock.GenerateUSBHash` |
| `0x4c1e60` | `lock.DecryptPayload` |
| `0x4c21c0` | `lock.RunEmbeddedExecutable` |
| `0x4c2500` | `lock.ExtractSelfTrailer` |
| `0x4c2580` | `lock.ExtractTrailerFromFile` |
| `0x4c28a0` | `lock.sha512Sum16` |
| `0x4c2bc0` | `lock.GetUSBCandidates` |
| `0x4c2ea0` | `lock.getWindowsDrives` |
| `0x4c3060` | `lock.isRemovableDrive` |
| `0x4c31a0` | `lock.getVolumeInfo` |
| `0x4c34a0` | `lock.getDeviceInfo` |
| `0x4c3580` | `lock.getDriveSize` |
| `0x4c3900`, `0x4c3a80`, `0x4c3b00` | `main.pause`, `main.fail`, `main.main` |

This is the payoff of the whole route. Go's function table survived Themida, so you get real names instead of anonymous code. See "Recognising Go".

### Step 11: read the functions in a sensible order

Disassemble one function at a time by name:

```sh
IMAGE=/tmp/zl/image.bin tools/re-venv/bin/python -I tools/go_pclntab.py main.main
```

Read in this order, and look for the listed evidence in each. The tool prints the called function's name beside every `call` and the text beside every loaded string.

| Order | Function | What to look for |
| --- | --- | --- |
| 1 | `main.main` | Calls to `ExtractSelfTrailer`, `GetUSBCandidates`, then `GenerateUSBHash`, `DecryptPayload` and `RunEmbeddedExecutable`. The four messages. |
| 2 | `main.fail`, `main.pause` | `fmt.Fprintln`, `bufio.(*Reader).ReadString` with `0xa` (newline), `os.Exit` with 1. |
| 3 | `ExtractTrailerFromFile` | `os.ReadFile`, `runtime.memequal` over 8 bytes (the `ZEUSLOCK` check), the bound `0x2c`. |
| 4 | `GetUSBCandidates` | Calls to `getWindowsDrives`, `isRemovableDrive`, `getVolumeInfo`, `getDeviceInfo`, `getDriveSize`. Each struct is `0x68` bytes. |
| 5 | `getVolumeInfo`, `getDriveSize` | `GetVolumeInformationW`, `GetDiskFreeSpaceExW`, the format string `%08X`. |
| 6 | `getDeviceInfo`, `sha512Sum16` | `os.hostname`, `concatstring2`, `crypto/sha512.Sum512`, then hex conversion of three slices of the digest (16, 8 and 8 bytes). |
| 7 | `GenerateUSBHash` | `fmt.Sprintf` with `%s\|%s\|%s\|%s\|%s\|%d`, then `Sum512`. |
| 8 | `DecryptPayload` | `Sum512`, `crypto/aes.NewCipher` with length `0x20` (32), `newGCMWithNonceAndTagSize` with 12 and 16, the error text `decryption failed: USB parameters do not match`. |
| 9 | `RunEmbeddedExecutable` | Writing a file, `os/exec`, the deferred removal. |

Use the rules from "Reading the functions". Go passes arguments in `rax`, `rbx`, `rcx`, `rdi`, `rsi`, `r8`, and a string is a pointer plus a length. A line like `mov ebx, 0x2e` right after `lea rax, [rip + ...]` is almost always a string whose length is `0x2e`. The tool prints that string for you.

### Step 12: check the key derivation

Now put the pieces together. The scheme you have read is:

```
h        = sha512(drive_root + hostname)
A, B, C  = hex(h[0:16]), hex(h[16:24]), hex(h[24:32])
usbhash  = hex(sha512("A|B|C|label|serial|size"))
key      = sha512(salt + usbhash)[:32]        (AES-256-GCM, nonce first, salt last)
```

The script `tools/zeuslock_decrypt.py` implements it. Its arguments are the executable, an output file, the drive root, the hostname, the volume label, the volume serial in hex, and the drive size in bytes:

```sh
tools/re-venv/bin/python -I tools/zeuslock_decrypt.py \
  challenges/task3_ppqqcc/ppqqcc.exe /tmp/payload.bin 'E:\' MYHOST MYLABEL 1234ABCD 16000000000
```

With made-up values this ends with `ValueError: MAC check failed`. That is the correct result. AES-GCM refuses to return anything when the key is wrong, and every wrong drive, wrong hostname or wrong size fails the same way. A correct set of values would print `ok:` and write the decrypted executable. We have no such values, so step 12 cannot finish. That is why the payload stays locked.

To check the scheme without the real drive, run the tests of the reconstruction. They compare `GenerateUSBHash` with a known value, decrypt a small test payload through the full key derivation, check the exact wrong-key error, and parse the real trailer of `ppqqcc.exe` (a 4,433,952-byte ciphertext, plus its nonce and salt). The expected values were computed separately in Python:

```sh
cd reconstruction && go test ./...
```

This needs Go. If it passes, the Go code agrees with an independent implementation on the hash, the key and the error text, and with the real file on the trailer layout.

### Step 13: compare with the reconstruction

Open `reconstruction/README.md`. Its table maps each recovered function to a source file. For each row, disassemble the function from step 11 and check the behaviour in the source. For example, check that `main.go` prints the four messages in the same conditions as `main.main`, that `lock.go` uses the same 8-byte magic and the `0x2c` minimum, and that `usb_windows.go` calls the same four kernel32 functions. This is the review that has not been done by a second person yet.

### If something goes wrong

| Symptom | Likely cause and fix |
| --- | --- |
| `ModuleNotFoundError: pefile` | Run with `tools/re-venv/bin/python`, not the system Python. |
| `stage2: ...` shows a different size | The input file is not the original. Check that its size is 8,156,236 bytes. |
| `target pid None` in step 7 | Themida needs more time (raise 15 to 30), or `ptrace_scope` blocks reading. |
| Image is not 9,138,176 bytes | A region is missing from step 8. Compare with `maps.txt`. |
| `go_pclntab.py` finds no header | The image is wrong or incomplete, or the dump was taken before unpacking finished. |
| `MAC check failed` in step 12 | Expected for any wrong drive parameters. |

## Part 4: what the mistakes taught us

The first mistake was reading one instruction pattern (the `MZ` scan) as the whole story. Reading a little further would have shown that the scan finds the program's own base and that a decompressor follows.

The second was blaming the tool. When the emulator spun forever, a quick `strings` search on the decompressed stage would have shown `Themida` and saved the detour into Qiling.

The third was guessing at a format instead of finding the code that reads it. The bytes at the end of a file are only labels until you see the code that uses them, and here the "key" turned out to be a salt.

In each case, a few minutes of looking at the evidence would have beaten a long attempt based on a guess.

## Glossary

| Term | Meaning |
| --- | --- |
| aPLib | Small LZ compression library that packers often use |
| AES, AES-256 | Standard symmetric cipher; 256 is the key size in bits |
| Anti-debug | Code that detects or blocks debuggers |
| Assembly | Machine instructions written as readable text |
| Big-endian | Byte order with the most significant byte first |
| Breakpoint, `int3` | Byte `0xCC`, which debuggers insert to pause a program |
| Bubblewrap | Linux sandbox tool built on namespaces |
| Capstone | Disassembler library |
| Dword | A 4-byte value |
| Dynamic analysis | Studying a program by running it |
| Emulator | Software that imitates a processor |
| Entropy | Randomness of bytes, 0 to 8 bits per byte |
| Entry point | Address where a program starts |
| GCM | AES mode that both encrypts and authenticates, using a nonce and a tag |
| Go, pclntab | Programming language; its table of function addresses and names |
| Hash, SHA-512 | Fixed-size fingerprint of data; SHA-512 produces 64 bytes |
| Hex | Base 16, written with 0-9 and a-f |
| Image base | Address where a PE file is loaded |
| Import table | List of outside functions a PE file needs |
| LZ compression | Compression that replaces repeats with back-references |
| Magic bytes | Fixed bytes that identify a file type, such as `MZ` |
| Memory dump | Copy of a process's memory saved to files |
| Namespace | Linux feature that gives a process a private view of a resource |
| Nonce | Value used once per encryption |
| Overlay | Data appended after a PE file's last section |
| Packer, protector | Wrapper that compresses or encrypts a program; a protector also resists analysis |
| PE, `MZ`, `PE\0\0` | Windows executable format and its two header markers |
| PE loader | Code that maps a PE file into memory by hand |
| PEB | Windows per-process structure listing loaded DLLs |
| Qiling | Emulation framework that adds a fake OS to Unicorn |
| RVA, VA | Address relative to the image base; real address in memory |
| Salt | Random data mixed into a key derivation |
| Sandbox | Restricted environment for running untrusted code |
| Section | Named block of a PE file, such as `.text` |
| Static analysis | Studying a program without running it |
| Struct, offset | Group of values in memory; a value's distance from the group's start |
| Stub | Small piece of code a packer adds to unpack the real program |
| Tag | GCM checksum that proves the key and data are correct |
| Themida | Commercial protector that uses code virtualisation |
| Unicorn | CPU emulator library |
| Virtual machine (protector) | Invented instruction set plus interpreter, used to hide code |
| Wine | Runs Windows programs on Linux by implementing the Windows API |
| XOR | Bit operation; applying it twice with the same value undoes it |
