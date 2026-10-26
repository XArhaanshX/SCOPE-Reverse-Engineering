# How we took apart ppqqcc.exe, explained

This is the plain-language companion to `PROGRESS.md`. It explains every term that file uses, and it shows how we found each fact, including the wrong turns. Read it top to bottom; each section builds on the one before.

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

### Where the work stops

The last step, writing the launcher out as Go source, has not started. Whoever picks it up should start from the "Handoff status" and "Reproducing everything" sections of `PROGRESS.md`. They list what is done, the exact commands to rebuild every intermediate file, and the known rough edges in our tools.

A few Go facts will help when reading the disassembly:

- Every function begins by comparing the stack pointer with a limit and calling `runtime.morestack_noctxt` if the stack is too small. This is the stack-growth check, and it can be ignored.
- `runtime.convTstring` and `runtime.convT64` box a value into an interface. Seeing several in a row usually means arguments are being prepared for a `fmt` function.
- `runtime.concatstring2` is the `+` operator on two strings.
- Calls shown as `?` that land just past a function's start are `duffcopy` or `duffzero`, which copy or clear structs.
- Global variables are reached through `rip`-relative addresses. `os.Stdin`, `os.Stdout` and `os.Stderr` sit next to each other, which is how we told them apart, and `os.Args` is a three-word slice (pointer, length, capacity).

## Part 3: what the mistakes taught us

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
