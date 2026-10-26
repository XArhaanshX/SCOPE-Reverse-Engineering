// Command zeuslock-run is a USB-licence launcher.
//
// It reads an AES-256-GCM encrypted executable appended to its own file (the
// "trailer"), derives the decryption key from the properties of a connected
// removable drive plus this PC's hostname, decrypts the executable and runs it.
// Without the licensed drive it refuses to run.
//
// This file is a human-readable reconstruction of the launcher recovered from
// ppqqcc.exe (Go 1.22, module "zeuslock", package cmd/zeuslock-run). It was
// rebuilt from the pclntab-named disassembly of the unpacked image; see
// notes/PROGRESS.md and notes/progress_readable.md for how every fact below
// was recovered. Behaviour (control flow, messages, exit code) matches the
// original; names of unexported locals are our own, since compilation discards
// them.
package main

import (
	"bufio"
	"fmt"
	"os"

	"zeuslock/internal/lock"
)

func main() {
	// 1. Parse the encrypted payload appended to our own executable.
	trailer, err := lock.ExtractSelfTrailer()
	if err != nil {
		fail("This application is not set up correctly: " + err.Error())
	}

	// 2. Enumerate attached removable drives. No removable drive at all is the
	//    "not detected" case, distinct from "detected but not licensed" below.
	candidates, err := lock.GetUSBCandidates()
	if err != nil {
		fail("No licensed USB drive was detected. Please connect it and try again.")
	}

	// 3. Try each drive. The correct one derives a key that passes the GCM tag
	//    check; wrong drives fail it and are skipped.
	for _, usb := range candidates {
		payload, err := lock.DecryptPayload(trailer, lock.GenerateUSBHash(usb))
		if err != nil {
			continue
		}
		if err := lock.RunEmbeddedExecutable(payload, os.Args[1:]); err != nil {
			fail("Error running the application: " + err.Error())
		}
		return
	}

	// 4. Drives were present but none produced a valid key.
	fail("This USB drive is not licensed for this application. Access denied.")
}

// fail prints msg to stdout, waits for the user, and exits with status 1.
func fail(msg string) {
	fmt.Println(msg)
	pause()
	os.Exit(1)
}

// pause keeps a double-clicked console window open until the user presses
// Enter, so the message can be read.
func pause() {
	fmt.Print("\nPress Enter to close.")
	bufio.NewReader(os.Stdin).ReadString('\n')
}
