// Package lock implements the licence check and payload decryption for the
// zeuslock launcher. This file holds the platform-independent parts: trailer
// parsing, the device/USB hash, AES-256-GCM decryption and running the
// decrypted executable. Removable-drive enumeration is OS-specific and lives in
// usb_windows.go (and a stub in usb_other.go).
//
// Reconstructed from zeuslock/internal/lock in the unpacked ppqqcc.exe.
package lock

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
)

// magic marks the trailer. It sits 16 bytes from the end of the file,
// immediately before the 8-byte big-endian trailer size.
const magic = "ZEUSLOCK"

// minTrailer is the smallest acceptable trailer size: a 12-byte nonce, a
// minimal GCM ciphertext (its 16-byte tag) and a 16-byte salt.
const minTrailer = 12 + 16 + 16 // 0x2C

// ErrNoTrailer reports that the executable carries no embedded payload.
var ErrNoTrailer = errors.New("no protected payload is embedded in this executable")

// Trailer holds the parsed pieces of the appended, encrypted payload.
type Trailer struct {
	Nonce      []byte // 12 bytes
	Ciphertext []byte // ciphertext followed by its 16-byte GCM tag
	Salt       []byte // 16 bytes
}

// ExtractSelfTrailer parses the trailer from the running executable's own file.
func ExtractSelfTrailer() (*Trailer, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("locating own executable: %w", err)
	}
	return ExtractTrailerFromFile(self)
}

// ExtractTrailerFromFile reads path and parses its ZEUSLOCK trailer.
//
// Layout, measured from the end of the file:
//
//	[ nonce 12 ][ ciphertext + GCM tag 16 ][ salt 16 ][ "ZEUSLOCK" ][ size uint64 BE ]
//
// size counts the nonce, ciphertext and salt (everything before the magic).
func ExtractTrailerFromFile(path string) (*Trailer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading executable: %w", err)
	}
	n := len(data)
	if n < 16 || string(data[n-16:n-8]) != magic {
		return nil, ErrNoTrailer
	}
	size := int(binary.BigEndian.Uint64(data[n-8:]))
	if size < minTrailer || n < size+16 {
		return nil, errors.New("corrupt trailer")
	}
	blob := data[n-16-size : n-16]
	return &Trailer{
		Nonce:      blob[:12],
		Ciphertext: blob[12 : len(blob)-16],
		Salt:       blob[len(blob)-16:],
	}, nil
}

// USBInfo describes one candidate removable drive. The first five fields feed
// GenerateUSBHash; Root is used only to compute A, B and C in getDeviceInfo.
// In the original this is a 0x68-byte struct; GenerateUSBHash reads offsets
// 0x00..0x50 (A, B, C, Label, Serial, Size), i.e. every field except Root.
type USBInfo struct {
	A, B, C string // hex slices of sha512(Root + hostname)
	Label   string // volume label
	Serial  string // volume serial, formatted %08X
	Size    int64  // total drive size in bytes
	Root    string // drive root such as `E:\`
}

// getDeviceInfo hashes the drive root joined with the hostname and returns
// three hex slices of the digest. Despite the "device" name these are derived,
// not read from the hardware.
func getDeviceInfo(root string) (a, b, c string, err error) {
	host, err := os.Hostname()
	if err != nil {
		return "", "", "", err
	}
	h := sha512.Sum512([]byte(root + host))
	return hex.EncodeToString(h[0:16]), hex.EncodeToString(h[16:24]), hex.EncodeToString(h[24:32]), nil
}

// GenerateUSBHash returns the hex SHA-512 of "A|B|C|label|serial|size".
// The format string "%s|%s|%s|%s|%s|%d" is visible verbatim in the dump.
func GenerateUSBHash(u USBInfo) string {
	s := fmt.Sprintf("%s|%s|%s|%s|%s|%d", u.A, u.B, u.C, u.Label, u.Serial, u.Size)
	sum := sha512.Sum512([]byte(s))
	return hex.EncodeToString(sum[:])
}

// DecryptPayload derives the AES-256 key as sha512(salt || usbHash)[:32] and
// opens the GCM ciphertext. The wrong drive yields the wrong key and fails the
// GCM tag check, so no plaintext is ever returned for an unlicensed drive.
func DecryptPayload(t *Trailer, usbHash string) ([]byte, error) {
	keyMaterial := sha512.Sum512(append(append([]byte{}, t.Salt...), usbHash...))
	block, err := aes.NewCipher(keyMaterial[:32])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block) // standard 12-byte nonce, 16-byte tag
	if err != nil {
		return nil, err
	}
	pt, err := gcm.Open(nil, t.Nonce, t.Ciphertext, nil)
	if err != nil {
		return nil, errors.New("decryption failed: USB parameters do not match")
	}
	return pt, nil
}

// RunEmbeddedExecutable writes the decrypted payload to a temporary file and
// runs it with the given arguments, forwarding the standard streams.
func RunEmbeddedExecutable(payload []byte, args []string) error {
	f, err := os.CreateTemp("", "zeuslock-*.exe")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err := f.Write(payload); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, 0o700); err != nil {
		return err
	}
	cmd := exec.Command(name, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}
