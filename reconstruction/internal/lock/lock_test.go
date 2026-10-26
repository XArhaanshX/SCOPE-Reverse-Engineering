package lock

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Vectors below were computed independently in Python
// (tools/zeuslock_decrypt.py uses the same scheme). If these pass, the Go
// reconstruction's hash and key derivation agree with the recovered scheme.

func TestGenerateUSBHash(t *testing.T) {
	got := GenerateUSBHash(USBInfo{
		A: "aa", B: "bb", C: "cc",
		Label: "MYDRIVE", Serial: "1A2B3C4D", Size: 1000000,
	})
	want := "23847ac32db145a1f58ed0b6c4a243e92e17d6ba35e7dbd762be212198d25585" +
		"c3d952afcb1dfbfd6d256373297d79fa66f44d931dca8b1fde266dd61d6554dd"
	if got != want {
		t.Fatalf("GenerateUSBHash mismatch:\n got=%s\nwant=%s", got, want)
	}
}

// TestDecryptPayloadEndToEnd exercises the whole salt||usbHash -> sha512 ->
// key[:32] -> AES-256-GCM path against a Python-generated ciphertext.
func TestDecryptPayloadEndToEnd(t *testing.T) {
	usbHash := "23847ac32db145a1f58ed0b6c4a243e92e17d6ba35e7dbd762be212198d25585" +
		"c3d952afcb1dfbfd6d256373297d79fa66f44d931dca8b1fde266dd61d6554dd"
	salt, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	nonce, _ := hex.DecodeString("000102030405060708090a0b")
	ctTag, _ := hex.DecodeString("106ce9ded81b907e011caf3fd8aebcf9f1649b90f4d0596410bc38c30a")

	pt, err := DecryptPayload(&Trailer{Nonce: nonce, Ciphertext: ctTag, Salt: salt}, usbHash)
	if err != nil {
		t.Fatalf("DecryptPayload: %v", err)
	}
	if string(pt) != "hello payload" {
		t.Fatalf("plaintext = %q, want %q", pt, "hello payload")
	}
}

func TestDecryptPayloadWrongKey(t *testing.T) {
	salt, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	nonce, _ := hex.DecodeString("000102030405060708090a0b")
	ctTag, _ := hex.DecodeString("106ce9ded81b907e011caf3fd8aebcf9f1649b90f4d0596410bc38c30a")

	_, err := DecryptPayload(&Trailer{Nonce: nonce, Ciphertext: ctTag, Salt: salt}, "wronghash")
	if err == nil {
		t.Fatal("expected failure with wrong key, got nil")
	}
	if !strings.Contains(err.Error(), "USB parameters do not match") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestExtractRealTrailer parses the actual challenge binary (if present) and
// checks the trailer against the documented values.
func TestExtractRealTrailer(t *testing.T) {
	path := filepath.Join("..", "..", "..", "challenges", "task3_ppqqcc", "ppqqcc.exe")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("challenge binary not present: %v", err)
	}
	tr, err := ExtractTrailerFromFile(path)
	if err != nil {
		t.Fatalf("ExtractTrailerFromFile: %v", err)
	}
	if n := hex.EncodeToString(tr.Nonce); n != "c43df3ef86346230a10a180c" {
		t.Errorf("nonce = %s", n)
	}
	if s := hex.EncodeToString(tr.Salt); s != "20dfc31eb3f6178d87b740b9fe422291" {
		t.Errorf("salt = %s", s)
	}
	if len(tr.Ciphertext) != 4433952 { // size 0x43a83c - 12 nonce - 16 salt
		t.Errorf("ciphertext len = %d, want 4433952", len(tr.Ciphertext))
	}
}
