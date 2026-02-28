package crypto

import (
	"bytes"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := make([]byte, KeySize)
	copy(key, "test-key-32-bytes-long-exactly!!")

	plaintext := []byte("hello, world")

	ciphertext, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if bytes.Equal(ciphertext, plaintext) {
		t.Fatal("ciphertext should differ from plaintext")
	}

	decrypted, err := Decrypt(key, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("got %q, want %q", decrypted, plaintext)
	}
}

func TestDecryptWrongKey(t *testing.T) {
	key1 := make([]byte, KeySize)
	key2 := make([]byte, KeySize)
	copy(key1, "key-one-32-bytes-long-exactly!!!")
	copy(key2, "key-two-32-bytes-long-exactly!!!")

	ciphertext, err := Encrypt(key1, []byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	_, err = Decrypt(key2, ciphertext)
	if err == nil {
		t.Fatal("expected error decrypting with wrong key")
	}
}

func TestDecryptTruncatedData(t *testing.T) {
	_, err := Decrypt(make([]byte, KeySize), []byte("short"))
	if err == nil {
		t.Fatal("expected error for truncated data")
	}
}

func TestDeriveKeyDeterministic(t *testing.T) {
	salt, err := GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt: %v", err)
	}

	key1 := DeriveKey([]byte("password"), salt)
	key2 := DeriveKey([]byte("password"), salt)
	key3 := DeriveKey([]byte("different"), salt)

	if !bytes.Equal(key1, key2) {
		t.Fatal("same password+salt should produce same key")
	}
	if bytes.Equal(key1, key3) {
		t.Fatal("different passwords should produce different keys")
	}
	if len(key1) != KeySize {
		t.Fatalf("key length: got %d, want %d", len(key1), KeySize)
	}
}

func TestGenerateSaltUniqueness(t *testing.T) {
	salt1, err := GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt: %v", err)
	}

	salt2, err := GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt: %v", err)
	}

	if bytes.Equal(salt1, salt2) {
		t.Fatal("salts should be unique")
	}
	if len(salt1) != SaltSize {
		t.Fatalf("salt length: got %d, want %d", len(salt1), SaltSize)
	}
}

func TestEncryptProducesUniqueCiphertext(t *testing.T) {
	key := make([]byte, KeySize)
	copy(key, "test-key-32-bytes-long-exactly!!")

	ct1, err := Encrypt(key, []byte("same"))
	if err != nil {
		t.Fatalf("Encrypt 1: %v", err)
	}

	ct2, err := Encrypt(key, []byte("same"))
	if err != nil {
		t.Fatalf("Encrypt 2: %v", err)
	}

	if bytes.Equal(ct1, ct2) {
		t.Fatal("encrypting same plaintext twice should produce different ciphertext (random nonce)")
	}
}
