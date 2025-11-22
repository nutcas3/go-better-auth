package util

import (
	"testing"
)

// TestGenerateToken verifies token generation works
func TestGenerateToken(t *testing.T) {
	token, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	if token == "" {
		t.Fatal("GenerateToken returned empty token")
	}
}

// TestEncryptDecryptToken verifies encryption and decryption work correctly
func TestEncryptDecryptToken(t *testing.T) {
	token := "sensitive_token_data"
	secret := "my_encryption_secret"

	// Encrypt token
	encrypted, err := EncryptToken(token, secret)
	if err != nil {
		t.Fatalf("EncryptToken failed: %v", err)
	}

	if encrypted == "" {
		t.Fatal("EncryptToken returned empty result")
	}

	// Decrypt token
	decrypted, err := DecryptToken(encrypted, secret)
	if err != nil {
		t.Fatalf("DecryptToken failed: %v", err)
	}

	if decrypted != token {
		t.Fatalf("Decrypted token mismatch: expected %s, got %s", token, decrypted)
	}

	// Verify decryption fails with wrong secret
	_, err = DecryptToken(encrypted, "wrong_secret")
	if err == nil {
		t.Fatal("DecryptToken should fail with wrong secret")
	}
}

// TestHashTokenWithSecret verifies HMAC hashing of tokens
func TestHashTokenWithSecret(t *testing.T) {
	token := "test_token"
	secret := "my_secret_key"

	hash1 := HashTokenWithSecret(token, secret)
	hash2 := HashTokenWithSecret(token, secret)

	if hash1 == "" {
		t.Fatal("HashTokenWithSecret returned empty result")
	}

	// Same token and secret should produce same hash
	if hash1 != hash2 {
		t.Fatalf("Hashes don't match: %s != %s", hash1, hash2)
	}

	// Different secret should produce different hash
	hash3 := HashTokenWithSecret(token, "different_secret")
	if hash1 == hash3 {
		t.Fatal("Different secrets should produce different hashes")
	}
}

// TestGenerateRandomBytes verifies random byte generation
func TestGenerateRandomBytes(t *testing.T) {
	// Valid case
	bytes, err := GenerateRandomBytes(32)
	if err != nil {
		t.Fatalf("GenerateRandomBytes(32) failed: %v", err)
	}

	if len(bytes) != 32 {
		t.Fatalf("Expected 32 bytes, got %d", len(bytes))
	}

	// Two calls should produce different results
	bytes2, err := GenerateRandomBytes(32)
	if err != nil {
		t.Fatalf("GenerateRandomBytes(32) failed: %v", err)
	}

	same := true
	for i := 0; i < len(bytes); i++ {
		if bytes[i] != bytes2[i] {
			same = false
			break
		}
	}

	if same {
		t.Fatal("Random bytes should be different")
	}

	// Invalid case: n <= 0
	_, err = GenerateRandomBytes(0)
	if err == nil {
		t.Fatal("GenerateRandomBytes(0) should return error")
	}

	_, err = GenerateRandomBytes(-1)
	if err == nil {
		t.Fatal("GenerateRandomBytes(-1) should return error")
	}
}
