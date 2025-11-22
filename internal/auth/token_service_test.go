package auth

import (
	"testing"

	"github.com/GoBetterAuth/go-better-auth/pkg/domain"
)

// TestTokenServiceGenerateToken verifies basic token generation
func TestTokenServiceGenerateToken(t *testing.T) {
	config := &domain.Config{
		Secret: "test_secret",
	}
	ts := NewTokenService(config)

	token, err := ts.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	if token == "" {
		t.Fatal("GenerateToken returned empty token")
	}
}

// TestTokenServiceHashToken verifies token hashing with secret
func TestTokenServiceHashToken(t *testing.T) {
	secret := "test_secret"
	config := &domain.Config{
		Secret: secret,
	}
	ts := NewTokenService(config)

	token := "test_token"
	hash1 := ts.HashToken(token)
	hash2 := ts.HashToken(token)

	if hash1 == "" {
		t.Fatal("HashToken returned empty result")
	}

	// Same token should produce same hash
	if hash1 != hash2 {
		t.Fatalf("Hashes don't match: %s != %s", hash1, hash2)
	}

	// With different secret, should produce different hash
	differentConfig := &domain.Config{
		Secret: "different_secret",
	}
	differentTS := NewTokenService(differentConfig)
	hash3 := differentTS.HashToken(token)

	if hash1 == hash3 {
		t.Fatal("Different secrets should produce different hashes")
	}
}

// TestTokenServiceEncryptedToken verifies encryption and decryption
func TestTokenServiceEncryptedToken(t *testing.T) {
	secret := "encryption_secret"
	config := &domain.Config{
		Secret: secret,
	}
	ts := NewTokenService(config)

	// Generate encrypted token
	encrypted, err := ts.GenerateEncryptedToken()
	if err != nil {
		t.Fatalf("GenerateEncryptedToken failed: %v", err)
	}

	if encrypted == "" {
		t.Fatal("GenerateEncryptedToken returned empty result")
	}

	// Decrypt token
	decrypted, err := ts.DecryptToken(encrypted)
	if err != nil {
		t.Fatalf("DecryptToken failed: %v", err)
	}

	if decrypted == "" {
		t.Fatal("DecryptToken returned empty result")
	}

	// Decryption with wrong secret should fail
	wrongConfig := &domain.Config{
		Secret: "wrong_secret",
	}
	wrongTS := NewTokenService(wrongConfig)
	_, err = wrongTS.DecryptToken(encrypted)
	if err == nil {
		t.Fatal("DecryptToken should fail with wrong secret")
	}
}

// TestTokenServiceNoSecret verifies error handling when secret is missing
func TestTokenServiceNoSecret(t *testing.T) {
	config := &domain.Config{
		Secret: "",
	}
	ts := NewTokenService(config)

	// EncryptedToken should fail without secret
	_, err := ts.GenerateEncryptedToken()
	if err == nil {
		t.Fatal("GenerateEncryptedToken should fail without secret")
	}

	// DecryptToken should fail without secret
	_, err = ts.DecryptToken("encrypted_token")
	if err == nil {
		t.Fatal("DecryptToken should fail without secret")
	}
}
