package util

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
)

// HashSHA256 returns the lowercase hex-encoded SHA-256 digest of data.
func HashSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// HashSHA512 returns the lowercase hex-encoded SHA-512 digest of data.
func HashSHA512(data []byte) string {
	sum := sha512.Sum512(data)
	return hex.EncodeToString(sum[:])
}

// HMACSHA256 returns the lowercase hex-encoded HMAC-SHA256 over data using key.
func HMACSHA256(key, data []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}

// ConstantTimeCompareHex compares two hex-encoded strings in constant time and
// returns true if they are equal. If either string is not valid hex, the
// function will fall back to a constant-time comparison of the raw strings.
func ConstantTimeCompareHex(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	ab, err1 := hex.DecodeString(a)
	bb, err2 := hex.DecodeString(b)
	if err1 != nil || err2 != nil {
		// Fall back to comparing the raw byte sequences in constant time.
		return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
	}
	return subtle.ConstantTimeCompare(ab, bb) == 1
}
