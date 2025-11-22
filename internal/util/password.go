package util

import (
	"github.com/alexedwards/argon2id"
)

// HashPassword hashes the given password using Argon2id.
// Returns the encoded hash string or an error.
func HashPassword(password string) (string, error) {
	hash, err := argon2id.CreateHash(password, argon2id.DefaultParams)
	if err != nil {
		return "", err
	}
	return hash, nil
}

func VerifyPassword(password string, hash string) (bool, error) {
	return argon2id.ComparePasswordAndHash(password, hash)
}
