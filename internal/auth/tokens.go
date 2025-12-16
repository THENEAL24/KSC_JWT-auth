package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"time"
)

func GenerateRefreshToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func HashRefreshToken(token string) (string) {
	hashed := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hashed[:])
}

func GenerateTokenPair(userID int32, roles []string) (accessToken, refreshToken, hashedRefreshToken string, expiresAt time.Time, err error) {
    refreshToken, err = GenerateRefreshToken()
    if err != nil {
        return "", "", "", time.Time{}, err
    }

    hashedRefreshToken = HashRefreshToken(refreshToken)

    accessToken, err = GenerateJWT(userID, roles)
    if err != nil {
        return "", "", "", time.Time{}, err
    }

    ttlStr := os.Getenv("REFRESH_TOKEN_TTL")
    if ttlStr == "" {
        ttlStr = "720h"
    }
    
    ttl, err := time.ParseDuration(ttlStr)
    if err != nil {
        ttl = 30 * 24 * time.Hour
    }
    
    expiresAt = time.Now().Add(ttl)

    return accessToken, refreshToken, hashedRefreshToken, expiresAt, nil
}

