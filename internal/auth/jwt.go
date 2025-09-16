package auth

import (
	"os"
	"errors"
    "time"
    "github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
)

var jwtSecret []byte

func InitJWTSecret() error {
    godotenv.Load()

    secret := os.Getenv("JWT_SECRET")
    if secret == "" {
        secret = "devsecret" // local
    }
    jwtSecret = []byte(secret)
    return nil
}

func GenerateJWT(userID int32, roles []string) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
        "roles":   roles,
        "exp":     time.Now().Add(24 * time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func ParseJWT(tokenStr string) (jwt.MapClaims, error) {
    token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
        return jwtSecret, nil
    })
    if err != nil || !token.Valid {
        return nil, errors.New("invalid token")
    }
    return token.Claims.(jwt.MapClaims), nil
}