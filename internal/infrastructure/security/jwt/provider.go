package jwt

import (
	"errors"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	UserID int32    `json:"user_id"`
	Roles  []string `json:"roles"`
	jwt.RegisteredClaims
}

type Config struct {
	Secret          string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
}

type Provider struct {
	secret          []byte
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
}

func NewProvider(cfg Config) (*Provider, error) {
	if len(cfg.Secret) < 32 {
		return nil, errors.New("JWT secret must be at least 32 characters")
	}

	return &Provider{
		secret:          []byte(cfg.Secret),
		accessTokenTTL:  cfg.AccessTokenTTL,
		refreshTokenTTL: cfg.RefreshTokenTTL,
	}, nil
}

func (p *Provider) GenerateAccessToken(userID int32, roles []string) (string, error) {
	return p.generateToken(userID, roles, p.accessTokenTTL)
}

func (p *Provider) GenerateRefreshToken(userID int32, roles []string) (string, error) {
	return p.generateToken(userID, roles, p.refreshTokenTTL)
}

func (p *Provider) generateToken(userID int32, roles []string, ttl time.Duration) (string, error) {
	now := time.Now()

	claims := Claims{
		UserID: userID,
		Roles:  roles,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(p.secret)
}

func (p *Provider) RefreshTokenTTL() time.Duration {
	return p.refreshTokenTTL
}

func (p *Provider) ParseToken(tokenStr string) (*Claims, error) {
	if strings.HasPrefix(strings.ToLower(tokenStr), "bearer ") {
		tokenStr = strings.TrimSpace(tokenStr[7:])
	}

	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, errors.New("unexpected signing method")
		}
		return p.secret, nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}

	return claims, nil
}
