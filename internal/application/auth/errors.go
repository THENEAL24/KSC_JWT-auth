package auth

import "errors"

var (
	ErrInvalidEmail       = errors.New("invalid email")
	ErrPasswordTooShort   = errors.New("password too short (min 6 chars)")
	ErrUserAlreadyExists  = errors.New("user already exists")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidToken       = errors.New("invalid token")
	ErrTokenExpired       = errors.New("token expired")
	ErrMissingToken       = errors.New("missing token")
	ErrInvalidClaims      = errors.New("invalid token claims")
	ErrForbidden          = errors.New("forbidden")
)

var (
	ErrInvalidOAuthState    = errors.New("invalid oauth state")
	ErrOAuthExchangeFailed  = errors.New("oauth exchange failed")
	ErrFailedToFetchProfile = errors.New("failed to fetch profile")
)
