package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"

	"user-service/internal/auth"
	"user-service/internal/db"

	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"github.com/jackc/pgx/v5/pgtype"
	"errors"
    "github.com/jackc/pgx/v5"
)

type OAuthHandlers struct {
	oauthConfig  *oauth2.Config
	stateStorage *auth.MemoryStateStorage
	queries      *db.Queries
	logger       *zap.Logger
}

func NewOAuthHandlers(
	q *db.Queries,
	stateStorage *auth.MemoryStateStorage,
	logger *zap.Logger,
) *OAuthHandlers {
	return &OAuthHandlers{
		oauthConfig: &oauth2.Config{
			ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
			ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
			RedirectURL:  os.Getenv("GOOGLE_REDIRECT_URI"),
			Scopes: []string{
				"https://www.googleapis.com/auth/userinfo.email",
				"https://www.googleapis.com/auth/userinfo.profile",
			},
			Endpoint: google.Endpoint,
		},
		stateStorage: stateStorage,
		queries:      q,
		logger:       logger,
	}
}

func (h *OAuthHandlers) GoogleLogin(w http.ResponseWriter, r *http.Request) {
	state, err := generateSecureState(32)
	if err != nil {
		h.logger.Error("failed to generate oauth state", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	meta := auth.StateMetadata{
		IP:        r.RemoteAddr,
		UserAgent: r.UserAgent(),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	h.stateStorage.Save(state, meta)

	url := h.oauthConfig.AuthCodeURL(state, oauth2.AccessTypeOffline)
	h.logger.Info("OAuth redirect URL", zap.String("url", url), zap.String("state", state))
	http.Redirect(w, r, url, http.StatusFound)
}

func (h *OAuthHandlers) GoogleCallback(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    state := r.URL.Query().Get("state")
    code := r.URL.Query().Get("code")

    h.logger.Info("callback received", zap.String("state", state), zap.String("code", code))

    if state == "" || code == "" {
        h.logger.Warn("invalid callback: missing state or code")
        writeError(w, http.StatusBadRequest, "invalid oauth callback: missing state or code")
        return
    }

    meta, ok := h.stateStorage.Get(state)
    if !ok {
        h.logger.Warn("invalid oauth state", zap.String("state", state))
        writeError(w, http.StatusUnauthorized, "invalid oauth state")
        return
    }
    h.logger.Info("oauth state validated", zap.Any("meta", meta))
    h.stateStorage.Delete(state)

    token, err := h.oauthConfig.Exchange(ctx, code)
    if err != nil {
        h.logger.Error("oauth exchange failed", zap.Error(err))
        writeError(w, http.StatusUnauthorized, "oauth exchange failed")
        return
    }
    h.logger.Info("oauth token received", zap.Any("token", token))

    email, err := fetchGoogleEmail(ctx, token)
    if err != nil {
        h.logger.Error("failed to fetch profile", zap.Error(err))
        writeError(w, http.StatusUnauthorized, "failed to fetch profile")
        return
    }
    email = strings.ToLower(strings.TrimSpace(email))
    h.logger.Info("google email fetched", zap.String("email", email))

    var userID int32
    var userEmail string

    userByEmail, err := h.queries.GetUserByEmail(ctx, email)
    if err != nil {
        if errors.Is(err, pgx.ErrNoRows) {
            h.logger.Info("user not found, creating new OAuth user", zap.String("email", email))
            
            createdUser, err := h.queries.CreateUser(ctx, db.CreateUserParams{
                Email: email,
                Password: pgtype.Text{String: "", Valid: true},
            })
            if err != nil {
                h.logger.Error("failed to create OAuth user", zap.Error(err))
                userByEmail, err = h.queries.GetUserByEmail(ctx, email)
                if err != nil {
                    writeError(w, http.StatusInternalServerError, "internal error")
                    return
                }
                userID = userByEmail.ID
                userEmail = userByEmail.Email
            } else {
                userID = createdUser.ID
                userEmail = createdUser.Email
                
                h.logger.Info("new OAuth user created", 
                    zap.Int32("user_id", userID), 
                    zap.String("email", userEmail))
            }
        } else {
            h.logger.Error("failed to get user by email", zap.Error(err))
            writeError(w, http.StatusInternalServerError, "internal error")
            return
        }
    } else {
        userID = userByEmail.ID
        userEmail = userByEmail.Email
        h.logger.Info("existing user found", 
            zap.Int32("user_id", userID), 
            zap.String("email", userEmail))
    }

    fullUserData, err := h.queries.GetUserById(ctx, userID)
    if err != nil {
        h.logger.Warn("failed to get full user data, continuing with basic info", zap.Error(err))
    } else {
        h.logger.Info("full user data loaded", zap.Any("user", fullUserData))
    }

    roles, err := h.queries.GetRolesByUserId(ctx, userID)
    if err != nil {
        h.logger.Error("failed to fetch roles", zap.Error(err))
        roles = []string{"user"}
    }
    if len(roles) == 0 {
        h.logger.Info("no roles found, defaulting to 'user'")
        roles = []string{"user"}
    }
    h.logger.Info("roles assigned", zap.Strings("roles", roles))

    accessToken, err := auth.GenerateJWT(userID, roles)
    if err != nil {
        h.logger.Error("failed to generate access token", zap.Error(err))
        writeError(w, http.StatusInternalServerError, "internal error")
        return
    }

    refreshToken, err := auth.GenerateJWT(userID, roles)
    if err != nil {
        h.logger.Error("failed to generate refresh token", zap.Error(err))
        writeError(w, http.StatusInternalServerError, "internal error")
        return
    }

    h.logger.Info("tokens generated successfully")

    _, err = h.queries.CreateRefreshToken(ctx, db.CreateRefreshTokenParams{
        UserID:    userID,
        Token:     refreshToken,
        ExpiresAt: pgtype.Timestamp{Time: time.Now().Add(30 * 24 * time.Hour), Valid: true},
    })
    if err != nil {
        h.logger.Error("failed to save refresh token", zap.Error(err))
        writeError(w, http.StatusInternalServerError, "internal error")
        return
    }

    h.logger.Info("refresh token saved to DB")

    writeJSON(w, http.StatusOK, map[string]string{
        "access_token":  accessToken,
        "refresh_token": refreshToken,
    })
    h.logger.Info("oauth callback finished successfully")
}

func generateSecureState(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func fetchGoogleEmail(ctx context.Context, token *oauth2.Token) (string, error) {
	client := oauth2.NewClient(ctx, oauth2.StaticTokenSource(token))
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var data struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", err
	}
	return data.Email, nil
}
