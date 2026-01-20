package handlers

import (
	"net/http"
	"user-service/internal/application/auth"

	"go.uber.org/zap"
)

type OAuthHandlers struct {
	oauthService *auth.OAuthService
	logger       *zap.Logger
}

func NewOAuthHandlers(oauthService *auth.OAuthService, logger *zap.Logger) *OAuthHandlers {
	return &OAuthHandlers{
		oauthService: oauthService,
		logger:       logger,
	}
}

func (h *OAuthHandlers) GoogleLogin(w http.ResponseWriter, r *http.Request) {
	url, err := h.oauthService.AuthURL(r.RemoteAddr, r.UserAgent())
	if err != nil {
		h.logger.Error("failed to generate oauth URL", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	h.logger.Info("OAuth redirect URL generated")
	http.Redirect(w, r, url, http.StatusFound)
}

func (h *OAuthHandlers) GoogleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")

	h.logger.Info("callback received", zap.String("state", state), zap.String("code", code))

	resp, err := h.oauthService.HandleCallback(ctx, auth.OAuthCallbackRequest{
		State: state,
		Code:  code,
	})
	if err != nil {
		handleServiceError(w, err, h.logger)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"access_token":  resp.AccessToken,
		"refresh_token": resp.RefreshToken,
	})
	h.logger.Info("oauth callback finished successfully")
}
