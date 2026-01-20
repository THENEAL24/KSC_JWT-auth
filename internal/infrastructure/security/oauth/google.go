package oauth

import (
	"context"
	"encoding/json"
	"io"
	"os"

	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type GoogleUserInfo struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
}

func NewGoogleOAuthConfig() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		RedirectURL:  os.Getenv("GOOGLE_REDIRECT_URL"),
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}
}

func GenerateStateToken() (string, error) {
	return uuid.New().String(), nil
}

func GoogleAuthURL(config *oauth2.Config, state string) string {
	return config.AuthCodeURL(state, oauth2.AccessTypeOffline)
}

func ExchangeCodeForToken(ctx context.Context, config *oauth2.Config, code string) (*oauth2.Token, error) {
	return config.Exchange(ctx, code)
}

func FetchGoogleUserInfo(ctx context.Context, token *oauth2.Token) (*GoogleUserInfo, error) {
	client := oauth2.NewClient(ctx, oauth2.StaticTokenSource(token))

	resp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var userInfo GoogleUserInfo
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, err
	}

	return &userInfo, nil
}
