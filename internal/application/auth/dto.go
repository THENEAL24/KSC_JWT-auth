package auth

type RegisterRequest struct {
	Email    string
	Password string
}

type LoginRequest struct {
	Email    string
	Password string
}

type AuthResponse struct {
	AccessToken  string
	RefreshToken string
}

type UserResponse struct {
	ID    int32
	Email string
}

type AssignRoleRequest struct {
	UserID int32
	RoleID int32
}

type RefreshRequest struct {
	RefreshToken string
}

type LogoutRequest struct {
	RefreshToken string
}

type OAuthCallbackRequest struct {
	State string
	Code  string
}

type OAuthUserInfo struct {
	Email string
}
