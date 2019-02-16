package auth

import "time"

const (
	AccessTokenMdKey = "x-cookie-access"
	RefreshTokenMdKey = "x-cookie-refresh"
	AccessTokenCookieKey = "access_token"
	RefreshTokenCookieKey = "refresh_token"
	TokenRefreshed = "token-refreshed"
	BearerAuthorizationTokenKey = "Authorization"
	RefreshWindow = time.Second * 30
)