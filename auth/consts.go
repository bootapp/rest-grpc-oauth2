package auth

import "time"

const (
	AccessTokenMdKey = "x-cookie-access"
	RefreshTokenMdKey = "x-cookie-refresh"
	ClearTokenMdKey = "clear-token"
	RemoteAddrMdKey = "remote-addr"
	AccessTokenCookieKey = "access_token"
	RefreshTokenCookieKey = "refresh_token"
	TokenRefreshed = "token-refreshed"
	BearerAuthorizationTokenKey = "Authorization"
	RefreshWindow = time.Second * 30
)