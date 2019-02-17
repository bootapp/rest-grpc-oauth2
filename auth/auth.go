package auth

import (
	"context"
	"github.com/bootapp/oauth2"
	"github.com/bootapp/oauth2/generates"
	"github.com/dgrijalva/jwt-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"gopkg.in/resty.v1"
	"log"
	"time"
)
type TokenResult struct {
	AccessToken string `json:"access_token"`
	ExpiresIn int64	`json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	TokenType string `json:"token_type"`
}
func AuthorityEncode(orgRoles []string, userRoles []string) (orgUserKey map[uint64]uint64) {
	var orgKey uint64 = 0
	for _, orgRole := range orgRoles {
		orgKey |= uint64(strToOrgAuthority[orgRole])
	}
	orgUserKey= make(map[uint64]uint64)
	for _, userRole := range userRoles {
		orgUser := strToOrgUserAuthority[userRole]
		if orgUser[0] & orgKey != 0 {
			orgUserKey[orgUser[0]] |= orgUser[1]
		}
	}
	return orgUserKey
}

func ResponseTokenInjector(ctx context.Context, accessToken string, refreshToken string) {
	var trailer metadata.MD
	if accessToken != "" {
		trailer = metadata.Pairs(AccessTokenMdKey, accessToken)
	}
	if refreshToken != "" {
		if trailer == nil {
			trailer = metadata.Pairs(RefreshTokenMdKey, refreshToken)
		} else {
			trailer.Append(RefreshTokenMdKey, refreshToken)
		}
	}
	_ = grpc.SetTrailer(ctx, trailer)
}

type StatelessAuthenticator struct {
	decoder *generates.JWTAccessGenerate
	oauthEndpoint string
	clientId string
	clientSecret string
}
var instance = &StatelessAuthenticator{}

func GetInstance() *StatelessAuthenticator {
	return instance
}
func (a *StatelessAuthenticator) SetOauthClient(endpoint, clientId, clientSecret string) {
	a.oauthEndpoint = endpoint
	a.clientId = clientId
	a.clientSecret = clientSecret
}
func (a *StatelessAuthenticator) UpdateKey(keyPem []byte, method jwt.SigningMethod) {
	if a.decoder == nil {
		a.decoder = generates.NewJWTAccessDecoder(keyPem, method)
	} else {
		_= a.decoder.UpdatePublicKey(keyPem, method)
	}
}
func (s *StatelessAuthenticator) GetTokenInfo(token string) (oauth2.TokenInfo, error) {
	if s.decoder == nil {
		log.Fatalf("authenticator error, no decoder registered!")
		return nil, status.Error(codes.Internal, "no decoder registered")
	}
	ti, err := s.decoder.ExtractInfo(token)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid access token")
	}
	return ti, nil
}
func (s *StatelessAuthenticator) RefreshTokenIfNeeded(accessToken string, refreshToken string) (string, string, bool) {
	if refreshToken == "" {
		return accessToken, refreshToken, false
	}
	accessTI, err := s.GetTokenInfo(accessToken)
	// no need to refresh
	if err == nil && time.Now().Add(RefreshWindow).Before(accessTI.GetExpiresAt()){
		return accessToken, refreshToken, false
	}
	// need refresh
	refreshTI, err := s.GetTokenInfo(refreshToken)
	if err == nil && time.Now().Before(refreshTI.GetExpiresAt()) {
		newAccessToken, newRefreshToken, err := s.UserRefreshToken(refreshToken)
		if err == nil {
			return newAccessToken, newRefreshToken, true
		}
	}
	return accessToken, refreshToken, false

}
func (s *StatelessAuthenticator) HasRole(ctx context.Context, role string) (userId int64, orgId int64, hasRole bool)  {
	userId, orgId, hasRole = 0, 0, false
	accessToken, isAuth := s.IsAuthenticated(ctx)
	if !isAuth {
		return
	}
	ti, err := s.GetTokenInfo(accessToken)
	if err != nil {
		return
	}
	if ti.GetExpiresAt().Before(time.Now()) {
		return
	}
	authorities := ti.GetAuthorities()
	userId = ti.GetUserID()
	orgId = ti.GetOrgID()
	if err != nil {
		return
	}
	targetRole := strToOrgUserAuthority[role]
	if authorities[targetRole[0]] & targetRole[1] != 0 {
		hasRole = true
	}
	return
}
func (s *StatelessAuthenticator) IsAuthenticated(ctx context.Context) (accessToken string, isAuth bool) {
	accessToken, isAuth = "", false
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return
	}
	accessToken = FirstIncomingHeaderMdWithName(md, AccessTokenMdKey)
	ti, err := s.GetTokenInfo(accessToken)
	if err != nil {
		return
	}
	if ti.GetExpiresAt().Before(time.Now()) {
		return
	}
	isAuth = true
	refreshed := FirstIncomingHeaderMdWithName(md, TokenRefreshed)
	if refreshed != "" {
		refreshToken := FirstIncomingHeaderMdWithName(md, RefreshTokenMdKey)
		ResponseTokenInjector(ctx, accessToken, refreshToken)
	}
	return
}
func (s *StatelessAuthenticator) CheckRole(ctx context.Context, role string) (int64, int64, error) {
	accessToken, isAuth := s.IsAuthenticated(ctx)
	if !isAuth {
		return 0, 0, status.Error(codes.Unauthenticated, "invalid access token")
	}
	ti, err := s.GetTokenInfo(accessToken)
	if err != nil {
		return 0, 0, status.Error(codes.Unauthenticated, "invalid access token")
	}
	if ti.GetExpiresAt().Before(time.Now()) {
		return 0, 0, status.Error(codes.Unauthenticated, "invalid access token")
	}
	authorities := ti.GetAuthorities()
	userId := ti.GetUserID()
	orgId:= ti.GetOrgID()
	targetRole := strToOrgUserAuthority[role]

	if authorities[targetRole[0]] & targetRole[1] != 0 {
		return userId, orgId, nil
	}
	return 0, 0, status.Error(codes.PermissionDenied, "user not authorized")
}
func (s *StatelessAuthenticator) CheckAuthentication(ctx context.Context) error {
	_, isAuth := s.IsAuthenticated(ctx)
	if !isAuth {
		return status.Error(codes.Unauthenticated, "invalid access token")
	}
	return nil
}
func (s *StatelessAuthenticator) UserGetAccessToken(authType string, login string, pass string) (accessToken, refreshToken string, err error) {
	res, err := resty.R().
		SetHeader("Content-Type", "application/json").
		SetQueryParams(map[string]string{"grant_type":"password","client_id":s.clientId,
			"scope":"user_rw","client_secret":s.clientSecret}).
		SetBody(`{"username":"`+login+`","password":"`+pass+`","authType":"`+authType+`"}`).
		SetResult(&TokenResult{}).
		Post(s.oauthEndpoint+"/token")
	if err != nil {
		return
	}
	accessRes := res.Result().(*TokenResult)
	accessToken = accessRes.AccessToken
	refreshToken = accessRes.RefreshToken
	return

}
func (s *StatelessAuthenticator) UserRefreshToken(refreshToken string) (newAccessToken, newRefreshToken string, err error) {
	res, err := resty.R().
		SetHeader("Content-Type", "application/json").
		SetQueryParams(map[string]string{"grant_type":"refresh_token","client_id":s.clientId,
			"scope":"user_rw","client_secret":s.clientSecret}).
		SetBody(`{"refresh_token":"`+refreshToken+`"}`).
		SetResult(&TokenResult{}).
		Post(s.oauthEndpoint+"/token")
	if err != nil {
		return
	}
	accessRes := res.Result().(*TokenResult)
	newAccessToken = accessRes.AccessToken
	newRefreshToken = accessRes.RefreshToken
	return

}