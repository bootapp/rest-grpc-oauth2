package auth

import (
	"context"
	"github.com/bootapp/oauth2"
	"github.com/bootapp/oauth2/errors"
	"github.com/bootapp/oauth2/generates"
	"github.com/dgrijalva/jwt-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"gopkg.in/resty.v1"
	"log"
	"strconv"
	"time"
)
type TokenResult struct {
	AccessToken string `json:"access_token"`
	ExpiresIn int64	`json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	TokenType string `json:"token_type"`
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
		return nil, errors.ErrServerError
	}
	ti, err := s.decoder.ExtractInfo(token)
	if err != nil {
		return nil, errors.ErrInvalidAccessToken
	}
	return ti, nil
}
func (s *StatelessAuthenticator) RefreshTokenIfNeeded(accessToken string, refreshToken string) (string, string) {
	if refreshToken == "" {
		return accessToken, refreshToken
	}
	accessTI, err := s.GetTokenInfo(accessToken)
	// no need to refresh
	if err == nil && time.Now().Add(RefreshWindow).Before(accessTI.GetExpiresAt()){
		return accessToken, refreshToken
	}
	// need refresh
	refreshTI, err := s.GetTokenInfo(refreshToken)
	if err == nil && time.Now().Before(refreshTI.GetExpiresAt()) {
		newAccessToken, newRefreshToken, err := s.UserRefreshToken(refreshTI.GetRefresh())
		if err == nil {
			return newAccessToken, newRefreshToken
		}
	}
	return accessToken, refreshToken

}
func (s *StatelessAuthenticator) HasRole(accessToken string, role string) (userId int64, hasRole bool)  {
	ti, err := s.GetTokenInfo(accessToken)
	if err != nil {
		return 0, false
	}
	if ti.GetExpiresAt().Before(time.Now()) {
		return 0,false
	}
	authorities := ti.GetAuthorities()
	for idx := range authorities {
		if role == authorities[idx] {
			userId, err = strconv.ParseInt(ti.GetUserID(), 10, 64)
			if err != nil {
				return 0, false
			}
			return userId,true
		}
	}
	return 0, false
}
func (a *StatelessAuthenticator) IsAuthenticated(ctx context.Context) (userId int64, isAuth bool) {
	userId,isAuth = 0, false
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return
	}
	accessToken := FirstIncomingHeaderMdWithName(md, AccessTokenMdKey)
	ti, err := a.GetTokenInfo(accessToken)
	if err != nil {
		return
	}
	if ti.GetExpiresAt().Before(time.Now()) {
		return
	}
	userId, err = strconv.ParseInt(ti.GetUserID(), 10, 64)
	if err != nil {
		return
	}
	isAuth = true
	return
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
		SetBody(`{"refresh_token":`+refreshToken+`}`).
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