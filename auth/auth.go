package auth

import (
	"context"
	"github.com/bootapp/oauth2"
	"github.com/bootapp/oauth2/generates"
	"github.com/bootapp/rest-grpc-oauth2/auth/pb"
	"github.com/dgrijalva/jwt-go"
	"github.com/golang/protobuf/ptypes/empty"
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
func AuthorityEncode(orgAuthorityKeys []string, userAuthorityKeys []string) (authorities map[int64]int64) {
	var orgValue int64 = 0
	for _, orgKey := range orgAuthorityKeys {
		orgValue |= strToOrgAuthority[orgKey].value
	}
	authorities = make(map[int64]int64)
	for _, userKey := range userAuthorityKeys {
		userAuthority := strToUserAuthority[userKey]
		if userAuthority.orgAuthorityValue & orgValue != 0 {
			authorities[userAuthority.orgAuthorityValue] |= userAuthority.value
		}
	}
	return authorities
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
	authorityEndpoint string
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
func (a *StatelessAuthenticator) SetOauthClientId(clientId string) {
	a.clientId = clientId
}
func (a *StatelessAuthenticator) SetOauthClientSecret(clientSecret string) {
	a.clientSecret = clientSecret
}
func (a *StatelessAuthenticator) SetOauthEndpoint(endpoint string) {
	a.oauthEndpoint = endpoint
}
func (a *StatelessAuthenticator) SetAuthorityEndpoint(endpoint string) {
	a.authorityEndpoint = endpoint
}
func (a *StatelessAuthenticator) ScheduledFetchAuthorities(ctx context.Context) error {
	conn, err := grpc.Dial(a.authorityEndpoint, grpc.WithInsecure())
	if err != nil {
		return err
	}
	client := dal_core_user.NewDalCoreAuthorityServiceClient(conn)
	go func() {
		scheduled := time.NewTimer(time.Second)
		for range scheduled.C {
			log.Println("refreshing authorities...")
			authorities, err := client.GetAuthorities(ctx, &empty.Empty{})
			if err != nil {
				log.Fatal(err)
			} else {
				for _, authority:= range authorities.OrgAuthorities {
					strToOrgAuthority[authority.IndexKey] = OrgAuthority{indexKey:authority.IndexKey,
						value:authority.Value, name: authority.Name}
				}
				for _, authority := range authorities.UserAuthorities {
					strToUserAuthority[authority.IndexKey] = UserAuthority{indexKey:authority.IndexKey,
						orgAuthorityKey:authority.OrgAuthorityKey, value: authority.Value,
						orgAuthorityValue:strToOrgAuthority[authority.OrgAuthorityKey].value, name:authority.Name}
				}
			}
			scheduled.Reset(time.Minute * 5)
			log.Println("refreshing authorities...done")
		}
	}()
	return nil
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
func (s *StatelessAuthenticator) HasAuthority(ctx context.Context, authority string) (userId int64, orgId int64, hasAuthority bool)  {
	userId, orgId, hasAuthority = 0, 0, false
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
	target := strToUserAuthority[authority]
	if authorities[target.orgAuthorityValue] & target.value != 0 {
		hasAuthority = true
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
func (s *StatelessAuthenticator) CheckAuthority(ctx context.Context, authority string) (int64, int64, error) {
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
	target := strToUserAuthority[authority]
	if authorities[target.orgAuthorityValue] & target.value != 0 {
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