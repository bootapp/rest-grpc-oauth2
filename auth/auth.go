package auth

import (
	"context"
	"github.com/bootapp/oauth2"
	"github.com/bootapp/oauth2/errors"
	"github.com/bootapp/oauth2/generates"
	restg "github.com/bootapp/rest-grpc-oauth2"
	"github.com/dgrijalva/jwt-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"log"
	"strconv"
	"time"
)

func ResponseTokenInjector(ctx context.Context, accessToken string, refreshToken string) {
	trailer := metadata.Pairs (
		restg.AccessTokenMdKey, accessToken,
		restg.RefreshTokenMdKey, refreshToken,
	)
	_ = grpc.SetTrailer(ctx, trailer)
}

type StatelessAuthenticator struct {
	decoder *generates.JWTAccessGenerate

}
var instance = &StatelessAuthenticator{}

func GetInstance() *StatelessAuthenticator {
	return instance
}
func (a *StatelessAuthenticator) UpdateKey(keyPem []byte, method jwt.SigningMethod) {
	if a.decoder == nil {
		a.decoder = generates.NewJWTAccessDecoder(keyPem, method)
	} else {
		_= a.decoder.UpdatePublicKey(keyPem, method)
	}
}
func (s *StatelessAuthenticator) decode(token string) (oauth2.TokenInfo, error) {
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
func (s *StatelessAuthenticator) HasRole(accessToken string, role string) (userId int64, hasRole bool)  {
	ti, err := s.decode(accessToken)
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
	accessToken := restg.FirstIncomingHeaderMdWithName(md, restg.AccessTokenMdKey)
	ti, err := a.decode(accessToken)
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
