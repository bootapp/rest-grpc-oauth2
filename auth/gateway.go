package auth

import (
	"context"
	"github.com/golang/protobuf/proto"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"log"
	"net/http"
	"time"
)
func FirstTrailerMdWithName(md runtime.ServerMetadata, name string) string {
	values := md.TrailerMD.Get(name)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
func FirstIncomingHeaderMdWithName(md metadata.MD, name string) string {
	values := md.Get(name)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func GatewayResponseCookieAnnotator(ctx context.Context, response http.ResponseWriter, _ proto.Message) error {
	md, ok := runtime.ServerMetadataFromContext(ctx)
	if ok {
		accessToken, refreshToken := FirstTrailerMdWithName(md, AccessTokenMdKey), FirstTrailerMdWithName(md, RefreshTokenMdKey)
		var cookie http.Cookie
		if accessToken != "" {
			cookie = http.Cookie{
				Name: AccessTokenCookieKey, Value:accessToken, HttpOnly: true, Path: "/", MaxAge: 86400, Expires: time.Now().Add(24 * time.Hour),
			}
			http.SetCookie(response, &cookie)
		}
		if refreshToken != "" {
			cookie = http.Cookie{
				Name: RefreshTokenCookieKey, Value:refreshToken, HttpOnly: true, Path: "/", MaxAge: 86400, Expires: time.Now().Add(7 * 24 * time.Hour),
			}
			http.SetCookie(response, &cookie)
		}
	}
	return nil
}
func GatewayRequestCookieParser(_ context.Context, req *http.Request) (resMD metadata.MD) {
	var accessToken, refreshToken string
	accessCookie, err := req.Cookie(AccessTokenCookieKey)
	if err ==nil && accessCookie != nil {
		accessToken = accessCookie.Value
	} else {
		accessToken = req.Header.Get(BearerAuthorizationTokenKey)
	}
	refreshCookie, err := req.Cookie(RefreshTokenCookieKey)
	if err == nil && refreshCookie != nil {
		refreshToken = refreshCookie.Value
	}

	if refreshToken != "" {
		authenticator := GetInstance()
		if authenticator != nil {
			var refreshed bool
			accessToken, refreshToken, refreshed = authenticator.RefreshTokenIfNeeded(accessToken, refreshToken)
			if refreshed {
				resMD = metadata.Pairs(TokenRefreshed, "1")
			}
		} else {
			log.Fatal("no oauth authenticator configured")
		}
	}

	if accessToken != "" {
		if resMD == nil {
			resMD = metadata.Pairs(AccessTokenMdKey, accessToken)
		} else {
			resMD.Append(AccessTokenMdKey, accessToken)
		}
		if refreshToken != "" {
			resMD.Append(RefreshTokenMdKey, refreshToken)
		}
	}
	return resMD
}

func TokenPassingInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		keys := md.Get(AccessTokenMdKey)
		if len(keys) > 0 {
			metadata.Pairs(AccessTokenMdKey, keys[0])
			ctx = metadata.NewOutgoingContext(ctx, md)
		}
	}
	return handler(ctx, req)
}