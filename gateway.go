package rest_grpc_oauth2

import (
	"context"
	"github.com/golang/protobuf/proto"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"google.golang.org/grpc/metadata"
	"net/http"
	"strings"
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
func GatewayRequestCookieParser(_ context.Context, req *http.Request) metadata.MD {
	var resMD metadata.MD
	accessCookie, err := req.Cookie(AccessTokenCookieKey)
	if err == nil && accessCookie != nil {
		resMD = metadata.Pairs(AccessTokenMdKey, accessCookie.Value)
	} else {
		accessToken := req.Header.Get(BearerAuthorizationTokenKey)
		if accessToken != "" {
			resMD = metadata.Pairs(AccessTokenMdKey, strings.TrimPrefix(accessToken, "Bearer "))
		}
	}
	refreshCookie, err := req.Cookie(RefreshTokenCookieKey)
	if err == nil && refreshCookie != nil{
		if resMD == nil {
			resMD = metadata.Pairs(RefreshTokenMdKey, refreshCookie.Value)
		} else {
			resMD.Append(RefreshTokenMdKey, refreshCookie.Value)
		}
	}
	return resMD
}