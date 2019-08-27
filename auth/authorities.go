package auth

type AuthorityGroup struct {
	name string
	groupAuthKey string
	groupAuthValue int64
}
type Authority struct {
	name string
	groupAuthKey string
	groupAuthValue int64
	authKey string
	authValue int64
}
var strToAuthorityGroup = map[string] AuthorityGroup{}
var strToAuthority = map[string] Authority{}