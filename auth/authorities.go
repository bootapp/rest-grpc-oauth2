package auth

type OrgAuthority struct {
	name string
	orgAuthKey string
	orgAuthValue int64
}
type UserAuthority struct {
	name string
	orgAuthKey string
	orgAuthValue int64
	userAuthKey string
	userAuthValue int64
}
var strToOrgAuthority = map[string] OrgAuthority{}
var strToUserAuthority = map[string] UserAuthority{}