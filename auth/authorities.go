package auth
//type OrgAuthority uint64
//type UserAuthority uint64
//type OrgUserAuthority [2]uint64

type OrgAuthority struct {
	value int64
	indexKey string
	name string
}
type UserAuthority struct {
	orgAuthorityValue int64
	value int64
	indexKey string
	orgAuthorityKey string
	name string
}
var strToOrgAuthority = map[string] OrgAuthority{}
var strToUserAuthority = map[string] UserAuthority{}