package auth

type AuthorityGroup struct {
	Id int64
	Pid int64
	Value int64
	Name string
}
type Authority struct {
	GroupId int64
	Key string
	Value int64
	Name string
}
var strToAuthority = map[string] Authority{}
var authGroupMap = map[int64] AuthorityGroup{}