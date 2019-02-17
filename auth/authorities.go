package auth
type OrgAuthority uint64
type UserAuthority uint64
type OrgUserAuthority [2]uint64

const (
	OrgUser      OrgAuthority = 0x1
	OrgAdmin     OrgAuthority = 0x2
	OrgDebit     OrgAuthority = 0x4
	OrgDebitRisk OrgAuthority = 0x8
	OrgCredit    OrgAuthority = 0x10
)
var strToOrgAuthority = map[string] OrgAuthority {
	"ORG_USER": OrgUser,
	"ORG_ADMIN": OrgAdmin,
	"ORG_DEBIT": OrgDebit,
	"ORG_DEBIT_RISK": OrgDebitRisk,
	"ORG_CREDIT": OrgCredit,
}

const (
	AuthorityUser UserAuthority = 0x1
)
const (
	AuthorityDebitManageRead UserAuthority = 0x1
	AuthorityDebitManageWrite UserAuthority = 0x2
)

var strToOrgUserAuthority = map[string] OrgUserAuthority {
	"AUTH_USER": [2]uint64{uint64(OrgUser), uint64(AuthorityUser)},
	"AUTH_DEBIT_MANAGE_R": [2]uint64{uint64(OrgDebit), uint64(AuthorityDebitManageRead)},
	"AUTH_DEBIT_MANAGE_W": [2]uint64{uint64(OrgDebit), uint64(AuthorityDebitManageWrite)},
}