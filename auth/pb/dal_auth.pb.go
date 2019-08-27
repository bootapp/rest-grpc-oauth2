// Code generated by protoc-gen-go. DO NOT EDIT.
// source: dal_auth.proto

package core

import (
	context "context"
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	grpc "google.golang.org/grpc"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type Authorities struct {
	AuthorityGroups      []*AuthorityGroup `protobuf:"bytes,1,rep,name=authority_groups,json=authorityGroups,proto3" json:"authority_groups,omitempty"`
	Authorities          []*Authority      `protobuf:"bytes,2,rep,name=authorities,proto3" json:"authorities,omitempty"`
	XXX_NoUnkeyedLiteral struct{}          `json:"-"`
	XXX_unrecognized     []byte            `json:"-"`
	XXX_sizecache        int32             `json:"-"`
}

func (m *Authorities) Reset()         { *m = Authorities{} }
func (m *Authorities) String() string { return proto.CompactTextString(m) }
func (*Authorities) ProtoMessage()    {}
func (*Authorities) Descriptor() ([]byte, []int) {
	return fileDescriptor_c1be496d0d735f64, []int{0}
}

func (m *Authorities) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Authorities.Unmarshal(m, b)
}
func (m *Authorities) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Authorities.Marshal(b, m, deterministic)
}
func (m *Authorities) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Authorities.Merge(m, src)
}
func (m *Authorities) XXX_Size() int {
	return xxx_messageInfo_Authorities.Size(m)
}
func (m *Authorities) XXX_DiscardUnknown() {
	xxx_messageInfo_Authorities.DiscardUnknown(m)
}

var xxx_messageInfo_Authorities proto.InternalMessageInfo

func (m *Authorities) GetAuthorityGroups() []*AuthorityGroup {
	if m != nil {
		return m.AuthorityGroups
	}
	return nil
}

func (m *Authorities) GetAuthorities() []*Authority {
	if m != nil {
		return m.Authorities
	}
	return nil
}

type Authority struct {
	GroupAuthKey         string   `protobuf:"bytes,1,opt,name=group_auth_key,json=groupAuthKey,proto3" json:"group_auth_key,omitempty"`
	AuthKey              string   `protobuf:"bytes,2,opt,name=auth_key,json=authKey,proto3" json:"auth_key,omitempty"`
	AuthValue            int64    `protobuf:"varint,3,opt,name=auth_value,json=authValue,proto3" json:"auth_value,omitempty"`
	Name                 string   `protobuf:"bytes,4,opt,name=name,proto3" json:"name,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Authority) Reset()         { *m = Authority{} }
func (m *Authority) String() string { return proto.CompactTextString(m) }
func (*Authority) ProtoMessage()    {}
func (*Authority) Descriptor() ([]byte, []int) {
	return fileDescriptor_c1be496d0d735f64, []int{1}
}

func (m *Authority) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Authority.Unmarshal(m, b)
}
func (m *Authority) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Authority.Marshal(b, m, deterministic)
}
func (m *Authority) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Authority.Merge(m, src)
}
func (m *Authority) XXX_Size() int {
	return xxx_messageInfo_Authority.Size(m)
}
func (m *Authority) XXX_DiscardUnknown() {
	xxx_messageInfo_Authority.DiscardUnknown(m)
}

var xxx_messageInfo_Authority proto.InternalMessageInfo

func (m *Authority) GetGroupAuthKey() string {
	if m != nil {
		return m.GroupAuthKey
	}
	return ""
}

func (m *Authority) GetAuthKey() string {
	if m != nil {
		return m.AuthKey
	}
	return ""
}

func (m *Authority) GetAuthValue() int64 {
	if m != nil {
		return m.AuthValue
	}
	return 0
}

func (m *Authority) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

type AuthorityGroup struct {
	GroupAuthKey         string   `protobuf:"bytes,1,opt,name=group_auth_key,json=groupAuthKey,proto3" json:"group_auth_key,omitempty"`
	GroupAuthValue       int64    `protobuf:"varint,2,opt,name=group_auth_value,json=groupAuthValue,proto3" json:"group_auth_value,omitempty"`
	Name                 string   `protobuf:"bytes,3,opt,name=name,proto3" json:"name,omitempty"`
	ModuleId             int64    `protobuf:"varint,4,opt,name=module_id,json=moduleId,proto3" json:"module_id,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *AuthorityGroup) Reset()         { *m = AuthorityGroup{} }
func (m *AuthorityGroup) String() string { return proto.CompactTextString(m) }
func (*AuthorityGroup) ProtoMessage()    {}
func (*AuthorityGroup) Descriptor() ([]byte, []int) {
	return fileDescriptor_c1be496d0d735f64, []int{2}
}

func (m *AuthorityGroup) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_AuthorityGroup.Unmarshal(m, b)
}
func (m *AuthorityGroup) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_AuthorityGroup.Marshal(b, m, deterministic)
}
func (m *AuthorityGroup) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AuthorityGroup.Merge(m, src)
}
func (m *AuthorityGroup) XXX_Size() int {
	return xxx_messageInfo_AuthorityGroup.Size(m)
}
func (m *AuthorityGroup) XXX_DiscardUnknown() {
	xxx_messageInfo_AuthorityGroup.DiscardUnknown(m)
}

var xxx_messageInfo_AuthorityGroup proto.InternalMessageInfo

func (m *AuthorityGroup) GetGroupAuthKey() string {
	if m != nil {
		return m.GroupAuthKey
	}
	return ""
}

func (m *AuthorityGroup) GetGroupAuthValue() int64 {
	if m != nil {
		return m.GroupAuthValue
	}
	return 0
}

func (m *AuthorityGroup) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *AuthorityGroup) GetModuleId() int64 {
	if m != nil {
		return m.ModuleId
	}
	return 0
}

type AuthEmpty struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *AuthEmpty) Reset()         { *m = AuthEmpty{} }
func (m *AuthEmpty) String() string { return proto.CompactTextString(m) }
func (*AuthEmpty) ProtoMessage()    {}
func (*AuthEmpty) Descriptor() ([]byte, []int) {
	return fileDescriptor_c1be496d0d735f64, []int{3}
}

func (m *AuthEmpty) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_AuthEmpty.Unmarshal(m, b)
}
func (m *AuthEmpty) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_AuthEmpty.Marshal(b, m, deterministic)
}
func (m *AuthEmpty) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AuthEmpty.Merge(m, src)
}
func (m *AuthEmpty) XXX_Size() int {
	return xxx_messageInfo_AuthEmpty.Size(m)
}
func (m *AuthEmpty) XXX_DiscardUnknown() {
	xxx_messageInfo_AuthEmpty.DiscardUnknown(m)
}

var xxx_messageInfo_AuthEmpty proto.InternalMessageInfo

func init() {
	proto.RegisterType((*Authorities)(nil), "core.Authorities")
	proto.RegisterType((*Authority)(nil), "core.Authority")
	proto.RegisterType((*AuthorityGroup)(nil), "core.AuthorityGroup")
	proto.RegisterType((*AuthEmpty)(nil), "core.AuthEmpty")
}

func init() { proto.RegisterFile("dal_auth.proto", fileDescriptor_c1be496d0d735f64) }

var fileDescriptor_c1be496d0d735f64 = []byte{
	// 313 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0x52, 0xcf, 0x4b, 0xc3, 0x30,
	0x14, 0x36, 0xeb, 0xd0, 0xf5, 0x55, 0xba, 0x19, 0x14, 0xab, 0x22, 0x8c, 0xe2, 0xa1, 0xa7, 0x82,
	0xf3, 0xe0, 0x51, 0x14, 0x45, 0x86, 0xb7, 0x08, 0x5e, 0x4b, 0xd6, 0x86, 0xad, 0xd8, 0x9a, 0x90,
	0xa5, 0x83, 0x9e, 0xc4, 0x3f, 0xc1, 0xff, 0x58, 0xf2, 0x3a, 0xbb, 0xd6, 0x93, 0xb7, 0xbe, 0xef,
	0x47, 0xbf, 0x97, 0x2f, 0x01, 0x3f, 0xe3, 0x45, 0xc2, 0x2b, 0xb3, 0x8a, 0x95, 0x96, 0x46, 0xd2,
	0x61, 0x2a, 0xb5, 0x08, 0xbf, 0x08, 0x78, 0xf7, 0x95, 0x59, 0x49, 0x9d, 0x9b, 0x5c, 0xac, 0xe9,
	0x1d, 0x4c, 0xf8, 0x76, 0xac, 0x93, 0xa5, 0x96, 0x95, 0x5a, 0x07, 0x64, 0xea, 0x44, 0xde, 0xec,
	0x38, 0xb6, 0x86, 0xf8, 0x57, 0x5c, 0x3f, 0x5b, 0x92, 0x8d, 0x79, 0x6f, 0x5e, 0xd3, 0x6b, 0xf0,
	0xf8, 0xee, 0x7f, 0xc1, 0x00, 0xbd, 0xe3, 0x3f, 0x5e, 0xd6, 0xd5, 0x84, 0x9f, 0xe0, 0xb6, 0x0c,
	0xbd, 0x02, 0x1f, 0x63, 0x71, 0xd5, 0xe4, 0x5d, 0xd4, 0x01, 0x99, 0x92, 0xc8, 0x65, 0x87, 0x88,
	0x5a, 0xdd, 0x8b, 0xa8, 0xe9, 0x19, 0x8c, 0x5a, 0x7e, 0x80, 0xfc, 0x01, 0xdf, 0x52, 0x97, 0x00,
	0x48, 0x6d, 0x78, 0x51, 0x89, 0xc0, 0x99, 0x92, 0xc8, 0x61, 0xae, 0x45, 0xde, 0x2c, 0x40, 0x29,
	0x0c, 0x3f, 0x78, 0x29, 0x82, 0x21, 0xba, 0xf0, 0x3b, 0xfc, 0x26, 0xe0, 0xf7, 0xcf, 0xf5, 0xcf,
	0x35, 0x22, 0x98, 0x74, 0x54, 0x4d, 0xe2, 0x00, 0x13, 0xfd, 0x56, 0xd7, 0x8f, 0x75, 0x76, 0xb1,
	0xf4, 0x02, 0xdc, 0x52, 0x66, 0x55, 0x21, 0x92, 0x3c, 0xc3, 0x7d, 0x1c, 0x36, 0x6a, 0x80, 0x79,
	0x16, 0x7a, 0x4d, 0x29, 0x4f, 0xa5, 0x32, 0xf5, 0x6c, 0x0e, 0xfe, 0x23, 0x2f, 0xec, 0xfc, 0x2a,
	0xf4, 0x26, 0x4f, 0x05, 0xbd, 0x85, 0x31, 0x13, 0x3c, 0xeb, 0x5e, 0x5d, 0xa7, 0x64, 0x74, 0x9d,
	0x1f, 0xf5, 0x5b, 0xb7, 0x55, 0xef, 0x3d, 0x9c, 0xc2, 0x49, 0x2a, 0xcb, 0x78, 0x21, 0xa5, 0xe1,
	0x4a, 0x35, 0x8a, 0xa5, 0x56, 0xe9, 0x62, 0x1f, 0x9f, 0xc5, 0xcd, 0x4f, 0x00, 0x00, 0x00, 0xff,
	0xff, 0x03, 0x72, 0xaf, 0xc9, 0x28, 0x02, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// DalAuthServiceClient is the client API for DalAuthService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type DalAuthServiceClient interface {
	ReadAuthorities(ctx context.Context, in *AuthEmpty, opts ...grpc.CallOption) (*Authorities, error)
}

type dalAuthServiceClient struct {
	cc *grpc.ClientConn
}

func NewDalAuthServiceClient(cc *grpc.ClientConn) DalAuthServiceClient {
	return &dalAuthServiceClient{cc}
}

func (c *dalAuthServiceClient) ReadAuthorities(ctx context.Context, in *AuthEmpty, opts ...grpc.CallOption) (*Authorities, error) {
	out := new(Authorities)
	err := c.cc.Invoke(ctx, "/core.DalAuthService/ReadAuthorities", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// DalAuthServiceServer is the server API for DalAuthService service.
type DalAuthServiceServer interface {
	ReadAuthorities(context.Context, *AuthEmpty) (*Authorities, error)
}

func RegisterDalAuthServiceServer(s *grpc.Server, srv DalAuthServiceServer) {
	s.RegisterService(&_DalAuthService_serviceDesc, srv)
}

func _DalAuthService_ReadAuthorities_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AuthEmpty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(DalAuthServiceServer).ReadAuthorities(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/core.DalAuthService/ReadAuthorities",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(DalAuthServiceServer).ReadAuthorities(ctx, req.(*AuthEmpty))
	}
	return interceptor(ctx, in, info, handler)
}

var _DalAuthService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "core.DalAuthService",
	HandlerType: (*DalAuthServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "ReadAuthorities",
			Handler:    _DalAuthService_ReadAuthorities_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "dal_auth.proto",
}
