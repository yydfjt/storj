// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: metainfo.proto

package pb

import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"
import timestamp "github.com/golang/protobuf/ptypes/timestamp"

import (
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion2 // please upgrade the proto package

type BucketInfo struct {
	Name                 string               `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Created              *timestamp.Timestamp `protobuf:"bytes,2,opt,name=created,proto3" json:"created,omitempty"`
	PathCipher           int32                `protobuf:"varint,3,opt,name=path_cipher,json=pathCipher,proto3" json:"path_cipher,omitempty"`
	XXX_NoUnkeyedLiteral struct{}             `json:"-"`
	XXX_unrecognized     []byte               `json:"-"`
	XXX_sizecache        int32                `json:"-"`
}

func (m *BucketInfo) Reset()         { *m = BucketInfo{} }
func (m *BucketInfo) String() string { return proto.CompactTextString(m) }
func (*BucketInfo) ProtoMessage()    {}
func (*BucketInfo) Descriptor() ([]byte, []int) {
	return fileDescriptor_metainfo_fe01dfb05652234b, []int{0}
}
func (m *BucketInfo) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_BucketInfo.Unmarshal(m, b)
}
func (m *BucketInfo) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_BucketInfo.Marshal(b, m, deterministic)
}
func (dst *BucketInfo) XXX_Merge(src proto.Message) {
	xxx_messageInfo_BucketInfo.Merge(dst, src)
}
func (m *BucketInfo) XXX_Size() int {
	return xxx_messageInfo_BucketInfo.Size(m)
}
func (m *BucketInfo) XXX_DiscardUnknown() {
	xxx_messageInfo_BucketInfo.DiscardUnknown(m)
}

var xxx_messageInfo_BucketInfo proto.InternalMessageInfo

func (m *BucketInfo) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *BucketInfo) GetCreated() *timestamp.Timestamp {
	if m != nil {
		return m.Created
	}
	return nil
}

func (m *BucketInfo) GetPathCipher() int32 {
	if m != nil {
		return m.PathCipher
	}
	return 0
}

// CreateBucketMetainfoRequest is a request message for the CreateBucket rpc call
type CreateBucketMetainfoRequest struct {
	Bucket               string   `protobuf:"bytes,1,opt,name=bucket,proto3" json:"bucket,omitempty"`
	PathCipher           int32    `protobuf:"varint,2,opt,name=path_cipher,json=pathCipher,proto3" json:"path_cipher,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *CreateBucketMetainfoRequest) Reset()         { *m = CreateBucketMetainfoRequest{} }
func (m *CreateBucketMetainfoRequest) String() string { return proto.CompactTextString(m) }
func (*CreateBucketMetainfoRequest) ProtoMessage()    {}
func (*CreateBucketMetainfoRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_metainfo_fe01dfb05652234b, []int{1}
}
func (m *CreateBucketMetainfoRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_CreateBucketMetainfoRequest.Unmarshal(m, b)
}
func (m *CreateBucketMetainfoRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_CreateBucketMetainfoRequest.Marshal(b, m, deterministic)
}
func (dst *CreateBucketMetainfoRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CreateBucketMetainfoRequest.Merge(dst, src)
}
func (m *CreateBucketMetainfoRequest) XXX_Size() int {
	return xxx_messageInfo_CreateBucketMetainfoRequest.Size(m)
}
func (m *CreateBucketMetainfoRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_CreateBucketMetainfoRequest.DiscardUnknown(m)
}

var xxx_messageInfo_CreateBucketMetainfoRequest proto.InternalMessageInfo

func (m *CreateBucketMetainfoRequest) GetBucket() string {
	if m != nil {
		return m.Bucket
	}
	return ""
}

func (m *CreateBucketMetainfoRequest) GetPathCipher() int32 {
	if m != nil {
		return m.PathCipher
	}
	return 0
}

// CreateBucketMetainfoResponse is a response message for the CreateBucket rpc call
type CreateBucketMetainfoResponse struct {
	Info                 *BucketInfo `protobuf:"bytes,1,opt,name=info,proto3" json:"info,omitempty"`
	XXX_NoUnkeyedLiteral struct{}    `json:"-"`
	XXX_unrecognized     []byte      `json:"-"`
	XXX_sizecache        int32       `json:"-"`
}

func (m *CreateBucketMetainfoResponse) Reset()         { *m = CreateBucketMetainfoResponse{} }
func (m *CreateBucketMetainfoResponse) String() string { return proto.CompactTextString(m) }
func (*CreateBucketMetainfoResponse) ProtoMessage()    {}
func (*CreateBucketMetainfoResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_metainfo_fe01dfb05652234b, []int{2}
}
func (m *CreateBucketMetainfoResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_CreateBucketMetainfoResponse.Unmarshal(m, b)
}
func (m *CreateBucketMetainfoResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_CreateBucketMetainfoResponse.Marshal(b, m, deterministic)
}
func (dst *CreateBucketMetainfoResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CreateBucketMetainfoResponse.Merge(dst, src)
}
func (m *CreateBucketMetainfoResponse) XXX_Size() int {
	return xxx_messageInfo_CreateBucketMetainfoResponse.Size(m)
}
func (m *CreateBucketMetainfoResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_CreateBucketMetainfoResponse.DiscardUnknown(m)
}

var xxx_messageInfo_CreateBucketMetainfoResponse proto.InternalMessageInfo

func (m *CreateBucketMetainfoResponse) GetInfo() *BucketInfo {
	if m != nil {
		return m.Info
	}
	return nil
}

// GetBucketMetainfoRequest is a request message for the GetBucket rpc call
type GetBucketMetainfoRequest struct {
	Bucket               string   `protobuf:"bytes,1,opt,name=bucket,proto3" json:"bucket,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *GetBucketMetainfoRequest) Reset()         { *m = GetBucketMetainfoRequest{} }
func (m *GetBucketMetainfoRequest) String() string { return proto.CompactTextString(m) }
func (*GetBucketMetainfoRequest) ProtoMessage()    {}
func (*GetBucketMetainfoRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_metainfo_fe01dfb05652234b, []int{3}
}
func (m *GetBucketMetainfoRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_GetBucketMetainfoRequest.Unmarshal(m, b)
}
func (m *GetBucketMetainfoRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_GetBucketMetainfoRequest.Marshal(b, m, deterministic)
}
func (dst *GetBucketMetainfoRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GetBucketMetainfoRequest.Merge(dst, src)
}
func (m *GetBucketMetainfoRequest) XXX_Size() int {
	return xxx_messageInfo_GetBucketMetainfoRequest.Size(m)
}
func (m *GetBucketMetainfoRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_GetBucketMetainfoRequest.DiscardUnknown(m)
}

var xxx_messageInfo_GetBucketMetainfoRequest proto.InternalMessageInfo

func (m *GetBucketMetainfoRequest) GetBucket() string {
	if m != nil {
		return m.Bucket
	}
	return ""
}

// GetBucketMetainfoResponse is a response message for the GetBucket rpc call
type GetBucketMetainfoResponse struct {
	Info                 *BucketInfo `protobuf:"bytes,1,opt,name=info,proto3" json:"info,omitempty"`
	XXX_NoUnkeyedLiteral struct{}    `json:"-"`
	XXX_unrecognized     []byte      `json:"-"`
	XXX_sizecache        int32       `json:"-"`
}

func (m *GetBucketMetainfoResponse) Reset()         { *m = GetBucketMetainfoResponse{} }
func (m *GetBucketMetainfoResponse) String() string { return proto.CompactTextString(m) }
func (*GetBucketMetainfoResponse) ProtoMessage()    {}
func (*GetBucketMetainfoResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_metainfo_fe01dfb05652234b, []int{4}
}
func (m *GetBucketMetainfoResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_GetBucketMetainfoResponse.Unmarshal(m, b)
}
func (m *GetBucketMetainfoResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_GetBucketMetainfoResponse.Marshal(b, m, deterministic)
}
func (dst *GetBucketMetainfoResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GetBucketMetainfoResponse.Merge(dst, src)
}
func (m *GetBucketMetainfoResponse) XXX_Size() int {
	return xxx_messageInfo_GetBucketMetainfoResponse.Size(m)
}
func (m *GetBucketMetainfoResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_GetBucketMetainfoResponse.DiscardUnknown(m)
}

var xxx_messageInfo_GetBucketMetainfoResponse proto.InternalMessageInfo

func (m *GetBucketMetainfoResponse) GetInfo() *BucketInfo {
	if m != nil {
		return m.Info
	}
	return nil
}

// ListBucketsMetainfoRequest is a request message for the ListBuckets rpc call
type ListBucketsMetainfoRequest struct {
	Cursor               string   `protobuf:"bytes,1,opt,name=cursor,proto3" json:"cursor,omitempty"`
	Direction            int32    `protobuf:"varint,2,opt,name=direction,proto3" json:"direction,omitempty"`
	Limit                int32    `protobuf:"varint,3,opt,name=limit,proto3" json:"limit,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ListBucketsMetainfoRequest) Reset()         { *m = ListBucketsMetainfoRequest{} }
func (m *ListBucketsMetainfoRequest) String() string { return proto.CompactTextString(m) }
func (*ListBucketsMetainfoRequest) ProtoMessage()    {}
func (*ListBucketsMetainfoRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_metainfo_fe01dfb05652234b, []int{5}
}
func (m *ListBucketsMetainfoRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ListBucketsMetainfoRequest.Unmarshal(m, b)
}
func (m *ListBucketsMetainfoRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ListBucketsMetainfoRequest.Marshal(b, m, deterministic)
}
func (dst *ListBucketsMetainfoRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ListBucketsMetainfoRequest.Merge(dst, src)
}
func (m *ListBucketsMetainfoRequest) XXX_Size() int {
	return xxx_messageInfo_ListBucketsMetainfoRequest.Size(m)
}
func (m *ListBucketsMetainfoRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_ListBucketsMetainfoRequest.DiscardUnknown(m)
}

var xxx_messageInfo_ListBucketsMetainfoRequest proto.InternalMessageInfo

func (m *ListBucketsMetainfoRequest) GetCursor() string {
	if m != nil {
		return m.Cursor
	}
	return ""
}

func (m *ListBucketsMetainfoRequest) GetDirection() int32 {
	if m != nil {
		return m.Direction
	}
	return 0
}

func (m *ListBucketsMetainfoRequest) GetLimit() int32 {
	if m != nil {
		return m.Limit
	}
	return 0
}

// ListBucketsMetainfoResponse is a response message for the ListBuckets rpc call
type ListBucketsMetainfoResponse struct {
	Items                []*BucketInfo `protobuf:"bytes,1,rep,name=items,proto3" json:"items,omitempty"`
	More                 bool          `protobuf:"varint,2,opt,name=more,proto3" json:"more,omitempty"`
	XXX_NoUnkeyedLiteral struct{}      `json:"-"`
	XXX_unrecognized     []byte        `json:"-"`
	XXX_sizecache        int32         `json:"-"`
}

func (m *ListBucketsMetainfoResponse) Reset()         { *m = ListBucketsMetainfoResponse{} }
func (m *ListBucketsMetainfoResponse) String() string { return proto.CompactTextString(m) }
func (*ListBucketsMetainfoResponse) ProtoMessage()    {}
func (*ListBucketsMetainfoResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_metainfo_fe01dfb05652234b, []int{6}
}
func (m *ListBucketsMetainfoResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ListBucketsMetainfoResponse.Unmarshal(m, b)
}
func (m *ListBucketsMetainfoResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ListBucketsMetainfoResponse.Marshal(b, m, deterministic)
}
func (dst *ListBucketsMetainfoResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ListBucketsMetainfoResponse.Merge(dst, src)
}
func (m *ListBucketsMetainfoResponse) XXX_Size() int {
	return xxx_messageInfo_ListBucketsMetainfoResponse.Size(m)
}
func (m *ListBucketsMetainfoResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_ListBucketsMetainfoResponse.DiscardUnknown(m)
}

var xxx_messageInfo_ListBucketsMetainfoResponse proto.InternalMessageInfo

func (m *ListBucketsMetainfoResponse) GetItems() []*BucketInfo {
	if m != nil {
		return m.Items
	}
	return nil
}

func (m *ListBucketsMetainfoResponse) GetMore() bool {
	if m != nil {
		return m.More
	}
	return false
}

// DeleteBucketsResponse is a response message for the DeleteBuckets rpc call
type DeleteBucketMetainfoRequest struct {
	Bucket               string   `protobuf:"bytes,1,opt,name=bucket,proto3" json:"bucket,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *DeleteBucketMetainfoRequest) Reset()         { *m = DeleteBucketMetainfoRequest{} }
func (m *DeleteBucketMetainfoRequest) String() string { return proto.CompactTextString(m) }
func (*DeleteBucketMetainfoRequest) ProtoMessage()    {}
func (*DeleteBucketMetainfoRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_metainfo_fe01dfb05652234b, []int{7}
}
func (m *DeleteBucketMetainfoRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_DeleteBucketMetainfoRequest.Unmarshal(m, b)
}
func (m *DeleteBucketMetainfoRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_DeleteBucketMetainfoRequest.Marshal(b, m, deterministic)
}
func (dst *DeleteBucketMetainfoRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_DeleteBucketMetainfoRequest.Merge(dst, src)
}
func (m *DeleteBucketMetainfoRequest) XXX_Size() int {
	return xxx_messageInfo_DeleteBucketMetainfoRequest.Size(m)
}
func (m *DeleteBucketMetainfoRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_DeleteBucketMetainfoRequest.DiscardUnknown(m)
}

var xxx_messageInfo_DeleteBucketMetainfoRequest proto.InternalMessageInfo

func (m *DeleteBucketMetainfoRequest) GetBucket() string {
	if m != nil {
		return m.Bucket
	}
	return ""
}

// DeleteBucketMetainfoResponse is a response message for the DeleteBucket rpc call
type DeleteBucketMetainfoResponse struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *DeleteBucketMetainfoResponse) Reset()         { *m = DeleteBucketMetainfoResponse{} }
func (m *DeleteBucketMetainfoResponse) String() string { return proto.CompactTextString(m) }
func (*DeleteBucketMetainfoResponse) ProtoMessage()    {}
func (*DeleteBucketMetainfoResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_metainfo_fe01dfb05652234b, []int{8}
}
func (m *DeleteBucketMetainfoResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_DeleteBucketMetainfoResponse.Unmarshal(m, b)
}
func (m *DeleteBucketMetainfoResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_DeleteBucketMetainfoResponse.Marshal(b, m, deterministic)
}
func (dst *DeleteBucketMetainfoResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_DeleteBucketMetainfoResponse.Merge(dst, src)
}
func (m *DeleteBucketMetainfoResponse) XXX_Size() int {
	return xxx_messageInfo_DeleteBucketMetainfoResponse.Size(m)
}
func (m *DeleteBucketMetainfoResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_DeleteBucketMetainfoResponse.DiscardUnknown(m)
}

var xxx_messageInfo_DeleteBucketMetainfoResponse proto.InternalMessageInfo

func init() {
	proto.RegisterType((*BucketInfo)(nil), "metainfo.BucketInfo")
	proto.RegisterType((*CreateBucketMetainfoRequest)(nil), "metainfo.CreateBucketMetainfoRequest")
	proto.RegisterType((*CreateBucketMetainfoResponse)(nil), "metainfo.CreateBucketMetainfoResponse")
	proto.RegisterType((*GetBucketMetainfoRequest)(nil), "metainfo.GetBucketMetainfoRequest")
	proto.RegisterType((*GetBucketMetainfoResponse)(nil), "metainfo.GetBucketMetainfoResponse")
	proto.RegisterType((*ListBucketsMetainfoRequest)(nil), "metainfo.ListBucketsMetainfoRequest")
	proto.RegisterType((*ListBucketsMetainfoResponse)(nil), "metainfo.ListBucketsMetainfoResponse")
	proto.RegisterType((*DeleteBucketMetainfoRequest)(nil), "metainfo.DeleteBucketMetainfoRequest")
	proto.RegisterType((*DeleteBucketMetainfoResponse)(nil), "metainfo.DeleteBucketMetainfoResponse")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// MetainfoClient is the client API for Metainfo service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type MetainfoClient interface {
	// CreateBucket creates a new bucket
	CreateBucket(ctx context.Context, in *CreateBucketMetainfoRequest, opts ...grpc.CallOption) (*CreateBucketMetainfoResponse, error)
	// GetBucket returns the info for a bucket
	GetBucket(ctx context.Context, in *GetBucketMetainfoRequest, opts ...grpc.CallOption) (*GetBucketMetainfoResponse, error)
	// ListBuckets lists the existing buckets
	ListBuckets(ctx context.Context, in *ListBucketsMetainfoRequest, opts ...grpc.CallOption) (*ListBucketsMetainfoResponse, error)
	// DeleteBucket deletes a bucket
	DeleteBucket(ctx context.Context, in *DeleteBucketMetainfoRequest, opts ...grpc.CallOption) (*DeleteBucketMetainfoResponse, error)
}

type metainfoClient struct {
	cc *grpc.ClientConn
}

func NewMetainfoClient(cc *grpc.ClientConn) MetainfoClient {
	return &metainfoClient{cc}
}

func (c *metainfoClient) CreateBucket(ctx context.Context, in *CreateBucketMetainfoRequest, opts ...grpc.CallOption) (*CreateBucketMetainfoResponse, error) {
	out := new(CreateBucketMetainfoResponse)
	err := c.cc.Invoke(ctx, "/metainfo.Metainfo/CreateBucket", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *metainfoClient) GetBucket(ctx context.Context, in *GetBucketMetainfoRequest, opts ...grpc.CallOption) (*GetBucketMetainfoResponse, error) {
	out := new(GetBucketMetainfoResponse)
	err := c.cc.Invoke(ctx, "/metainfo.Metainfo/GetBucket", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *metainfoClient) ListBuckets(ctx context.Context, in *ListBucketsMetainfoRequest, opts ...grpc.CallOption) (*ListBucketsMetainfoResponse, error) {
	out := new(ListBucketsMetainfoResponse)
	err := c.cc.Invoke(ctx, "/metainfo.Metainfo/ListBuckets", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *metainfoClient) DeleteBucket(ctx context.Context, in *DeleteBucketMetainfoRequest, opts ...grpc.CallOption) (*DeleteBucketMetainfoResponse, error) {
	out := new(DeleteBucketMetainfoResponse)
	err := c.cc.Invoke(ctx, "/metainfo.Metainfo/DeleteBucket", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// MetainfoServer is the server API for Metainfo service.
type MetainfoServer interface {
	// CreateBucket creates a new bucket
	CreateBucket(context.Context, *CreateBucketMetainfoRequest) (*CreateBucketMetainfoResponse, error)
	// GetBucket returns the info for a bucket
	GetBucket(context.Context, *GetBucketMetainfoRequest) (*GetBucketMetainfoResponse, error)
	// ListBuckets lists the existing buckets
	ListBuckets(context.Context, *ListBucketsMetainfoRequest) (*ListBucketsMetainfoResponse, error)
	// DeleteBucket deletes a bucket
	DeleteBucket(context.Context, *DeleteBucketMetainfoRequest) (*DeleteBucketMetainfoResponse, error)
}

func RegisterMetainfoServer(s *grpc.Server, srv MetainfoServer) {
	s.RegisterService(&_Metainfo_serviceDesc, srv)
}

func _Metainfo_CreateBucket_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateBucketMetainfoRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MetainfoServer).CreateBucket(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/metainfo.Metainfo/CreateBucket",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MetainfoServer).CreateBucket(ctx, req.(*CreateBucketMetainfoRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Metainfo_GetBucket_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetBucketMetainfoRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MetainfoServer).GetBucket(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/metainfo.Metainfo/GetBucket",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MetainfoServer).GetBucket(ctx, req.(*GetBucketMetainfoRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Metainfo_ListBuckets_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListBucketsMetainfoRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MetainfoServer).ListBuckets(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/metainfo.Metainfo/ListBuckets",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MetainfoServer).ListBuckets(ctx, req.(*ListBucketsMetainfoRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Metainfo_DeleteBucket_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteBucketMetainfoRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MetainfoServer).DeleteBucket(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/metainfo.Metainfo/DeleteBucket",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MetainfoServer).DeleteBucket(ctx, req.(*DeleteBucketMetainfoRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _Metainfo_serviceDesc = grpc.ServiceDesc{
	ServiceName: "metainfo.Metainfo",
	HandlerType: (*MetainfoServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "CreateBucket",
			Handler:    _Metainfo_CreateBucket_Handler,
		},
		{
			MethodName: "GetBucket",
			Handler:    _Metainfo_GetBucket_Handler,
		},
		{
			MethodName: "ListBuckets",
			Handler:    _Metainfo_ListBuckets_Handler,
		},
		{
			MethodName: "DeleteBucket",
			Handler:    _Metainfo_DeleteBucket_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "metainfo.proto",
}

func init() { proto.RegisterFile("metainfo.proto", fileDescriptor_metainfo_fe01dfb05652234b) }

var fileDescriptor_metainfo_fe01dfb05652234b = []byte{
	// 419 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x94, 0x53, 0xd1, 0xae, 0x93, 0x40,
	0x10, 0x0d, 0xdc, 0xf6, 0xda, 0x0e, 0x37, 0x3e, 0x6c, 0x6e, 0x0c, 0xd2, 0xc6, 0x4b, 0x56, 0xaf,
	0x21, 0x3e, 0xd0, 0x04, 0xf5, 0x07, 0x5a, 0x8d, 0x9a, 0xe8, 0x0b, 0x69, 0x7c, 0x68, 0xd2, 0x18,
	0xa0, 0xd3, 0x76, 0x63, 0x61, 0x91, 0x5d, 0xe2, 0xbf, 0xfb, 0x64, 0xba, 0x2c, 0x85, 0x28, 0xa5,
	0xe9, 0xdb, 0xce, 0x70, 0xe6, 0xcc, 0xc9, 0x39, 0x03, 0x3c, 0x4d, 0x51, 0x46, 0x2c, 0xdb, 0x72,
	0x3f, 0x2f, 0xb8, 0xe4, 0x64, 0x54, 0xd7, 0xce, 0xc3, 0x8e, 0xf3, 0xdd, 0x01, 0x67, 0xaa, 0x1f,
	0x97, 0xdb, 0x99, 0x64, 0x29, 0x0a, 0x19, 0xa5, 0x79, 0x05, 0xa5, 0xbf, 0x01, 0xe6, 0x65, 0xf2,
	0x13, 0xe5, 0x97, 0x6c, 0xcb, 0x09, 0x81, 0x41, 0x16, 0xa5, 0x68, 0x1b, 0xae, 0xe1, 0x8d, 0x43,
	0xf5, 0x26, 0xef, 0xe0, 0x49, 0x52, 0x60, 0x24, 0x71, 0x63, 0x9b, 0xae, 0xe1, 0x59, 0x81, 0xe3,
	0x57, 0xa4, 0x7e, 0x4d, 0xea, 0x2f, 0x6b, 0xd2, 0xb0, 0x86, 0x92, 0x07, 0xb0, 0xf2, 0x48, 0xee,
	0x7f, 0x24, 0x2c, 0xdf, 0x63, 0x61, 0xdf, 0xb8, 0x86, 0x37, 0x0c, 0xe1, 0xd8, 0x5a, 0xa8, 0x0e,
	0xfd, 0x0e, 0x93, 0x85, 0xc2, 0x56, 0xeb, 0xbf, 0x69, 0xc5, 0x21, 0xfe, 0x2a, 0x51, 0x48, 0xf2,
	0x0c, 0x6e, 0x63, 0xf5, 0x41, 0x6b, 0xd1, 0xd5, 0xbf, 0xbc, 0xe6, 0x7f, 0xbc, 0x9f, 0x61, 0xda,
	0xcd, 0x2b, 0x72, 0x9e, 0x09, 0x24, 0x1e, 0x0c, 0x8e, 0xb5, 0xa2, 0xb5, 0x82, 0x7b, 0xff, 0x64,
	0x5d, 0x63, 0x43, 0xa8, 0x10, 0x34, 0x00, 0xfb, 0x13, 0xca, 0xab, 0xe4, 0xd1, 0x8f, 0xf0, 0xbc,
	0x63, 0xe6, 0xea, 0xd5, 0x7b, 0x70, 0xbe, 0x32, 0xa1, 0x79, 0x44, 0xc7, 0xf2, 0xa4, 0x2c, 0x04,
	0x2f, 0xea, 0xe5, 0x55, 0x45, 0xa6, 0x30, 0xde, 0xb0, 0x02, 0x13, 0xc9, 0x78, 0xa6, 0x9d, 0x69,
	0x1a, 0xe4, 0x1e, 0x86, 0x07, 0x96, 0x32, 0xa9, 0xb3, 0xa8, 0x0a, 0xba, 0x86, 0x49, 0xe7, 0x26,
	0x2d, 0xf9, 0x0d, 0x0c, 0x99, 0xc4, 0x54, 0xd8, 0x86, 0x7b, 0x73, 0x56, 0x73, 0x05, 0x39, 0x1e,
	0x4f, 0xca, 0x0b, 0x54, 0x9b, 0x47, 0xa1, 0x7a, 0xd3, 0xf7, 0x30, 0xf9, 0x80, 0x07, 0xbc, 0x32,
	0x65, 0xfa, 0x02, 0xa6, 0xdd, 0x63, 0x95, 0xac, 0xe0, 0x8f, 0x09, 0xa3, 0xba, 0x49, 0xd6, 0x70,
	0xd7, 0x4e, 0x9c, 0x3c, 0x36, 0x22, 0x7b, 0x2e, 0xcc, 0x79, 0x7d, 0x09, 0xa6, 0x2d, 0x58, 0xc2,
	0xf8, 0x14, 0x29, 0xa1, 0xcd, 0xd0, 0xb9, 0xdb, 0x70, 0x5e, 0xf6, 0x62, 0x34, 0xeb, 0x0a, 0xac,
	0x96, 0xef, 0xe4, 0x55, 0x33, 0x73, 0x3e, 0x78, 0xe7, 0xf1, 0x02, 0x4a, 0x73, 0xaf, 0xe1, 0xae,
	0xed, 0x5e, 0xdb, 0x90, 0x9e, 0x30, 0xda, 0x86, 0xf4, 0x99, 0x3f, 0x1f, 0xac, 0xcc, 0x3c, 0x8e,
	0x6f, 0xd5, 0xdf, 0xff, 0xf6, 0x6f, 0x00, 0x00, 0x00, 0xff, 0xff, 0x5c, 0x19, 0x77, 0xbe, 0x7c,
	0x04, 0x00, 0x00,
}