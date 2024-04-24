// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             v3.12.4
// source: inbs_sb.proto

package pb

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	INBSSBService_INBMCommand_FullMethodName = "/inbs.INBSSBService/INBMCommand"
)

// INBSSBServiceClient is the client API for INBSSBService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type INBSSBServiceClient interface {
	// Bi-directional streaming method
	INBMCommand(ctx context.Context, opts ...grpc.CallOption) (INBSSBService_INBMCommandClient, error)
}

type iNBSSBServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewINBSSBServiceClient(cc grpc.ClientConnInterface) INBSSBServiceClient {
	return &iNBSSBServiceClient{cc}
}

func (c *iNBSSBServiceClient) INBMCommand(ctx context.Context, opts ...grpc.CallOption) (INBSSBService_INBMCommandClient, error) {
	stream, err := c.cc.NewStream(ctx, &INBSSBService_ServiceDesc.Streams[0], INBSSBService_INBMCommand_FullMethodName, opts...)
	if err != nil {
		return nil, err
	}
	x := &iNBSSBServiceINBMCommandClient{stream}
	return x, nil
}

type INBSSBService_INBMCommandClient interface {
	Send(*INBMResponse) error
	Recv() (*INBMRequest, error)
	grpc.ClientStream
}

type iNBSSBServiceINBMCommandClient struct {
	grpc.ClientStream
}

func (x *iNBSSBServiceINBMCommandClient) Send(m *INBMResponse) error {
	return x.ClientStream.SendMsg(m)
}

func (x *iNBSSBServiceINBMCommandClient) Recv() (*INBMRequest, error) {
	m := new(INBMRequest)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// INBSSBServiceServer is the server API for INBSSBService service.
// All implementations must embed UnimplementedINBSSBServiceServer
// for forward compatibility
type INBSSBServiceServer interface {
	// Bi-directional streaming method
	INBMCommand(INBSSBService_INBMCommandServer) error
	mustEmbedUnimplementedINBSSBServiceServer()
}

// UnimplementedINBSSBServiceServer must be embedded to have forward compatible implementations.
type UnimplementedINBSSBServiceServer struct {
}

func (UnimplementedINBSSBServiceServer) INBMCommand(INBSSBService_INBMCommandServer) error {
	return status.Errorf(codes.Unimplemented, "method INBMCommand not implemented")
}
func (UnimplementedINBSSBServiceServer) mustEmbedUnimplementedINBSSBServiceServer() {}

// UnsafeINBSSBServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to INBSSBServiceServer will
// result in compilation errors.
type UnsafeINBSSBServiceServer interface {
	mustEmbedUnimplementedINBSSBServiceServer()
}

func RegisterINBSSBServiceServer(s grpc.ServiceRegistrar, srv INBSSBServiceServer) {
	s.RegisterService(&INBSSBService_ServiceDesc, srv)
}

func _INBSSBService_INBMCommand_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(INBSSBServiceServer).INBMCommand(&iNBSSBServiceINBMCommandServer{stream})
}

type INBSSBService_INBMCommandServer interface {
	Send(*INBMRequest) error
	Recv() (*INBMResponse, error)
	grpc.ServerStream
}

type iNBSSBServiceINBMCommandServer struct {
	grpc.ServerStream
}

func (x *iNBSSBServiceINBMCommandServer) Send(m *INBMRequest) error {
	return x.ServerStream.SendMsg(m)
}

func (x *iNBSSBServiceINBMCommandServer) Recv() (*INBMResponse, error) {
	m := new(INBMResponse)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// INBSSBService_ServiceDesc is the grpc.ServiceDesc for INBSSBService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var INBSSBService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "inbs.INBSSBService",
	HandlerType: (*INBSSBServiceServer)(nil),
	Methods:     []grpc.MethodDesc{},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "INBMCommand",
			Handler:       _INBSSBService_INBMCommand_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
	Metadata: "inbs_sb.proto",
}