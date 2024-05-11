// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.33.0
// 	protoc        v3.12.4
// source: inbs/v1/inbs_sb.proto

package pb

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type INBMRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RequestId string `protobuf:"bytes,1,opt,name=request_id,json=requestId,proto3" json:"request_id,omitempty"`
	// Types that are assignable to Payload:
	//
	//	*INBMRequest_PingRequest
	Payload isINBMRequest_Payload `protobuf_oneof:"payload"`
}

func (x *INBMRequest) Reset() {
	*x = INBMRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_inbs_v1_inbs_sb_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *INBMRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*INBMRequest) ProtoMessage() {}

func (x *INBMRequest) ProtoReflect() protoreflect.Message {
	mi := &file_inbs_v1_inbs_sb_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use INBMRequest.ProtoReflect.Descriptor instead.
func (*INBMRequest) Descriptor() ([]byte, []int) {
	return file_inbs_v1_inbs_sb_proto_rawDescGZIP(), []int{0}
}

func (x *INBMRequest) GetRequestId() string {
	if x != nil {
		return x.RequestId
	}
	return ""
}

func (m *INBMRequest) GetPayload() isINBMRequest_Payload {
	if m != nil {
		return m.Payload
	}
	return nil
}

func (x *INBMRequest) GetPingRequest() *PingRequest {
	if x, ok := x.GetPayload().(*INBMRequest_PingRequest); ok {
		return x.PingRequest
	}
	return nil
}

type isINBMRequest_Payload interface {
	isINBMRequest_Payload()
}

type INBMRequest_PingRequest struct {
	PingRequest *PingRequest `protobuf:"bytes,2,opt,name=ping_request,json=pingRequest,proto3,oneof"`
}

func (*INBMRequest_PingRequest) isINBMRequest_Payload() {}

type INBMResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RequestId string `protobuf:"bytes,1,opt,name=request_id,json=requestId,proto3" json:"request_id,omitempty"`
	// Types that are assignable to Payload:
	//
	//	*INBMResponse_PingResponse
	Payload isINBMResponse_Payload `protobuf_oneof:"payload"`
}

func (x *INBMResponse) Reset() {
	*x = INBMResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_inbs_v1_inbs_sb_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *INBMResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*INBMResponse) ProtoMessage() {}

func (x *INBMResponse) ProtoReflect() protoreflect.Message {
	mi := &file_inbs_v1_inbs_sb_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use INBMResponse.ProtoReflect.Descriptor instead.
func (*INBMResponse) Descriptor() ([]byte, []int) {
	return file_inbs_v1_inbs_sb_proto_rawDescGZIP(), []int{1}
}

func (x *INBMResponse) GetRequestId() string {
	if x != nil {
		return x.RequestId
	}
	return ""
}

func (m *INBMResponse) GetPayload() isINBMResponse_Payload {
	if m != nil {
		return m.Payload
	}
	return nil
}

func (x *INBMResponse) GetPingResponse() *PingResponse {
	if x, ok := x.GetPayload().(*INBMResponse_PingResponse); ok {
		return x.PingResponse
	}
	return nil
}

type isINBMResponse_Payload interface {
	isINBMResponse_Payload()
}

type INBMResponse_PingResponse struct {
	PingResponse *PingResponse `protobuf:"bytes,2,opt,name=ping_response,json=pingResponse,proto3,oneof"`
}

func (*INBMResponse_PingResponse) isINBMResponse_Payload() {}

type PingRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *PingRequest) Reset() {
	*x = PingRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_inbs_v1_inbs_sb_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PingRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PingRequest) ProtoMessage() {}

func (x *PingRequest) ProtoReflect() protoreflect.Message {
	mi := &file_inbs_v1_inbs_sb_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PingRequest.ProtoReflect.Descriptor instead.
func (*PingRequest) Descriptor() ([]byte, []int) {
	return file_inbs_v1_inbs_sb_proto_rawDescGZIP(), []int{2}
}

type PingResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *PingResponse) Reset() {
	*x = PingResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_inbs_v1_inbs_sb_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PingResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PingResponse) ProtoMessage() {}

func (x *PingResponse) ProtoReflect() protoreflect.Message {
	mi := &file_inbs_v1_inbs_sb_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PingResponse.ProtoReflect.Descriptor instead.
func (*PingResponse) Descriptor() ([]byte, []int) {
	return file_inbs_v1_inbs_sb_proto_rawDescGZIP(), []int{3}
}

type TestCommonImport struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	CommonMessage *CommonMessage `protobuf:"bytes,1,opt,name=common_message,json=commonMessage,proto3" json:"common_message,omitempty"`
}

func (x *TestCommonImport) Reset() {
	*x = TestCommonImport{}
	if protoimpl.UnsafeEnabled {
		mi := &file_inbs_v1_inbs_sb_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TestCommonImport) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TestCommonImport) ProtoMessage() {}

func (x *TestCommonImport) ProtoReflect() protoreflect.Message {
	mi := &file_inbs_v1_inbs_sb_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TestCommonImport.ProtoReflect.Descriptor instead.
func (*TestCommonImport) Descriptor() ([]byte, []int) {
	return file_inbs_v1_inbs_sb_proto_rawDescGZIP(), []int{4}
}

func (x *TestCommonImport) GetCommonMessage() *CommonMessage {
	if x != nil {
		return x.CommonMessage
	}
	return nil
}

var File_inbs_v1_inbs_sb_proto protoreflect.FileDescriptor

var file_inbs_v1_inbs_sb_proto_rawDesc = []byte{
	0x0a, 0x15, 0x69, 0x6e, 0x62, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x69, 0x6e, 0x62, 0x73, 0x5f, 0x73,
	0x62, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x07, 0x69, 0x6e, 0x62, 0x73, 0x2e, 0x76, 0x31,
	0x1a, 0x16, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2f, 0x76, 0x31, 0x2f, 0x63, 0x6f, 0x6d, 0x6d,
	0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x72, 0x0a, 0x0b, 0x49, 0x4e, 0x42, 0x4d,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1d, 0x0a, 0x0a, 0x72, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x72, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x49, 0x64, 0x12, 0x39, 0x0a, 0x0c, 0x70, 0x69, 0x6e, 0x67, 0x5f, 0x72,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x69,
	0x6e, 0x62, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x50, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x48, 0x00, 0x52, 0x0b, 0x70, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x42, 0x09, 0x0a, 0x07, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x22, 0x76, 0x0a, 0x0c,
	0x49, 0x4e, 0x42, 0x4d, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x1d, 0x0a, 0x0a,
	0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x09, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x49, 0x64, 0x12, 0x3c, 0x0a, 0x0d, 0x70,
	0x69, 0x6e, 0x67, 0x5f, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x15, 0x2e, 0x69, 0x6e, 0x62, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x50, 0x69, 0x6e,
	0x67, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x48, 0x00, 0x52, 0x0c, 0x70, 0x69, 0x6e,
	0x67, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x42, 0x09, 0x0a, 0x07, 0x70, 0x61, 0x79,
	0x6c, 0x6f, 0x61, 0x64, 0x22, 0x0d, 0x0a, 0x0b, 0x50, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x22, 0x0e, 0x0a, 0x0c, 0x50, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x22, 0x53, 0x0a, 0x10, 0x54, 0x65, 0x73, 0x74, 0x43, 0x6f, 0x6d, 0x6d, 0x6f,
	0x6e, 0x49, 0x6d, 0x70, 0x6f, 0x72, 0x74, 0x12, 0x3f, 0x0a, 0x0e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f,
	0x6e, 0x5f, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x18, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x76, 0x31, 0x2e, 0x43, 0x6f, 0x6d, 0x6d,
	0x6f, 0x6e, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x52, 0x0d, 0x63, 0x6f, 0x6d, 0x6d, 0x6f,
	0x6e, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x32, 0x4f, 0x0a, 0x0d, 0x49, 0x4e, 0x42, 0x53,
	0x53, 0x42, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x3e, 0x0a, 0x0b, 0x49, 0x4e, 0x42,
	0x4d, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x12, 0x15, 0x2e, 0x69, 0x6e, 0x62, 0x73, 0x2e,
	0x76, 0x31, 0x2e, 0x49, 0x4e, 0x42, 0x4d, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x1a,
	0x14, 0x2e, 0x69, 0x6e, 0x62, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x49, 0x4e, 0x42, 0x4d, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x28, 0x01, 0x30, 0x01, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x33,
}

var (
	file_inbs_v1_inbs_sb_proto_rawDescOnce sync.Once
	file_inbs_v1_inbs_sb_proto_rawDescData = file_inbs_v1_inbs_sb_proto_rawDesc
)

func file_inbs_v1_inbs_sb_proto_rawDescGZIP() []byte {
	file_inbs_v1_inbs_sb_proto_rawDescOnce.Do(func() {
		file_inbs_v1_inbs_sb_proto_rawDescData = protoimpl.X.CompressGZIP(file_inbs_v1_inbs_sb_proto_rawDescData)
	})
	return file_inbs_v1_inbs_sb_proto_rawDescData
}

var file_inbs_v1_inbs_sb_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_inbs_v1_inbs_sb_proto_goTypes = []interface{}{
	(*INBMRequest)(nil),      // 0: inbs.v1.INBMRequest
	(*INBMResponse)(nil),     // 1: inbs.v1.INBMResponse
	(*PingRequest)(nil),      // 2: inbs.v1.PingRequest
	(*PingResponse)(nil),     // 3: inbs.v1.PingResponse
	(*TestCommonImport)(nil), // 4: inbs.v1.TestCommonImport
	(*CommonMessage)(nil),    // 5: common.v1.CommonMessage
}
var file_inbs_v1_inbs_sb_proto_depIdxs = []int32{
	2, // 0: inbs.v1.INBMRequest.ping_request:type_name -> inbs.v1.PingRequest
	3, // 1: inbs.v1.INBMResponse.ping_response:type_name -> inbs.v1.PingResponse
	5, // 2: inbs.v1.TestCommonImport.common_message:type_name -> common.v1.CommonMessage
	1, // 3: inbs.v1.INBSSBService.INBMCommand:input_type -> inbs.v1.INBMResponse
	0, // 4: inbs.v1.INBSSBService.INBMCommand:output_type -> inbs.v1.INBMRequest
	4, // [4:5] is the sub-list for method output_type
	3, // [3:4] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_inbs_v1_inbs_sb_proto_init() }
func file_inbs_v1_inbs_sb_proto_init() {
	if File_inbs_v1_inbs_sb_proto != nil {
		return
	}
	file_common_v1_common_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_inbs_v1_inbs_sb_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*INBMRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_inbs_v1_inbs_sb_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*INBMResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_inbs_v1_inbs_sb_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PingRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_inbs_v1_inbs_sb_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PingResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_inbs_v1_inbs_sb_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TestCommonImport); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	file_inbs_v1_inbs_sb_proto_msgTypes[0].OneofWrappers = []interface{}{
		(*INBMRequest_PingRequest)(nil),
	}
	file_inbs_v1_inbs_sb_proto_msgTypes[1].OneofWrappers = []interface{}{
		(*INBMResponse_PingResponse)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_inbs_v1_inbs_sb_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_inbs_v1_inbs_sb_proto_goTypes,
		DependencyIndexes: file_inbs_v1_inbs_sb_proto_depIdxs,
		MessageInfos:      file_inbs_v1_inbs_sb_proto_msgTypes,
	}.Build()
	File_inbs_v1_inbs_sb_proto = out.File
	file_inbs_v1_inbs_sb_proto_rawDesc = nil
	file_inbs_v1_inbs_sb_proto_goTypes = nil
	file_inbs_v1_inbs_sb_proto_depIdxs = nil
}
