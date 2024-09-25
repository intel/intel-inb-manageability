// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.27.1
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

type HandleINBMCommandRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RequestId string       `protobuf:"bytes,1,opt,name=request_id,json=requestId,proto3" json:"request_id,omitempty"`
	Command   *INBMCommand `protobuf:"bytes,2,opt,name=command,proto3" json:"command,omitempty"`
}

func (x *HandleINBMCommandRequest) Reset() {
	*x = HandleINBMCommandRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_inbs_v1_inbs_sb_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HandleINBMCommandRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HandleINBMCommandRequest) ProtoMessage() {}

func (x *HandleINBMCommandRequest) ProtoReflect() protoreflect.Message {
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

// Deprecated: Use HandleINBMCommandRequest.ProtoReflect.Descriptor instead.
func (*HandleINBMCommandRequest) Descriptor() ([]byte, []int) {
	return file_inbs_v1_inbs_sb_proto_rawDescGZIP(), []int{0}
}

func (x *HandleINBMCommandRequest) GetRequestId() string {
	if x != nil {
		return x.RequestId
	}
	return ""
}

func (x *HandleINBMCommandRequest) GetCommand() *INBMCommand {
	if x != nil {
		return x.Command
	}
	return nil
}

type HandleINBMCommandResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RequestId string `protobuf:"bytes,1,opt,name=request_id,json=requestId,proto3" json:"request_id,omitempty"`
	Error     *Error `protobuf:"bytes,2,opt,name=error,proto3" json:"error,omitempty"`
}

func (x *HandleINBMCommandResponse) Reset() {
	*x = HandleINBMCommandResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_inbs_v1_inbs_sb_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HandleINBMCommandResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HandleINBMCommandResponse) ProtoMessage() {}

func (x *HandleINBMCommandResponse) ProtoReflect() protoreflect.Message {
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

// Deprecated: Use HandleINBMCommandResponse.ProtoReflect.Descriptor instead.
func (*HandleINBMCommandResponse) Descriptor() ([]byte, []int) {
	return file_inbs_v1_inbs_sb_proto_rawDescGZIP(), []int{1}
}

func (x *HandleINBMCommandResponse) GetRequestId() string {
	if x != nil {
		return x.RequestId
	}
	return ""
}

func (x *HandleINBMCommandResponse) GetError() *Error {
	if x != nil {
		return x.Error
	}
	return nil
}

type INBMCommand struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to InbmCommand:
	//	*INBMCommand_UpdateScheduledOperations
	//	*INBMCommand_Ping
	InbmCommand isINBMCommand_InbmCommand `protobuf_oneof:"inbm_command"`
}

func (x *INBMCommand) Reset() {
	*x = INBMCommand{}
	if protoimpl.UnsafeEnabled {
		mi := &file_inbs_v1_inbs_sb_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *INBMCommand) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*INBMCommand) ProtoMessage() {}

func (x *INBMCommand) ProtoReflect() protoreflect.Message {
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

// Deprecated: Use INBMCommand.ProtoReflect.Descriptor instead.
func (*INBMCommand) Descriptor() ([]byte, []int) {
	return file_inbs_v1_inbs_sb_proto_rawDescGZIP(), []int{2}
}

func (m *INBMCommand) GetInbmCommand() isINBMCommand_InbmCommand {
	if m != nil {
		return m.InbmCommand
	}
	return nil
}

func (x *INBMCommand) GetUpdateScheduledOperations() *UpdateScheduledOperations {
	if x, ok := x.GetInbmCommand().(*INBMCommand_UpdateScheduledOperations); ok {
		return x.UpdateScheduledOperations
	}
	return nil
}

func (x *INBMCommand) GetPing() *Ping {
	if x, ok := x.GetInbmCommand().(*INBMCommand_Ping); ok {
		return x.Ping
	}
	return nil
}

type isINBMCommand_InbmCommand interface {
	isINBMCommand_InbmCommand()
}

type INBMCommand_UpdateScheduledOperations struct {
	UpdateScheduledOperations *UpdateScheduledOperations `protobuf:"bytes,1,opt,name=update_scheduled_operations,json=updateScheduledOperations,proto3,oneof"`
}

type INBMCommand_Ping struct {
	Ping *Ping `protobuf:"bytes,2,opt,name=ping,proto3,oneof"`
}

func (*INBMCommand_UpdateScheduledOperations) isINBMCommand_InbmCommand() {}

func (*INBMCommand_Ping) isINBMCommand_InbmCommand() {}

type UpdateScheduledOperations struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ScheduledOperations []*ScheduledOperation `protobuf:"bytes,1,rep,name=scheduled_operations,json=scheduledOperations,proto3" json:"scheduled_operations,omitempty"`
}

func (x *UpdateScheduledOperations) Reset() {
	*x = UpdateScheduledOperations{}
	if protoimpl.UnsafeEnabled {
		mi := &file_inbs_v1_inbs_sb_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UpdateScheduledOperations) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UpdateScheduledOperations) ProtoMessage() {}

func (x *UpdateScheduledOperations) ProtoReflect() protoreflect.Message {
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

// Deprecated: Use UpdateScheduledOperations.ProtoReflect.Descriptor instead.
func (*UpdateScheduledOperations) Descriptor() ([]byte, []int) {
	return file_inbs_v1_inbs_sb_proto_rawDescGZIP(), []int{3}
}

func (x *UpdateScheduledOperations) GetScheduledOperations() []*ScheduledOperation {
	if x != nil {
		return x.ScheduledOperations
	}
	return nil
}

type Ping struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *Ping) Reset() {
	*x = Ping{}
	if protoimpl.UnsafeEnabled {
		mi := &file_inbs_v1_inbs_sb_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Ping) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Ping) ProtoMessage() {}

func (x *Ping) ProtoReflect() protoreflect.Message {
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

// Deprecated: Use Ping.ProtoReflect.Descriptor instead.
func (*Ping) Descriptor() ([]byte, []int) {
	return file_inbs_v1_inbs_sb_proto_rawDescGZIP(), []int{4}
}

type SendNodeUpdateRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RequestId string `protobuf:"bytes,1,opt,name=request_id,json=requestId,proto3" json:"request_id,omitempty"`
	// Types that are assignable to Update:
	//	*SendNodeUpdateRequest_JobUpdate
	Update isSendNodeUpdateRequest_Update `protobuf_oneof:"update"`
}

func (x *SendNodeUpdateRequest) Reset() {
	*x = SendNodeUpdateRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_inbs_v1_inbs_sb_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SendNodeUpdateRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SendNodeUpdateRequest) ProtoMessage() {}

func (x *SendNodeUpdateRequest) ProtoReflect() protoreflect.Message {
	mi := &file_inbs_v1_inbs_sb_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SendNodeUpdateRequest.ProtoReflect.Descriptor instead.
func (*SendNodeUpdateRequest) Descriptor() ([]byte, []int) {
	return file_inbs_v1_inbs_sb_proto_rawDescGZIP(), []int{5}
}

func (x *SendNodeUpdateRequest) GetRequestId() string {
	if x != nil {
		return x.RequestId
	}
	return ""
}

func (m *SendNodeUpdateRequest) GetUpdate() isSendNodeUpdateRequest_Update {
	if m != nil {
		return m.Update
	}
	return nil
}

func (x *SendNodeUpdateRequest) GetJobUpdate() *Job {
	if x, ok := x.GetUpdate().(*SendNodeUpdateRequest_JobUpdate); ok {
		return x.JobUpdate
	}
	return nil
}

type isSendNodeUpdateRequest_Update interface {
	isSendNodeUpdateRequest_Update()
}

type SendNodeUpdateRequest_JobUpdate struct {
	JobUpdate *Job `protobuf:"bytes,3,opt,name=job_update,json=jobUpdate,proto3,oneof"` // node_id will be filled in by INBS; schedule_id, executed_by, desired_start_time, create_time will be ignored
}

func (*SendNodeUpdateRequest_JobUpdate) isSendNodeUpdateRequest_Update() {}

type SendNodeUpdateResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RequestId string `protobuf:"bytes,1,opt,name=request_id,json=requestId,proto3" json:"request_id,omitempty"`
	Error     *Error `protobuf:"bytes,2,opt,name=error,proto3" json:"error,omitempty"`
}

func (x *SendNodeUpdateResponse) Reset() {
	*x = SendNodeUpdateResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_inbs_v1_inbs_sb_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SendNodeUpdateResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SendNodeUpdateResponse) ProtoMessage() {}

func (x *SendNodeUpdateResponse) ProtoReflect() protoreflect.Message {
	mi := &file_inbs_v1_inbs_sb_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SendNodeUpdateResponse.ProtoReflect.Descriptor instead.
func (*SendNodeUpdateResponse) Descriptor() ([]byte, []int) {
	return file_inbs_v1_inbs_sb_proto_rawDescGZIP(), []int{6}
}

func (x *SendNodeUpdateResponse) GetRequestId() string {
	if x != nil {
		return x.RequestId
	}
	return ""
}

func (x *SendNodeUpdateResponse) GetError() *Error {
	if x != nil {
		return x.Error
	}
	return nil
}

var File_inbs_v1_inbs_sb_proto protoreflect.FileDescriptor

var file_inbs_v1_inbs_sb_proto_rawDesc = []byte{
	0x0a, 0x15, 0x69, 0x6e, 0x62, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x69, 0x6e, 0x62, 0x73, 0x5f, 0x73,
	0x62, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x07, 0x69, 0x6e, 0x62, 0x73, 0x2e, 0x76, 0x31,
	0x1a, 0x16, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2f, 0x76, 0x31, 0x2f, 0x63, 0x6f, 0x6d, 0x6d,
	0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x69, 0x0a, 0x18, 0x48, 0x61, 0x6e, 0x64,
	0x6c, 0x65, 0x49, 0x4e, 0x42, 0x4d, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x12, 0x1d, 0x0a, 0x0a, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x5f,
	0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x49, 0x64, 0x12, 0x2e, 0x0a, 0x07, 0x63, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x69, 0x6e, 0x62, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x49,
	0x4e, 0x42, 0x4d, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x52, 0x07, 0x63, 0x6f, 0x6d, 0x6d,
	0x61, 0x6e, 0x64, 0x22, 0x62, 0x0a, 0x19, 0x48, 0x61, 0x6e, 0x64, 0x6c, 0x65, 0x49, 0x4e, 0x42,
	0x4d, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x12, 0x1d, 0x0a, 0x0a, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x49, 0x64, 0x12,
	0x26, 0x0a, 0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x10,
	0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x76, 0x31, 0x2e, 0x45, 0x72, 0x72, 0x6f, 0x72,
	0x52, 0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x22, 0xa8, 0x01, 0x0a, 0x0b, 0x49, 0x4e, 0x42, 0x4d,
	0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x12, 0x64, 0x0a, 0x1b, 0x75, 0x70, 0x64, 0x61, 0x74,
	0x65, 0x5f, 0x73, 0x63, 0x68, 0x65, 0x64, 0x75, 0x6c, 0x65, 0x64, 0x5f, 0x6f, 0x70, 0x65, 0x72,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x22, 0x2e, 0x69,
	0x6e, 0x62, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x53, 0x63, 0x68,
	0x65, 0x64, 0x75, 0x6c, 0x65, 0x64, 0x4f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73,
	0x48, 0x00, 0x52, 0x19, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x53, 0x63, 0x68, 0x65, 0x64, 0x75,
	0x6c, 0x65, 0x64, 0x4f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x12, 0x23, 0x0a,
	0x04, 0x70, 0x69, 0x6e, 0x67, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0d, 0x2e, 0x69, 0x6e,
	0x62, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x50, 0x69, 0x6e, 0x67, 0x48, 0x00, 0x52, 0x04, 0x70, 0x69,
	0x6e, 0x67, 0x42, 0x0e, 0x0a, 0x0c, 0x69, 0x6e, 0x62, 0x6d, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x61,
	0x6e, 0x64, 0x22, 0x6d, 0x0a, 0x19, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x53, 0x63, 0x68, 0x65,
	0x64, 0x75, 0x6c, 0x65, 0x64, 0x4f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x12,
	0x50, 0x0a, 0x14, 0x73, 0x63, 0x68, 0x65, 0x64, 0x75, 0x6c, 0x65, 0x64, 0x5f, 0x6f, 0x70, 0x65,
	0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1d, 0x2e,
	0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x63, 0x68, 0x65, 0x64, 0x75,
	0x6c, 0x65, 0x64, 0x4f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x13, 0x73, 0x63,
	0x68, 0x65, 0x64, 0x75, 0x6c, 0x65, 0x64, 0x4f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x73, 0x22, 0x06, 0x0a, 0x04, 0x50, 0x69, 0x6e, 0x67, 0x22, 0x71, 0x0a, 0x15, 0x53, 0x65, 0x6e,
	0x64, 0x4e, 0x6f, 0x64, 0x65, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x12, 0x1d, 0x0a, 0x0a, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x5f, 0x69, 0x64,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x49,
	0x64, 0x12, 0x2f, 0x0a, 0x0a, 0x6a, 0x6f, 0x62, 0x5f, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0e, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x76,
	0x31, 0x2e, 0x4a, 0x6f, 0x62, 0x48, 0x00, 0x52, 0x09, 0x6a, 0x6f, 0x62, 0x55, 0x70, 0x64, 0x61,
	0x74, 0x65, 0x42, 0x08, 0x0a, 0x06, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x22, 0x5f, 0x0a, 0x16,
	0x53, 0x65, 0x6e, 0x64, 0x4e, 0x6f, 0x64, 0x65, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x1d, 0x0a, 0x0a, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x72, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x49, 0x64, 0x12, 0x26, 0x0a, 0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x10, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x76, 0x31,
	0x2e, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x52, 0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x32, 0xc2, 0x01,
	0x0a, 0x0d, 0x49, 0x4e, 0x42, 0x53, 0x53, 0x42, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12,
	0x5e, 0x0a, 0x11, 0x48, 0x61, 0x6e, 0x64, 0x6c, 0x65, 0x49, 0x4e, 0x42, 0x4d, 0x43, 0x6f, 0x6d,
	0x6d, 0x61, 0x6e, 0x64, 0x12, 0x22, 0x2e, 0x69, 0x6e, 0x62, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x48,
	0x61, 0x6e, 0x64, 0x6c, 0x65, 0x49, 0x4e, 0x42, 0x4d, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x1a, 0x21, 0x2e, 0x69, 0x6e, 0x62, 0x73, 0x2e,
	0x76, 0x31, 0x2e, 0x48, 0x61, 0x6e, 0x64, 0x6c, 0x65, 0x49, 0x4e, 0x42, 0x4d, 0x43, 0x6f, 0x6d,
	0x6d, 0x61, 0x6e, 0x64, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x28, 0x01, 0x30, 0x01, 0x12,
	0x51, 0x0a, 0x0e, 0x53, 0x65, 0x6e, 0x64, 0x4e, 0x6f, 0x64, 0x65, 0x55, 0x70, 0x64, 0x61, 0x74,
	0x65, 0x12, 0x1e, 0x2e, 0x69, 0x6e, 0x62, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x65, 0x6e, 0x64,
	0x4e, 0x6f, 0x64, 0x65, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x1a, 0x1f, 0x2e, 0x69, 0x6e, 0x62, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x65, 0x6e, 0x64,
	0x4e, 0x6f, 0x64, 0x65, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
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

var file_inbs_v1_inbs_sb_proto_msgTypes = make([]protoimpl.MessageInfo, 7)
var file_inbs_v1_inbs_sb_proto_goTypes = []interface{}{
	(*HandleINBMCommandRequest)(nil),  // 0: inbs.v1.HandleINBMCommandRequest
	(*HandleINBMCommandResponse)(nil), // 1: inbs.v1.HandleINBMCommandResponse
	(*INBMCommand)(nil),               // 2: inbs.v1.INBMCommand
	(*UpdateScheduledOperations)(nil), // 3: inbs.v1.UpdateScheduledOperations
	(*Ping)(nil),                      // 4: inbs.v1.Ping
	(*SendNodeUpdateRequest)(nil),     // 5: inbs.v1.SendNodeUpdateRequest
	(*SendNodeUpdateResponse)(nil),    // 6: inbs.v1.SendNodeUpdateResponse
	(*Error)(nil),                     // 7: common.v1.Error
	(*ScheduledOperation)(nil),        // 8: common.v1.ScheduledOperation
	(*Job)(nil),                       // 9: common.v1.Job
}
var file_inbs_v1_inbs_sb_proto_depIdxs = []int32{
	2, // 0: inbs.v1.HandleINBMCommandRequest.command:type_name -> inbs.v1.INBMCommand
	7, // 1: inbs.v1.HandleINBMCommandResponse.error:type_name -> common.v1.Error
	3, // 2: inbs.v1.INBMCommand.update_scheduled_operations:type_name -> inbs.v1.UpdateScheduledOperations
	4, // 3: inbs.v1.INBMCommand.ping:type_name -> inbs.v1.Ping
	8, // 4: inbs.v1.UpdateScheduledOperations.scheduled_operations:type_name -> common.v1.ScheduledOperation
	9, // 5: inbs.v1.SendNodeUpdateRequest.job_update:type_name -> common.v1.Job
	7, // 6: inbs.v1.SendNodeUpdateResponse.error:type_name -> common.v1.Error
	1, // 7: inbs.v1.INBSSBService.HandleINBMCommand:input_type -> inbs.v1.HandleINBMCommandResponse
	5, // 8: inbs.v1.INBSSBService.SendNodeUpdate:input_type -> inbs.v1.SendNodeUpdateRequest
	0, // 9: inbs.v1.INBSSBService.HandleINBMCommand:output_type -> inbs.v1.HandleINBMCommandRequest
	6, // 10: inbs.v1.INBSSBService.SendNodeUpdate:output_type -> inbs.v1.SendNodeUpdateResponse
	9, // [9:11] is the sub-list for method output_type
	7, // [7:9] is the sub-list for method input_type
	7, // [7:7] is the sub-list for extension type_name
	7, // [7:7] is the sub-list for extension extendee
	0, // [0:7] is the sub-list for field type_name
}

func init() { file_inbs_v1_inbs_sb_proto_init() }
func file_inbs_v1_inbs_sb_proto_init() {
	if File_inbs_v1_inbs_sb_proto != nil {
		return
	}
	file_common_v1_common_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_inbs_v1_inbs_sb_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*HandleINBMCommandRequest); i {
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
			switch v := v.(*HandleINBMCommandResponse); i {
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
			switch v := v.(*INBMCommand); i {
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
			switch v := v.(*UpdateScheduledOperations); i {
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
			switch v := v.(*Ping); i {
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
		file_inbs_v1_inbs_sb_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SendNodeUpdateRequest); i {
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
		file_inbs_v1_inbs_sb_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SendNodeUpdateResponse); i {
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
	file_inbs_v1_inbs_sb_proto_msgTypes[2].OneofWrappers = []interface{}{
		(*INBMCommand_UpdateScheduledOperations)(nil),
		(*INBMCommand_Ping)(nil),
	}
	file_inbs_v1_inbs_sb_proto_msgTypes[5].OneofWrappers = []interface{}{
		(*SendNodeUpdateRequest_JobUpdate)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_inbs_v1_inbs_sb_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   7,
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
