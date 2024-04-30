# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: proto/inbs_sb.proto
# Protobuf Python Version: 4.25.1
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x13proto/inbs_sb.proto\x12\x04inbs\"Q\n\x0bINBMRequest\x12\x12\n\nrequest_id\x18\x01 \x01(\t\x12.\n\x0crequest_data\x18\x02 \x01(\x0b\x32\x18.inbs.INBMRequestPayload\"T\n\x0cINBMResponse\x12\x12\n\nrequest_id\x18\x01 \x01(\t\x12\x30\n\rresponse_data\x18\x02 \x01(\x0b\x32\x19.inbs.INBMResponsePayload\"\x9a\x01\n\x12INBMRequestPayload\x12\x30\n\x0cping_request\x18\x01 \x01(\x0b\x32\x18.inbs.PingRequestPayloadH\x00\x12G\n\x18scheduled_update_request\x18\x02 \x01(\x0b\x32#.inbs.ScheduledUpdateRequestPayloadH\x00\x42\t\n\x07payload\"\x9f\x01\n\x13INBMResponsePayload\x12\x32\n\rping_response\x18\x01 \x01(\x0b\x32\x19.inbs.PingResponsePayloadH\x00\x12I\n\x19scheduled_update_response\x18\x02 \x01(\x0b\x32$.inbs.ScheduledUpdateResponsePayloadH\x00\x42\t\n\x07payload\"\x14\n\x12PingRequestPayload\"\x15\n\x13PingResponsePayload\"\xb3\x01\n\x1dScheduledUpdateRequestPayload\x12\x43\n\x0bupdate_type\x18\x01 \x01(\x0e\x32..inbs.ScheduledUpdateRequestPayload.UpdateType\x12\x14\n\nepoch_time\x18\x02 \x01(\x03H\x00\x12\x13\n\timmediate\x18\x03 \x01(\x08H\x00\"\x16\n\nUpdateType\x12\x08\n\x04SOTA\x10\x00\x42\n\n\x08schedule\" \n\x1eScheduledUpdateResponsePayload2I\n\rINBSSBService\x12\x38\n\x0bINBMCommand\x12\x12.inbs.INBMResponse\x1a\x11.inbs.INBMRequest(\x01\x30\x01\x62\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'proto.inbs_sb_pb2', _globals)
if _descriptor._USE_C_DESCRIPTORS == False:
  DESCRIPTOR._options = None
  _globals['_INBMREQUEST']._serialized_start=29
  _globals['_INBMREQUEST']._serialized_end=110
  _globals['_INBMRESPONSE']._serialized_start=112
  _globals['_INBMRESPONSE']._serialized_end=196
  _globals['_INBMREQUESTPAYLOAD']._serialized_start=199
  _globals['_INBMREQUESTPAYLOAD']._serialized_end=353
  _globals['_INBMRESPONSEPAYLOAD']._serialized_start=356
  _globals['_INBMRESPONSEPAYLOAD']._serialized_end=515
  _globals['_PINGREQUESTPAYLOAD']._serialized_start=517
  _globals['_PINGREQUESTPAYLOAD']._serialized_end=537
  _globals['_PINGRESPONSEPAYLOAD']._serialized_start=539
  _globals['_PINGRESPONSEPAYLOAD']._serialized_end=560
  _globals['_SCHEDULEDUPDATEREQUESTPAYLOAD']._serialized_start=563
  _globals['_SCHEDULEDUPDATEREQUESTPAYLOAD']._serialized_end=742
  _globals['_SCHEDULEDUPDATEREQUESTPAYLOAD_UPDATETYPE']._serialized_start=708
  _globals['_SCHEDULEDUPDATEREQUESTPAYLOAD_UPDATETYPE']._serialized_end=730
  _globals['_SCHEDULEDUPDATERESPONSEPAYLOAD']._serialized_start=744
  _globals['_SCHEDULEDUPDATERESPONSEPAYLOAD']._serialized_end=776
  _globals['_INBSSBSERVICE']._serialized_start=778
  _globals['_INBSSBSERVICE']._serialized_end=851
# @@protoc_insertion_point(module_scope)
