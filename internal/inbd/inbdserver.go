package inbd

import (
	"context"
	"log"

	pb "github.com/intel/intel-inb-manageability/pkg/api/inbd/v1"
)

type InbdServer struct {
	pb.UnimplementedInbServiceServer
}

func (s *InbdServer) UpdateSystemSoftware(ctx context.Context, req *pb.UpdateSystemSoftwareRequest) (*pb.UpdateResponse, error) {
	log.Printf("Received UpdateSystemSoftware request")
	return &pb.UpdateResponse{StatusCode: 501, Error: "Not implemented"}, nil
}

func (s *InbdServer) UpdateOSSource(ctx context.Context, req *pb.UpdateOSSourceRequest) (*pb.UpdateResponse, error) {
	log.Printf("Received UpdateOSSource request")
	return &pb.UpdateResponse{StatusCode: 501, Error: "Not implemented"}, nil
}

func (s *InbdServer) AddApplicationSource(ctx context.Context, req *pb.AddApplicationSourceRequest) (*pb.UpdateResponse, error) {
	log.Printf("Received AddApplicationSource request")
	return &pb.UpdateResponse{StatusCode: 501, Error: "Not implemented"}, nil
}

func (s *InbdServer) RemoveApplicationSource(ctx context.Context, req *pb.RemoveApplicationSourceRequest) (*pb.UpdateResponse, error) {
	log.Printf("Received RemoveApplicationSource request")
	return &pb.UpdateResponse{StatusCode: 501, Error: "Not implemented"}, nil
}
