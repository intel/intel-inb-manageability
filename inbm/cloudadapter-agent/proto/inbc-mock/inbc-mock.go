package main

import (
	"log"
	"net"
	"time"

	pb "inbc-mock/pb"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// server is used to implement inbs.INBSSBServiceServer.
type server struct {
	pb.UnimplementedINBSSBServiceServer
}

func authStreamInterceptor(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	md, ok := metadata.FromIncomingContext(stream.Context())
	if !ok {
		log.Print("Missing metadata from client")
		return status.Errorf(codes.InvalidArgument, "Missing metadata")
	}

	token, ok := md["token"]
	if !ok || len(token) == 0 || token[0] != "good_token" { // Replace with your expected token.
		log.Print("Invalid token given by client: " + token[0])
		return status.Errorf(codes.Unauthenticated, "invalid token")
	}

	// If the metadata is valid, proceed with handling the stream
	return handler(srv, stream)
}

func (s *server) INBMCommand(stream pb.INBSSBService_INBMCommandServer) error {
	ctx := stream.Context()

	// Extract metadata from the context
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		log.Fatalf("Failed to retrieve metadata")
		return status.Errorf(codes.InvalidArgument, "Missing metadata")
	}

	// Retrieve the inband-id from metadata
	nodeIDVals, ok := md["node-id"]
	if !ok || len(nodeIDVals) == 0 {
		log.Fatalf("node-id is required in metadata")
		return status.Errorf(codes.Unauthenticated, "node-id is required")
	}
	nodeID := nodeIDVals[0] // Using the first value

	log.Printf("Received connection with inband-id: %s", nodeID)

	// Loop until the context is done (connection closed)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			// Sending a Ping to the client
			requestId := uuid.New().String()
			err := stream.Send(&pb.INBMRequest{
				RequestId: requestId,
				Payload: &pb.INBMRequest_PingRequest{
					PingRequest: &pb.PingRequest{},
				},
			})
			if err != nil {
				log.Fatalf("Failed to send a ping: %v", err)
			}
			log.Println("Ping sent to client with request ID " + requestId)

			// Receiving and logging INBMResponse from client
			response, err := stream.Recv()
			if err != nil {
				log.Fatalf("Failed to receive INBM response: %v", err)
			}

			if requestId != response.GetRequestId() {
				log.Fatalf("Response request ID " + response.GetRequestId() + " does not match request ID " + requestId)
			}
			// check that the response payload is a ping type
			if _, ok := response.GetPayload().(*pb.INBMResponse_PingResponse); !ok {
				log.Fatalf("Response payload is not a PingResponse")
			}

			log.Println("Received response from client with request ID " + response.GetRequestId())

			// Wait for a second before next ping
			time.Sleep(1 * time.Second)
		}
	}
}

func main() {
	lis, err := net.Listen("tcp", ":5678")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	opts := []grpc.ServerOption{
		grpc.StreamInterceptor(authStreamInterceptor),
	}
	s := grpc.NewServer(opts...)
	pb.RegisterINBSSBServiceServer(s, &server{})
	log.Printf("Server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
