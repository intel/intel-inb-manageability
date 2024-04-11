package main

import (
	"log"
	"net"
	"time"

	pb "inbc-mock/pb"

	"github.com/google/uuid"
	"google.golang.org/grpc"
)

// server is used to implement inbs.INBSServiceServer.
type server struct {
	pb.UnimplementedINBSServiceServer
}

// Ping implements inbs.INBSServiceServer
func (s *server) Ping(stream pb.INBSService_PingServer) error {
	ctx := stream.Context()

	// Loop until the context is done (connection closed)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			// Sending a Ping to the client
			requestId := uuid.New().String()
			err := stream.Send(&pb.PingRequest{
				RequestId: requestId,
			})
			if err != nil {
				log.Fatalf("Failed to send a ping: %v", err)
			}
			log.Println("Ping sent to client with request ID " + requestId)

			// Receiving and logging PingResponse from client
			response, err := stream.Recv()
			if err != nil {
				log.Fatalf("Failed to receive ping response: %v", err)
			}

			if requestId != response.GetRequestId() {
				log.Fatalf("Response request ID " + response.GetRequestId() + " does not match ping request ID " + requestId)
			}

			log.Println("Received ping response from client with request ID " + response.GetRequestId())

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
	s := grpc.NewServer()
	pb.RegisterINBSServiceServer(s, &server{})
	log.Printf("Server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
