package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	pb "inbs-mock/pb"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// server is used to implement inbs.INBSSBServiceServer.
type server struct {
	pb.UnimplementedINBSSBServiceServer
}

type loggingListener struct {
	net.Listener
}

func (l *loggingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		log.Printf("Failed to accept connection: %v", err)
	} else {
		log.Printf("Accepted new connection from %v", conn.RemoteAddr())
	}
	return conn, err
}

func authStreamInterceptor(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	md, ok := metadata.FromIncomingContext(stream.Context())
	if !ok {
		log.Print("Missing metadata from client")
		return status.Errorf(codes.InvalidArgument, "Missing metadata")
	}

	nodeid, ok := md["node-id"]
	if !ok || len(nodeid) == 0 {
		log.Print("Missing node-id from metadata")
		return status.Errorf(codes.Unauthenticated, "Missing node-id in client metadata")
	}

	token, ok := md["token"]
	if !ok || len(token) == 0 || token[0] != "good_token" { // Replace with your expected token.
		log.Print("Invalid token given by client, or token missing")
		return status.Errorf(codes.Unauthenticated, "invalid token")
	}

	// If the metadata is valid, proceed with handling the stream
	err := handler(srv, stream)
	if err != nil {
		log.Printf("Error handling stream: %v", err)
	}
	return err
}

func sendUpdateScheduledTasksRequestsToClient(stream pb.INBSSBService_HandleINBMCommandServer) error {
	requestId := uuid.New().String()
	err := stream.Send(&pb.HandleINBMCommandRequest{
		RequestId: requestId,
		Request: &pb.HandleINBMCommandRequest_UpdateScheduledTasksRequest{
			UpdateScheduledTasksRequest: &pb.UpdateScheduledTasksRequest{
				Tasks: []*pb.ScheduledTask{
					&pb.ScheduledTask{
						Operation: &pb.Operation{
							PreOperations:  []*pb.PreOperation{},
							PostOperations: []*pb.PostOperation{},
							OperationType: &pb.Operation_UpdateSystemSoftwareRequest{
								UpdateSystemSoftwareRequest: &pb.UpdateSystemSoftwareRequest{
									Url:         &pb.Url{},
									ReleaseDate: nil,
									Mode: &pb.DownloadMode{
										Mode: pb.DownloadMode_MODE_DOWNLOAD_ONLY,
									},
									DoNotReboot: true,
									PackageList: []string{},
								},
							},
						},
						Schedules: []*pb.Schedule{
							&pb.Schedule{
								Schedule: &pb.Schedule_SingleSchedule{
									SingleSchedule: &pb.SingleSchedule{
										StartTime: &timestamppb.Timestamp{
											Seconds: 1234,
										},
										EndTime: &timestamppb.Timestamp{
											Seconds: 5678,
										},
									},
								},
							},
						},
					},
				},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to send a update scheduled tasks request: %w", err)
	}
	log.Println("Update scheduled tasks request sent to client with request ID " + requestId)

	// Receiving and logging INBMResponse from client
	response, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("failed to receive client response: %w", err)
	}

	if requestId != response.GetRequestId() {
		return errors.New("Response request ID " + response.GetRequestId() + " does not match request ID " + requestId)
	}
	// check that the response payload is a ping type
	if _, ok := response.GetResponse().(*pb.HandleINBMCommandResponse_UpdateScheduledTasksResponse); !ok {
		return errors.New("response payload is not an UpdateScheduledTasksResponse")
	}

	log.Println("Received response from client with request ID " + response.GetRequestId())

	return nil
}

func sendPingToClient(stream pb.INBSSBService_HandleINBMCommandServer) error {
	requestId := uuid.New().String()
	err := stream.Send(&pb.HandleINBMCommandRequest{
		RequestId: requestId,
		Request:   &pb.HandleINBMCommandRequest_PingRequest{},
	})
	if err != nil {
		return fmt.Errorf("failed to send a ping: %w", err)
	}
	log.Println("Ping sent to client with request ID " + requestId)

	// Receiving and logging INBMResponse from client
	response, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("failed to receive INBM response: %w", err)
	}

	if requestId != response.GetRequestId() {
		return errors.New("response request ID " + response.GetRequestId() + " does not match request ID " + requestId)
	}
	// check that the response payload is a ping type
	if _, ok := response.GetResponse().(*pb.HandleINBMCommandResponse_PingResponse); !ok {
		return errors.New("response payload is not a PingResponseData")
	}

	log.Println("Received response from client with request ID " + response.GetRequestId())

	return nil
}

func (s *server) HandleINBMCommand(stream pb.INBSSBService_HandleINBMCommandServer) error {
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

	// Send a single INBM schedule command to the client
	err := sendUpdateScheduledTasksRequestsToClient(stream)
	if err != nil {
		log.Fatalf("Failed to send SetScheduleRequest to client: %v", err)
	}

	// Loop until the context is done (connection closed)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			// Sending a Ping to the client
			err := sendPingToClient(stream)
			if err != nil {
				log.Fatalf("Failed to send ping to client: %v", err)
			}
			// Wait for a second before next ping
			time.Sleep(1 * time.Second)
		}
	}
}

func main() {
	secure := flag.Bool("secure", false, "Enable secure mode with TLS")
	certFile := flag.String("cert", "server.crt", "Path to the server TLS certificate file")
	keyFile := flag.String("key", "server.key", "Path to the server TLS key file")
	flag.Parse()

	lis, err := net.Listen("tcp", ":5002")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	loggingLis := &loggingListener{Listener: lis}

	var opts []grpc.ServerOption
	if *secure {
		// Set up TLS
		certificate, err := tls.LoadX509KeyPair(*certFile, *keyFile)
		if err != nil {
			log.Fatalf("could not load server key pair: %s", err)
		}
		certPool := x509.NewCertPool()
		ca, err := os.ReadFile(*certFile) // Assuming the certificate file includes the CA too
		if err != nil {
			log.Fatalf("could not read CA certificate: %s", err)
		}
		if !certPool.AppendCertsFromPEM(ca) {
			log.Fatalf("failed to append CA certs")
		}

		creds := credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{certificate},
			ClientAuth:   tls.NoClientCert,
		})
		opts = append(opts, grpc.Creds(creds))
		opts = append(opts, grpc.StreamInterceptor(authStreamInterceptor))
	}

	s := grpc.NewServer(opts...)
	pb.RegisterINBSSBServiceServer(s, &server{})
	log.Printf("Server listening at %v", lis.Addr())
	if err := s.Serve(loggingLis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
