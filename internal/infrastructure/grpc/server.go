package delivery_grpc

import (
	"fmt"
	"log/slog"
	"net"
	ports "pinstack-auth-service/internal/domain/ports"
	auth_grpc "pinstack-auth-service/internal/infrastructure/grpc/auth"
	"pinstack-auth-service/internal/infrastructure/middleware"
	"runtime/debug"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_recovery "github.com/grpc-ecosystem/go-grpc-middleware/recovery"
	pb "github.com/soloda1/pinstack-proto-definitions/gen/go/pinstack-proto-definitions/auth/v1"
	"google.golang.org/grpc"
)

type Server struct {
	authGRPCService *auth_grpc.AuthGRPCService
	server          *grpc.Server
	address         string
	port            int
	log             ports.Logger
}

func NewServer(grpcServer *auth_grpc.AuthGRPCService, address string, port int, log ports.Logger) *Server {
	return &Server{
		authGRPCService: grpcServer,
		address:         address,
		port:            port,
		log:             log,
	}
}

func (s *Server) Run() error {
	address := fmt.Sprintf("%s:%d", s.address, s.port)
	lis, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("failed to listen: %v", err)
	}

	opts := []grpc_recovery.Option{
		grpc_recovery.WithRecoveryHandler(func(p interface{}) (err error) {
			s.log.Error("panic recovered", slog.Any("panic", p), slog.String("stack", string(debug.Stack())))
			return status.Errorf(codes.Internal, "internal server error")
		}),
	}

	s.server = grpc.NewServer(
		grpc.UnaryInterceptor(grpc_middleware.ChainUnaryServer(
			middleware.UnaryLoggerInterceptor(s.log),
			grpc_recovery.UnaryServerInterceptor(opts...),
		)),
	)

	pb.RegisterAuthServiceServer(s.server, s.authGRPCService)

	s.log.Info("Starting gRPC server", slog.Int("ports", s.port))
	return s.server.Serve(lis)
}

func (s *Server) Shutdown() error {
	if s.server != nil {
		s.server.GracefulStop()
	}
	return nil
}
