package auth_grpc

import (
	"github.com/go-playground/validator/v10"
	pb "github.com/soloda1/pinstack-proto-definitions/gen/go/pinstack-proto-definitions/auth/v1"
	"pinstack-auth-service/internal/logger"
	"pinstack-auth-service/internal/service/token"
)

var validate = validator.New()

type AuthGRPCService struct {
	pb.UnimplementedAuthServiceServer
	tokenService auth_service.TokenService
	log          *logger.Logger
}

func NewAuthGRPCService(tokenService auth_service.TokenService, log *logger.Logger) *AuthGRPCService {
	return &AuthGRPCService{
		tokenService: tokenService,
		log:          log,
	}
}
