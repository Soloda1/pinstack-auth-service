package auth_grpc

import (
	input "pinstack-auth-service/internal/domain/ports"
	"pinstack-auth-service/internal/infrastructure/logger"

	"github.com/go-playground/validator/v10"
	pb "github.com/soloda1/pinstack-proto-definitions/gen/go/pinstack-proto-definitions/auth/v1"
)

var validate = validator.New()

type AuthGRPCService struct {
	pb.UnimplementedAuthServiceServer
	tokenService input.TokenService
	log          *logger.Logger
}

func NewAuthGRPCService(tokenService input.TokenService, log *logger.Logger) *AuthGRPCService {
	return &AuthGRPCService{
		tokenService: tokenService,
		log:          log,
	}
}
