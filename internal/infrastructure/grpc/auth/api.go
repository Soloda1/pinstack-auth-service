package auth_grpc

import (
	ports "pinstack-auth-service/internal/domain/ports"

	"github.com/go-playground/validator/v10"
	pb "github.com/soloda1/pinstack-proto-definitions/gen/go/pinstack-proto-definitions/auth/v1"
)

var validate = validator.New()

type AuthGRPCService struct {
	pb.UnimplementedAuthServiceServer
	tokenService ports.TokenService
	log          ports.Logger
}

func NewAuthGRPCService(tokenService ports.TokenService, log ports.Logger) *AuthGRPCService {
	return &AuthGRPCService{
		tokenService: tokenService,
		log:          log,
	}
}
