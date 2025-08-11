package auth_grpc

import (
	"context"
	"github.com/soloda1/pinstack-proto-definitions/custom_errors"

	pb "github.com/soloda1/pinstack-proto-definitions/gen/go/pinstack-proto-definitions/auth/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type LoginRequest struct {
	Login    string `validate:"required"`
	Password string `validate:"required"`
}

func (s *AuthGRPCService) Login(ctx context.Context, req *pb.LoginRequest) (*pb.TokenPair, error) {
	s.log.Info("Login attempt", "login", req.Login)

	input := LoginRequest{
		Login:    req.Login,
		Password: req.Password,
	}
	if err := validate.Struct(input); err != nil {
		s.log.Warn("Invalid login request", "error", err)
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	tokens, err := s.tokenService.Login(ctx, req.Login, req.Password)
	if err != nil {
		switch err {
		case custom_errors.ErrUserNotFound:
			s.log.Warn("User not found", "login", req.Login)
			return nil, status.Error(codes.NotFound, err.Error())
		case custom_errors.ErrInvalidPassword:
			s.log.Warn("Invalid password", "login", req.Login)
			return nil, status.Error(codes.InvalidArgument, err.Error())
		default:
			s.log.Error("Login failed", "error", err, "login", req.Login)
			return nil, status.Error(codes.Internal, err.Error())
		}
	}

	s.log.Info("Login successful", "login", req.Login)
	return &pb.TokenPair{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}, nil
}
