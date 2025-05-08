package auth_grpc

import (
	"context"
	"pinstack-auth-service/internal/custom_errors"
	"pinstack-auth-service/internal/model"

	pb "github.com/soloda1/pinstack-proto-definitions/gen/go/pinstack-proto-definitions/auth/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type RegisterRequest struct {
	Username string `validate:"required,min=3"`
	Email    string `validate:"required,email"`
	Password string `validate:"required,min=8"`
}

func (s *AuthGRPCService) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.TokenPair, error) {
	s.log.Info("Register attempt", "username", req.Username, "email", req.Email)

	input := RegisterRequest{
		Username: req.Username,
		Email:    req.Email,
		Password: req.Password,
	}
	if err := validate.Struct(input); err != nil {
		s.log.Warn("Invalid register request", "error", err, "username", req.Username)
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	user := &model.User{
		Username: req.Username,
		Email:    req.Email,
		Password: req.Password,
	}

	tokens, err := s.tokenService.Register(ctx, user)
	if err != nil {
		switch err {
		case custom_errors.ErrUserAlreadyExists:
			s.log.Warn("User already exists", "username", req.Username, "email", req.Email)
			return nil, status.Error(codes.AlreadyExists, err.Error())
		case custom_errors.ErrInvalidUsername, custom_errors.ErrInvalidEmail, custom_errors.ErrInvalidPassword:
			s.log.Warn("Invalid user data", "error", err, "username", req.Username)
			return nil, status.Error(codes.InvalidArgument, err.Error())
		default:
			s.log.Error("Registration failed", "error", err, "username", req.Username)
			return nil, status.Error(codes.Internal, err.Error())
		}
	}

	s.log.Info("Registration successful", "username", req.Username)
	return &pb.TokenPair{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}, nil
}
