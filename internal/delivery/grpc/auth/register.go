package auth_grpc

import (
	"context"
	"errors"
	"log/slog"
	"pinstack-auth-service/internal/custom_errors"
	"pinstack-auth-service/internal/model"
	"pinstack-auth-service/internal/utils"

	pb "github.com/soloda1/pinstack-proto-definitions/gen/go/pinstack-proto-definitions/auth/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type RegisterRequest struct {
	Username  string `validate:"required,min=3"`
	Email     string `validate:"required,email"`
	Password  string `validate:"required,min=8"`
	FullName  string `validate:"omitempty,min=3"`
	Bio       string `validate:"omitempty,min=8"`
	AvatarUrl string `validate:"omitempty,min=8"`
}

func (s *AuthGRPCService) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.TokenPair, error) {
	s.log.Info("Register attempt", slog.Any("req", req))

	input := RegisterRequest{
		Username:  req.Username,
		Email:     req.Email,
		Password:  req.Password,
		FullName:  utils.StrPtrToStr(req.FullName),
		Bio:       utils.StrPtrToStr(req.Bio),
		AvatarUrl: utils.StrPtrToStr(req.AvatarUrl),
	}
	if err := validate.Struct(input); err != nil {
		s.log.Warn("Invalid register request", "error", err, "username", req.Username)
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	user := &model.User{
		Username:  req.Username,
		Email:     req.Email,
		Password:  req.Password,
		FullName:  req.FullName,
		Bio:       req.Bio,
		AvatarURL: req.AvatarUrl,
	}

	tokens, err := s.tokenService.Register(ctx, user)
	if err != nil {
		switch {
		case errors.Is(err, custom_errors.ErrInvalidInput):
			s.log.Warn("Invalid input data", "error", err, "username", req.Username)
			return nil, status.Error(codes.InvalidArgument, err.Error())
		case errors.Is(err, custom_errors.ErrInvalidEmail):
			s.log.Warn("Invalid email format", "error", err, "email", req.Email)
			return nil, status.Error(codes.InvalidArgument, err.Error())
		case errors.Is(err, custom_errors.ErrInvalidPassword):
			s.log.Warn("Invalid password", "error", err, "username", req.Username)
			return nil, status.Error(codes.InvalidArgument, err.Error())
		case errors.Is(err, custom_errors.ErrUsernameExists):
			s.log.Warn("Username already exists", "username", req.Username)
			return nil, status.Error(codes.AlreadyExists, err.Error())
		case errors.Is(err, custom_errors.ErrEmailExists):
			s.log.Warn("Email already exists", "email", req.Email)
			return nil, status.Error(codes.AlreadyExists, err.Error())
		case errors.Is(err, custom_errors.ErrInvalidUsername):
			s.log.Warn("Invalid username", "error", err, "username", req.Username)
			return nil, status.Error(codes.InvalidArgument, err.Error())
		case errors.Is(err, custom_errors.ErrExternalServiceError):
			s.log.Error("External service error during registration", "error", err, "username", req.Username)
			return nil, status.Error(codes.Unavailable, err.Error())
		case errors.Is(err, custom_errors.ErrOperationNotAllowed):
			s.log.Error("Operation not allowed during registration", "error", err, "username", req.Username)
			return nil, status.Error(codes.PermissionDenied, err.Error())
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
