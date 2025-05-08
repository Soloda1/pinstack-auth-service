package auth_grpc

import (
	"context"
	"pinstack-auth-service/internal/custom_errors"

	pb "github.com/soloda1/pinstack-proto-definitions/gen/go/pinstack-proto-definitions/auth/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type RefreshRequest struct {
	RefreshToken string `validate:"required"`
}

func (s *AuthGRPCService) Refresh(ctx context.Context, req *pb.RefreshRequest) (*pb.TokenPair, error) {
	s.log.Info("Refresh token attempt")

	input := RefreshRequest{
		RefreshToken: req.RefreshToken,
	}
	if err := validate.Struct(input); err != nil {
		s.log.Warn("Invalid refresh request", "error", err)
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	tokens, err := s.tokenService.Refresh(ctx, req.RefreshToken)
	if err != nil {
		switch err {
		case custom_errors.ErrExpiredToken:
			s.log.Warn("Token expired")
			return nil, status.Error(codes.Unauthenticated, err.Error())
		case custom_errors.ErrInvalidToken:
			s.log.Warn("Invalid token")
			return nil, status.Error(codes.InvalidArgument, err.Error())
		case custom_errors.ErrUserNotFound:
			s.log.Warn("User not found for token")
			return nil, status.Error(codes.NotFound, err.Error())
		case custom_errors.ErrOperationNotAllowed:
			s.log.Warn("Operation not allowed", "error", err)
			return nil, status.Error(codes.PermissionDenied, err.Error())
		default:
			s.log.Error("Token refresh failed", "error", err)
			return nil, status.Error(codes.Internal, err.Error())
		}
	}

	s.log.Info("Token refresh successful")
	return &pb.TokenPair{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}, nil
}
