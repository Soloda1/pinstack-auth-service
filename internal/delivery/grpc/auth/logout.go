package auth_grpc

import (
	"context"
	"github.com/soloda1/pinstack-proto-definitions/custom_errors"

	pb "github.com/soloda1/pinstack-proto-definitions/gen/go/pinstack-proto-definitions/auth/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

type LogoutRequest struct {
	RefreshToken string `validate:"required"`
}

func (s *AuthGRPCService) Logout(ctx context.Context, req *pb.LogoutRequest) (*emptypb.Empty, error) {
	s.log.Info("Logout attempt")

	input := LogoutRequest{
		RefreshToken: req.RefreshToken,
	}
	if err := validate.Struct(input); err != nil {
		s.log.Warn("Invalid logout request", "error", err)
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	err := s.tokenService.Logout(ctx, req.RefreshToken)
	if err != nil {
		switch err {
		case custom_errors.ErrInvalidToken:
			s.log.Warn("Invalid token during logout")
			return nil, status.Error(codes.InvalidArgument, err.Error())
		default:
			s.log.Error("Logout failed", "error", err)
			return nil, status.Error(codes.Internal, err.Error())
		}
	}

	s.log.Info("Logout successful")
	return &emptypb.Empty{}, nil
}
