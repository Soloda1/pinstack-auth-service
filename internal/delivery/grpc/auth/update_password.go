package auth_grpc

import (
	"context"
	"github.com/soloda1/pinstack-proto-definitions/custom_errors"

	pb "github.com/soloda1/pinstack-proto-definitions/gen/go/pinstack-proto-definitions/auth/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

type UpdatePasswordRequest struct {
	Id          int64  `validate:"required,gt=0"`
	OldPassword string `validate:"required"`
	NewPassword string `validate:"required,min=8"`
}

func (s *AuthGRPCService) UpdatePassword(ctx context.Context, req *pb.UpdatePasswordRequest) (*emptypb.Empty, error) {
	s.log.Info("Update password attempt", "user_id", req.Id)

	input := UpdatePasswordRequest{
		Id:          req.Id,
		OldPassword: req.OldPassword,
		NewPassword: req.NewPassword,
	}
	if err := validate.Struct(input); err != nil {
		s.log.Warn("Invalid update password request", "error", err, "user_id", req.Id)
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	err := s.tokenService.UpdatePassword(ctx, req.Id, req.OldPassword, req.NewPassword)
	if err != nil {
		switch err {
		case custom_errors.ErrUserNotFound:
			s.log.Warn("User not found", "user_id", req.Id)
			return nil, status.Error(codes.NotFound, err.Error())
		case custom_errors.ErrInvalidPassword:
			s.log.Warn("Invalid password", "user_id", req.Id)
			return nil, status.Error(codes.InvalidArgument, err.Error())
		default:
			s.log.Error("Password update failed", "error", err, "user_id", req.Id)
			return nil, status.Error(codes.Internal, err.Error())
		}
	}

	s.log.Info("Password update successful", "user_id", req.Id)
	return &emptypb.Empty{}, nil
}
