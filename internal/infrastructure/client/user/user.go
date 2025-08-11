package user

import (
	"context"
	"log/slog"
	"pinstack-auth-service/internal/domain/models"
	"pinstack-auth-service/internal/domain/ports"

	"github.com/soloda1/pinstack-proto-definitions/custom_errors"

	pb "github.com/soloda1/pinstack-proto-definitions/gen/go/pinstack-proto-definitions/user/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type userClient struct {
	client pb.UserServiceClient
	log    ports.Logger
}

func NewUserClient(conn *grpc.ClientConn, log ports.Logger) ports.UserClient {
	return &userClient{
		client: pb.NewUserServiceClient(conn),
		log:    log,
	}
}

func (u userClient) GetUser(ctx context.Context, id int64) (*models.User, error) {
	u.log.Info("Getting user by ID", slog.Int64("id", id))
	resp, err := u.client.GetUser(ctx, &pb.GetUserRequest{Id: id})
	if err != nil {
		u.log.Error("Error getting user", slog.String("error", err.Error()), slog.Int64("id", id))
		if st, ok := status.FromError(err); ok {
			if st.Code() == codes.NotFound {
				return nil, custom_errors.ErrUserNotFound
			}
		}
		return nil, custom_errors.ErrExternalServiceError
	}
	u.log.Info("Successfully got user", slog.Int64("id", id))
	return models.UserFromProto(resp), nil
}

func (u userClient) CreateUser(ctx context.Context, user *models.User) (*models.User, error) {
	u.log.Info("Creating new user", slog.Any("user", user))
	resp, err := u.client.CreateUser(ctx, &pb.CreateUserRequest{
		Username:  user.Username,
		Email:     user.Email,
		Password:  user.Password,
		FullName:  user.FullName,
		Bio:       user.Bio,
		AvatarUrl: user.AvatarURL,
	})
	if err != nil {
		u.log.Error("Failed to create user", slog.String("username", user.Username), slog.String("error", err.Error()))
		if st, ok := status.FromError(err); ok {
			switch st.Code() {
			case codes.AlreadyExists:
				switch st.Message() {
				case "username already exists":
					return nil, custom_errors.ErrUsernameExists
				case "email already exists":
					return nil, custom_errors.ErrEmailExists
				}
			case codes.InvalidArgument:
				switch st.Message() {
				case "invalid username":
					return nil, custom_errors.ErrInvalidUsername
				case "invalid email":
					return nil, custom_errors.ErrInvalidEmail
				case "invalid password":
					return nil, custom_errors.ErrInvalidPassword
				}
			}
		}
		return nil, custom_errors.ErrExternalServiceError
	}
	u.log.Info("Successfully created user", slog.Int64("id", resp.Id))
	return models.UserFromProto(resp), nil
}

func (u userClient) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	u.log.Info("Getting user by username", slog.String("username", username))
	resp, err := u.client.GetUserByUsername(ctx, &pb.GetUserByUsernameRequest{Username: username})
	if err != nil {
		u.log.Error("Failed to get user by username", slog.String("username", username), slog.String("error", err.Error()))
		if st, ok := status.FromError(err); ok {
			if st.Code() == codes.NotFound {
				return nil, custom_errors.ErrUserNotFound
			}
		}
		return nil, custom_errors.ErrExternalServiceError
	}
	u.log.Info("Successfully got user by username", slog.String("username", username))
	return models.UserFromProto(resp), nil
}

func (u userClient) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	u.log.Info("Getting user by email", slog.String("email", email))
	resp, err := u.client.GetUserByEmail(ctx, &pb.GetUserByEmailRequest{Email: email})
	if err != nil {
		u.log.Error("Failed to get user by email", slog.String("email", email), slog.String("error", err.Error()))
		if st, ok := status.FromError(err); ok {
			if st.Code() == codes.NotFound {
				return nil, custom_errors.ErrUserNotFound
			}
		}
		return nil, custom_errors.ErrExternalServiceError
	}
	u.log.Info("Successfully got user by email", slog.String("email", email))
	return models.UserFromProto(resp), nil
}

func (u userClient) UpdatePassword(ctx context.Context, id int64, oldPassword, newPassword string) error {
	u.log.Info("Updating user password", slog.Int64("id", id))
	_, err := u.client.UpdatePassword(ctx, &pb.UpdatePasswordRequest{
		Id:          id,
		OldPassword: oldPassword,
		NewPassword: newPassword,
	})
	if err != nil {
		u.log.Error("Failed to update password", slog.String("error", err.Error()), slog.Int64("id", id))
		if st, ok := status.FromError(err); ok {
			switch st.Code() {
			case codes.NotFound:
				return custom_errors.ErrUserNotFound
			case codes.InvalidArgument:
				return custom_errors.ErrInvalidPassword
			}
		}
		return custom_errors.ErrExternalServiceError
	}
	u.log.Info("Successfully updated password", slog.Int64("id", id))
	return nil
}
