package user_client

import (
	"context"
	pb "github.com/soloda1/pinstack-proto-definitions/gen/go/pinstack-proto-definitions/user/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"log/slog"
	"pinstack-auth-service/internal/custom_errors"
	"pinstack-auth-service/internal/logger"
	"pinstack-auth-service/internal/model"
)

type userClient struct {
	client pb.UserServiceClient
	log    *logger.Logger
}

func NewUserClient(conn *grpc.ClientConn, log *logger.Logger) UserClient {
	return &userClient{
		client: pb.NewUserServiceClient(conn),
		log:    log,
	}
}

func (u userClient) GetUser(ctx context.Context, id int64) (*model.User, error) {
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
	return model.UserFromProto(resp), nil
}

func (u userClient) CreateUser(ctx context.Context, user *model.User) (*model.User, error) {
	u.log.Info("Creating new user", slog.String("username", user.Username), slog.String("email", user.Email))
	resp, err := u.client.CreateUser(ctx, &pb.CreateUserRequest{
		Username: user.Username,
		Email:    user.Email,
		Password: user.Password,
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
	return model.UserFromProto(resp), nil
}

func (u userClient) GetUserByUsername(ctx context.Context, username string) (*model.User, error) {
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
	return model.UserFromProto(resp), nil
}

func (u userClient) GetUserByEmail(ctx context.Context, email string) (*model.User, error) {
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
	return model.UserFromProto(resp), nil
}
