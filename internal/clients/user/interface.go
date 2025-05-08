package user_client

import (
	"context"
	"pinstack-auth-service/internal/model"
)

type UserClient interface {
	GetUser(ctx context.Context, id int64) (*model.User, error)
	CreateUser(ctx context.Context, user *model.User) (*model.User, error)
	GetUserByUsername(ctx context.Context, username string) (*model.User, error)
	GetUserByEmail(ctx context.Context, email string) (*model.User, error)
	UpdatePassword(ctx context.Context, id int64, oldPassword, newPassword string) error
}
