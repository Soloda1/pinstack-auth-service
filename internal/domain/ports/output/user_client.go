package output

import (
	"context"
	"pinstack-auth-service/internal/domain/models"
)

//go:generate mockery --name UserClient --dir . --output ../../../mocks --outpkg mocks --with-expecter
type UserClient interface {
	GetUser(ctx context.Context, id int64) (*models.User, error)
	CreateUser(ctx context.Context, user *models.User) (*models.User, error)
	GetUserByUsername(ctx context.Context, username string) (*models.User, error)
	GetUserByEmail(ctx context.Context, email string) (*models.User, error)
	UpdatePassword(ctx context.Context, id int64, oldPassword, newPassword string) error
}
