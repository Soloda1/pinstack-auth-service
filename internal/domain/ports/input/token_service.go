package input

import (
	"context"
	"pinstack-auth-service/internal/domain/models"
)

//go:generate mockery --name TokenService --dir . --output ../../../mocks --outpkg mocks --with-expecter
type TokenService interface {
	Login(ctx context.Context, login, password string) (*models.TokenPair, error)
	Register(ctx context.Context, user *models.User) (*models.TokenPair, error)
	Refresh(ctx context.Context, refreshToken string) (*models.TokenPair, error)
	Logout(ctx context.Context, refreshToken string) error
	UpdatePassword(ctx context.Context, id int64, oldPassword, newPassword string) error
}
