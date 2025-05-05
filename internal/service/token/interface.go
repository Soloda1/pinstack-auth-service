package auth_service

import (
	"context"
	"pinstack-auth-service/internal/model"

	"pinstack-auth-service/internal/auth"
)

type Service interface {
	Login(ctx context.Context, login, password string) (*auth.TokenPair, error)
	Register(ctx context.Context, user *model.User) (*auth.TokenPair, error)
	Refresh(ctx context.Context, refreshToken string) (*auth.TokenPair, error)
	Logout(ctx context.Context, refreshToken string) error
}
