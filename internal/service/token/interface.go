package token

import (
	"context"

	"pinstack-auth-service/internal/auth"
)

type Service interface {
	Login(ctx context.Context, email, password string) (*auth.TokenPair, error)
	Register(ctx context.Context, email, password string) (*auth.TokenPair, error)
	Refresh(ctx context.Context, refreshToken string) (*auth.TokenPair, error)
	Logout(ctx context.Context, refreshToken string) error
}
