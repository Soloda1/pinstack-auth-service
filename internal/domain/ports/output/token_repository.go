package output

import (
	"context"
	"time"

	"pinstack-auth-service/internal/domain/models"
)

//go:generate mockery --name TokenRepository --dir . --output ../../../../mocks --outpkg mocks --with-expecter
type TokenRepository interface {
	CreateRefreshToken(ctx context.Context, token *models.RefreshToken) error
	GetRefreshToken(ctx context.Context, token string) (*models.RefreshToken, error)
	GetRefreshTokenByJTI(ctx context.Context, jti string) (*models.RefreshToken, error)
	DeleteRefreshToken(ctx context.Context, token string) error
	DeleteRefreshTokenByJTI(ctx context.Context, jti string) error
	DeleteUserRefreshTokens(ctx context.Context, userID int64) error
	DeleteExpiredTokens(ctx context.Context, before time.Time) error
}
