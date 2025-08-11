package ports

import "pinstack-auth-service/internal/domain/models"

//go:generate mockery --name TokenManager --dir . --output ../../../mocks --outpkg mocks --with-expecter
type TokenManager interface {
	NewJWT(userID int64) (*models.TokenPair, error)
	ParseRefreshToken(tokenString string) (*models.TokenClaims, error)
}
