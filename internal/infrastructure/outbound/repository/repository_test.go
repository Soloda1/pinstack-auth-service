package repository_test

import (
	"context"
	"testing"
	"time"

	"github.com/soloda1/pinstack-proto-definitions/custom_errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"pinstack-auth-service/internal/domain/models"
	auth_repository "pinstack-auth-service/internal/domain/ports/output"
	"pinstack-auth-service/internal/infrastructure/logger"
	memory "pinstack-auth-service/internal/infrastructure/outbound/repository/memory"
)

func setupTest(t *testing.T) (auth_repository.TokenRepository, func()) {
	log := logger.New("test")
	repo := memory.NewTokenRepository(log)
	return repo, func() {}
}

func TestCreateRefreshToken(t *testing.T) {
	repo, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	token := &models.RefreshToken{
		UserID:    1,
		Token:     "test-token",
		JTI:       "test-jti",
		ExpiresAt: time.Now().Add(time.Hour),
	}

	err := repo.CreateRefreshToken(ctx, token)
	require.NoError(t, err)
	assert.NotZero(t, token.ID)
	assert.False(t, token.CreatedAt.IsZero())
}

func TestGetRefreshToken(t *testing.T) {
	repo, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	token := &models.RefreshToken{
		UserID:    1,
		Token:     "test-token",
		JTI:       "test-jti",
		ExpiresAt: time.Now().Add(time.Hour),
	}

	err := repo.CreateRefreshToken(ctx, token)
	require.NoError(t, err)

	found, err := repo.GetRefreshToken(ctx, token.Token)
	require.NoError(t, err)
	assert.Equal(t, token.ID, found.ID)
	assert.Equal(t, token.UserID, found.UserID)
	assert.Equal(t, token.Token, found.Token)
	assert.Equal(t, token.JTI, found.JTI)
	assert.Equal(t, token.ExpiresAt, found.ExpiresAt)
	assert.Equal(t, token.CreatedAt, found.CreatedAt)

	_, err = repo.GetRefreshToken(ctx, "non-existent")
	assert.ErrorIs(t, err, custom_errors.ErrInvalidToken)
}

func TestGetRefreshTokenByJTI(t *testing.T) {
	repo, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	token := &models.RefreshToken{
		UserID:    1,
		Token:     "test-token",
		JTI:       "test-jti",
		ExpiresAt: time.Now().Add(time.Hour),
	}

	err := repo.CreateRefreshToken(ctx, token)
	require.NoError(t, err)

	found, err := repo.GetRefreshTokenByJTI(ctx, token.JTI)
	require.NoError(t, err)
	assert.Equal(t, token.ID, found.ID)
	assert.Equal(t, token.UserID, found.UserID)
	assert.Equal(t, token.Token, found.Token)
	assert.Equal(t, token.JTI, found.JTI)
	assert.Equal(t, token.ExpiresAt, found.ExpiresAt)
	assert.Equal(t, token.CreatedAt, found.CreatedAt)

	_, err = repo.GetRefreshTokenByJTI(ctx, "non-existent")
	assert.ErrorIs(t, err, custom_errors.ErrInvalidToken)
}

func TestDeleteRefreshToken(t *testing.T) {
	repo, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	token := &models.RefreshToken{
		UserID:    1,
		Token:     "test-token",
		JTI:       "test-jti",
		ExpiresAt: time.Now().Add(time.Hour),
	}

	err := repo.CreateRefreshToken(ctx, token)
	require.NoError(t, err)

	err = repo.DeleteRefreshToken(ctx, token.Token)
	require.NoError(t, err)

	_, err = repo.GetRefreshToken(ctx, token.Token)
	assert.ErrorIs(t, err, custom_errors.ErrInvalidToken)

	err = repo.DeleteRefreshToken(ctx, "non-existent")
	assert.ErrorIs(t, err, custom_errors.ErrInvalidToken)
}

func TestDeleteRefreshTokenByJTI(t *testing.T) {
	repo, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	token := &models.RefreshToken{
		UserID:    1,
		Token:     "test-token",
		JTI:       "test-jti",
		ExpiresAt: time.Now().Add(time.Hour),
	}

	err := repo.CreateRefreshToken(ctx, token)
	require.NoError(t, err)

	err = repo.DeleteRefreshTokenByJTI(ctx, token.JTI)
	require.NoError(t, err)

	_, err = repo.GetRefreshTokenByJTI(ctx, token.JTI)
	assert.ErrorIs(t, err, custom_errors.ErrInvalidToken)

	err = repo.DeleteRefreshTokenByJTI(ctx, "non-existent")
	assert.ErrorIs(t, err, custom_errors.ErrInvalidToken)
}

func TestDeleteUserRefreshTokens(t *testing.T) {
	repo, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	token1 := &models.RefreshToken{
		UserID:    1,
		Token:     "test-token-1",
		JTI:       "test-jti-1",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	token2 := &models.RefreshToken{
		UserID:    1,
		Token:     "test-token-2",
		JTI:       "test-jti-2",
		ExpiresAt: time.Now().Add(time.Hour),
	}

	err := repo.CreateRefreshToken(ctx, token1)
	require.NoError(t, err)
	err = repo.CreateRefreshToken(ctx, token2)
	require.NoError(t, err)

	err = repo.DeleteUserRefreshTokens(ctx, 1)
	require.NoError(t, err)

	_, err = repo.GetRefreshToken(ctx, token1.Token)
	assert.ErrorIs(t, err, custom_errors.ErrInvalidToken)
	_, err = repo.GetRefreshToken(ctx, token2.Token)
	assert.ErrorIs(t, err, custom_errors.ErrInvalidToken)
}

func TestDeleteExpiredTokens(t *testing.T) {
	repo, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	validToken := &models.RefreshToken{
		UserID:    1,
		Token:     "valid-token",
		JTI:       "valid-jti",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	expiredToken := &models.RefreshToken{
		UserID:    2,
		Token:     "expired-token",
		JTI:       "expired-jti",
		ExpiresAt: time.Now().Add(-time.Hour),
	}

	err := repo.CreateRefreshToken(ctx, validToken)
	require.NoError(t, err)
	err = repo.CreateRefreshToken(ctx, expiredToken)
	require.NoError(t, err)

	err = repo.DeleteExpiredTokens(ctx, time.Now())
	require.NoError(t, err)

	_, err = repo.GetRefreshToken(ctx, validToken.Token)
	require.NoError(t, err)
	_, err = repo.GetRefreshToken(ctx, expiredToken.Token)
	assert.ErrorIs(t, err, custom_errors.ErrInvalidToken)
}

func TestCreateRefreshTokenWithDuplicateJTI(t *testing.T) {
	repo, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	token1 := &models.RefreshToken{
		UserID:    1,
		Token:     "test-token-1",
		JTI:       "test-jti",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	token2 := &models.RefreshToken{
		UserID:    2,
		Token:     "test-token-2",
		JTI:       "test-jti", // Тот же JTI
		ExpiresAt: time.Now().Add(time.Hour),
	}

	err := repo.CreateRefreshToken(ctx, token1)
	require.NoError(t, err)

	err = repo.CreateRefreshToken(ctx, token2)
	assert.Equal(t, custom_errors.ErrOperationNotAllowed.Error(), err.Error())
}

func TestGetExpiredRefreshToken(t *testing.T) {
	repo, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	token := &models.RefreshToken{
		UserID:    1,
		Token:     "test-token",
		JTI:       "test-jti",
		ExpiresAt: time.Now().Add(-time.Hour),
	}

	err := repo.CreateRefreshToken(ctx, token)
	require.NoError(t, err)

	_, err = repo.GetRefreshToken(ctx, token.Token)
	assert.Equal(t, custom_errors.ErrTokenExpired.Error(), err.Error())
}

func TestGetExpiredRefreshTokenByJTI(t *testing.T) {
	repo, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	token := &models.RefreshToken{
		UserID:    1,
		Token:     "test-token",
		JTI:       "test-jti",
		ExpiresAt: time.Now().Add(-time.Hour), // Истекший токен
	}

	err := repo.CreateRefreshToken(ctx, token)
	require.NoError(t, err)

	_, err = repo.GetRefreshTokenByJTI(ctx, token.JTI)
	assert.Equal(t, custom_errors.ErrTokenExpired.Error(), err.Error())
}

func TestDeleteExpiredTokensWithMixedTokens(t *testing.T) {
	repo, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	validToken := &models.RefreshToken{
		UserID:    1,
		Token:     "valid-token",
		JTI:       "valid-jti",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	expiredToken1 := &models.RefreshToken{
		UserID:    2,
		Token:     "expired-token-1",
		JTI:       "expired-jti-1",
		ExpiresAt: time.Now().Add(-time.Hour),
	}
	expiredToken2 := &models.RefreshToken{
		UserID:    3,
		Token:     "expired-token-2",
		JTI:       "expired-jti-2",
		ExpiresAt: time.Now().Add(-2 * time.Hour),
	}

	err := repo.CreateRefreshToken(ctx, validToken)
	require.NoError(t, err)
	err = repo.CreateRefreshToken(ctx, expiredToken1)
	require.NoError(t, err)
	err = repo.CreateRefreshToken(ctx, expiredToken2)
	require.NoError(t, err)

	err = repo.DeleteExpiredTokens(ctx, time.Now())
	require.NoError(t, err)

	// Проверяем, что валидный токен остался
	_, err = repo.GetRefreshToken(ctx, validToken.Token)
	require.NoError(t, err)

	// Проверяем, что истекшие токены удалены
	_, err = repo.GetRefreshToken(ctx, expiredToken1.Token)
	assert.ErrorIs(t, err, custom_errors.ErrInvalidToken)
	_, err = repo.GetRefreshToken(ctx, expiredToken2.Token)
	assert.ErrorIs(t, err, custom_errors.ErrInvalidToken)
}

func TestDeleteUserRefreshTokensWithMixedUsers(t *testing.T) {
	repo, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	user1Token1 := &models.RefreshToken{
		UserID:    1,
		Token:     "user1-token-1",
		JTI:       "user1-jti-1",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	user1Token2 := &models.RefreshToken{
		UserID:    1,
		Token:     "user1-token-2",
		JTI:       "user1-jti-2",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	user2Token := &models.RefreshToken{
		UserID:    2,
		Token:     "user2-token",
		JTI:       "user2-jti",
		ExpiresAt: time.Now().Add(time.Hour),
	}

	err := repo.CreateRefreshToken(ctx, user1Token1)
	require.NoError(t, err)
	err = repo.CreateRefreshToken(ctx, user1Token2)
	require.NoError(t, err)
	err = repo.CreateRefreshToken(ctx, user2Token)
	require.NoError(t, err)

	err = repo.DeleteUserRefreshTokens(ctx, 1)
	require.NoError(t, err)

	_, err = repo.GetRefreshToken(ctx, user1Token1.Token)
	assert.ErrorIs(t, err, custom_errors.ErrInvalidToken)
	_, err = repo.GetRefreshToken(ctx, user1Token2.Token)
	assert.ErrorIs(t, err, custom_errors.ErrInvalidToken)

	_, err = repo.GetRefreshToken(ctx, user2Token.Token)
	require.NoError(t, err)
}

func TestDeleteRefreshTokenByJTIWithMultipleTokens(t *testing.T) {
	repo, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	token1 := &models.RefreshToken{
		UserID:    1,
		Token:     "test-token-1",
		JTI:       "test-jti-1",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	token2 := &models.RefreshToken{
		UserID:    2,
		Token:     "test-token-2",
		JTI:       "test-jti-2",
		ExpiresAt: time.Now().Add(time.Hour),
	}

	err := repo.CreateRefreshToken(ctx, token1)
	require.NoError(t, err)
	err = repo.CreateRefreshToken(ctx, token2)
	require.NoError(t, err)

	err = repo.DeleteRefreshTokenByJTI(ctx, token1.JTI)
	require.NoError(t, err)

	_, err = repo.GetRefreshTokenByJTI(ctx, token1.JTI)
	assert.ErrorIs(t, err, custom_errors.ErrInvalidToken)

	_, err = repo.GetRefreshTokenByJTI(ctx, token2.JTI)
	require.NoError(t, err)
}
