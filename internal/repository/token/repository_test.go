package auth_repository_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"pinstack-auth-service/internal/custom_errors"
	"pinstack-auth-service/internal/logger"
	"pinstack-auth-service/internal/model"
	auth_repository "pinstack-auth-service/internal/repository/token"
	"pinstack-auth-service/internal/repository/token/memory"
)

type mockQuerier struct{}

func (m *mockQuerier) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}

func (m *mockQuerier) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return nil
}

func (m *mockQuerier) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return nil, nil
}

func (m *mockQuerier) Begin(ctx context.Context) (pgx.Tx, error) {
	return nil, nil
}

func (m *mockQuerier) BeginTx(ctx context.Context, txOptions pgx.TxOptions) (pgx.Tx, error) {
	return nil, nil
}

func (m *mockQuerier) CopyFrom(ctx context.Context, tableName pgx.Identifier, columnNames []string, rowSrc pgx.CopyFromSource) (int64, error) {
	return 0, nil
}

func (m *mockQuerier) SendBatch(ctx context.Context, b *pgx.Batch) pgx.BatchResults {
	return nil
}

func setupTest(t *testing.T) (auth_repository.TokenRepository, auth_repository.Querier, func()) {
	log := logger.New("test")
	repo := memory.NewTokenRepository(log)
	q := &mockQuerier{}
	return repo, q, func() {}
}

func TestCreateRefreshToken(t *testing.T) {
	repo, q, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	token := &model.RefreshToken{
		UserID:    1,
		Token:     "test-token",
		JTI:       "test-jti",
		ExpiresAt: time.Now().Add(time.Hour),
	}

	err := repo.CreateRefreshToken(ctx, q, token)
	require.NoError(t, err)
	assert.NotZero(t, token.ID)
	assert.False(t, token.CreatedAt.IsZero())
}

func TestGetRefreshToken(t *testing.T) {
	repo, q, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	token := &model.RefreshToken{
		UserID:    1,
		Token:     "test-token",
		JTI:       "test-jti",
		ExpiresAt: time.Now().Add(time.Hour),
	}

	err := repo.CreateRefreshToken(ctx, q, token)
	require.NoError(t, err)

	found, err := repo.GetRefreshToken(ctx, q, token.Token)
	require.NoError(t, err)
	assert.Equal(t, token.ID, found.ID)
	assert.Equal(t, token.UserID, found.UserID)
	assert.Equal(t, token.Token, found.Token)
	assert.Equal(t, token.JTI, found.JTI)
	assert.Equal(t, token.ExpiresAt, found.ExpiresAt)
	assert.Equal(t, token.CreatedAt, found.CreatedAt)

	_, err = repo.GetRefreshToken(ctx, q, "non-existent")
	assert.ErrorIs(t, err, custom_errors.ErrInvalidToken)
}

func TestGetRefreshTokenByJTI(t *testing.T) {
	repo, q, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	token := &model.RefreshToken{
		UserID:    1,
		Token:     "test-token",
		JTI:       "test-jti",
		ExpiresAt: time.Now().Add(time.Hour),
	}

	err := repo.CreateRefreshToken(ctx, q, token)
	require.NoError(t, err)

	found, err := repo.GetRefreshTokenByJTI(ctx, q, token.JTI)
	require.NoError(t, err)
	assert.Equal(t, token.ID, found.ID)
	assert.Equal(t, token.UserID, found.UserID)
	assert.Equal(t, token.Token, found.Token)
	assert.Equal(t, token.JTI, found.JTI)
	assert.Equal(t, token.ExpiresAt, found.ExpiresAt)
	assert.Equal(t, token.CreatedAt, found.CreatedAt)

	_, err = repo.GetRefreshTokenByJTI(ctx, q, "non-existent")
	assert.ErrorIs(t, err, custom_errors.ErrInvalidToken)
}

func TestDeleteRefreshToken(t *testing.T) {
	repo, q, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	token := &model.RefreshToken{
		UserID:    1,
		Token:     "test-token",
		JTI:       "test-jti",
		ExpiresAt: time.Now().Add(time.Hour),
	}

	err := repo.CreateRefreshToken(ctx, q, token)
	require.NoError(t, err)

	err = repo.DeleteRefreshToken(ctx, q, token.Token)
	require.NoError(t, err)

	_, err = repo.GetRefreshToken(ctx, q, token.Token)
	assert.ErrorIs(t, err, custom_errors.ErrInvalidToken)

	err = repo.DeleteRefreshToken(ctx, q, "non-existent")
	assert.ErrorIs(t, err, custom_errors.ErrInvalidToken)
}

func TestDeleteRefreshTokenByJTI(t *testing.T) {
	repo, q, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	token := &model.RefreshToken{
		UserID:    1,
		Token:     "test-token",
		JTI:       "test-jti",
		ExpiresAt: time.Now().Add(time.Hour),
	}

	err := repo.CreateRefreshToken(ctx, q, token)
	require.NoError(t, err)

	err = repo.DeleteRefreshTokenByJTI(ctx, q, token.JTI)
	require.NoError(t, err)

	_, err = repo.GetRefreshTokenByJTI(ctx, q, token.JTI)
	assert.ErrorIs(t, err, custom_errors.ErrInvalidToken)

	err = repo.DeleteRefreshTokenByJTI(ctx, q, "non-existent")
	assert.ErrorIs(t, err, custom_errors.ErrInvalidToken)
}

func TestDeleteUserRefreshTokens(t *testing.T) {
	repo, q, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	token1 := &model.RefreshToken{
		UserID:    1,
		Token:     "test-token-1",
		JTI:       "test-jti-1",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	token2 := &model.RefreshToken{
		UserID:    1,
		Token:     "test-token-2",
		JTI:       "test-jti-2",
		ExpiresAt: time.Now().Add(time.Hour),
	}

	err := repo.CreateRefreshToken(ctx, q, token1)
	require.NoError(t, err)
	err = repo.CreateRefreshToken(ctx, q, token2)
	require.NoError(t, err)

	err = repo.DeleteUserRefreshTokens(ctx, q, 1)
	require.NoError(t, err)

	_, err = repo.GetRefreshToken(ctx, q, token1.Token)
	assert.ErrorIs(t, err, custom_errors.ErrInvalidToken)
	_, err = repo.GetRefreshToken(ctx, q, token2.Token)
	assert.ErrorIs(t, err, custom_errors.ErrInvalidToken)
}

func TestDeleteExpiredTokens(t *testing.T) {
	repo, q, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	validToken := &model.RefreshToken{
		UserID:    1,
		Token:     "valid-token",
		JTI:       "valid-jti",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	expiredToken := &model.RefreshToken{
		UserID:    2,
		Token:     "expired-token",
		JTI:       "expired-jti",
		ExpiresAt: time.Now().Add(-time.Hour),
	}

	err := repo.CreateRefreshToken(ctx, q, validToken)
	require.NoError(t, err)
	err = repo.CreateRefreshToken(ctx, q, expiredToken)
	require.NoError(t, err)

	err = repo.DeleteExpiredTokens(ctx, q, time.Now())
	require.NoError(t, err)

	_, err = repo.GetRefreshToken(ctx, q, validToken.Token)
	require.NoError(t, err)
	_, err = repo.GetRefreshToken(ctx, q, expiredToken.Token)
	assert.ErrorIs(t, err, custom_errors.ErrInvalidToken)
}

func TestCreateRefreshTokenWithDuplicateJTI(t *testing.T) {
	repo, q, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	token1 := &model.RefreshToken{
		UserID:    1,
		Token:     "test-token-1",
		JTI:       "test-jti",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	token2 := &model.RefreshToken{
		UserID:    2,
		Token:     "test-token-2",
		JTI:       "test-jti", // Тот же JTI
		ExpiresAt: time.Now().Add(time.Hour),
	}

	err := repo.CreateRefreshToken(ctx, q, token1)
	require.NoError(t, err)

	err = repo.CreateRefreshToken(ctx, q, token2)
	assert.Equal(t, custom_errors.ErrOperationNotAllowed.Error(), err.Error())
}

func TestGetExpiredRefreshToken(t *testing.T) {
	repo, q, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	token := &model.RefreshToken{
		UserID:    1,
		Token:     "test-token",
		JTI:       "test-jti",
		ExpiresAt: time.Now().Add(-time.Hour), // Истекший токен
	}

	err := repo.CreateRefreshToken(ctx, q, token)
	require.NoError(t, err)

	_, err = repo.GetRefreshToken(ctx, q, token.Token)
	assert.Equal(t, custom_errors.ErrExpiredToken.Error(), err.Error())
}

func TestGetExpiredRefreshTokenByJTI(t *testing.T) {
	repo, q, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	token := &model.RefreshToken{
		UserID:    1,
		Token:     "test-token",
		JTI:       "test-jti",
		ExpiresAt: time.Now().Add(-time.Hour), // Истекший токен
	}

	err := repo.CreateRefreshToken(ctx, q, token)
	require.NoError(t, err)

	_, err = repo.GetRefreshTokenByJTI(ctx, q, token.JTI)
	assert.Equal(t, custom_errors.ErrExpiredToken.Error(), err.Error())
}

func TestDeleteExpiredTokensWithMixedTokens(t *testing.T) {
	repo, q, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	validToken := &model.RefreshToken{
		UserID:    1,
		Token:     "valid-token",
		JTI:       "valid-jti",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	expiredToken1 := &model.RefreshToken{
		UserID:    2,
		Token:     "expired-token-1",
		JTI:       "expired-jti-1",
		ExpiresAt: time.Now().Add(-time.Hour),
	}
	expiredToken2 := &model.RefreshToken{
		UserID:    3,
		Token:     "expired-token-2",
		JTI:       "expired-jti-2",
		ExpiresAt: time.Now().Add(-2 * time.Hour),
	}

	err := repo.CreateRefreshToken(ctx, q, validToken)
	require.NoError(t, err)
	err = repo.CreateRefreshToken(ctx, q, expiredToken1)
	require.NoError(t, err)
	err = repo.CreateRefreshToken(ctx, q, expiredToken2)
	require.NoError(t, err)

	err = repo.DeleteExpiredTokens(ctx, q, time.Now())
	require.NoError(t, err)

	// Проверяем, что валидный токен остался
	_, err = repo.GetRefreshToken(ctx, q, validToken.Token)
	require.NoError(t, err)

	// Проверяем, что истекшие токены удалены
	_, err = repo.GetRefreshToken(ctx, q, expiredToken1.Token)
	assert.ErrorIs(t, err, custom_errors.ErrInvalidToken)
	_, err = repo.GetRefreshToken(ctx, q, expiredToken2.Token)
	assert.ErrorIs(t, err, custom_errors.ErrInvalidToken)
}

func TestDeleteUserRefreshTokensWithMixedUsers(t *testing.T) {
	repo, q, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	user1Token1 := &model.RefreshToken{
		UserID:    1,
		Token:     "user1-token-1",
		JTI:       "user1-jti-1",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	user1Token2 := &model.RefreshToken{
		UserID:    1,
		Token:     "user1-token-2",
		JTI:       "user1-jti-2",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	user2Token := &model.RefreshToken{
		UserID:    2,
		Token:     "user2-token",
		JTI:       "user2-jti",
		ExpiresAt: time.Now().Add(time.Hour),
	}

	err := repo.CreateRefreshToken(ctx, q, user1Token1)
	require.NoError(t, err)
	err = repo.CreateRefreshToken(ctx, q, user1Token2)
	require.NoError(t, err)
	err = repo.CreateRefreshToken(ctx, q, user2Token)
	require.NoError(t, err)

	err = repo.DeleteUserRefreshTokens(ctx, q, 1)
	require.NoError(t, err)

	_, err = repo.GetRefreshToken(ctx, q, user1Token1.Token)
	assert.ErrorIs(t, err, custom_errors.ErrInvalidToken)
	_, err = repo.GetRefreshToken(ctx, q, user1Token2.Token)
	assert.ErrorIs(t, err, custom_errors.ErrInvalidToken)

	_, err = repo.GetRefreshToken(ctx, q, user2Token.Token)
	require.NoError(t, err)
}

func TestDeleteRefreshTokenByJTIWithMultipleTokens(t *testing.T) {
	repo, q, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	token1 := &model.RefreshToken{
		UserID:    1,
		Token:     "test-token-1",
		JTI:       "test-jti-1",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	token2 := &model.RefreshToken{
		UserID:    2,
		Token:     "test-token-2",
		JTI:       "test-jti-2",
		ExpiresAt: time.Now().Add(time.Hour),
	}

	err := repo.CreateRefreshToken(ctx, q, token1)
	require.NoError(t, err)
	err = repo.CreateRefreshToken(ctx, q, token2)
	require.NoError(t, err)

	err = repo.DeleteRefreshTokenByJTI(ctx, q, token1.JTI)
	require.NoError(t, err)

	_, err = repo.GetRefreshTokenByJTI(ctx, q, token1.JTI)
	assert.ErrorIs(t, err, custom_errors.ErrInvalidToken)

	_, err = repo.GetRefreshTokenByJTI(ctx, q, token2.JTI)
	require.NoError(t, err)
}
