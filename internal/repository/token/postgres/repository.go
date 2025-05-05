package auth_repository

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"log/slog"
	"pinstack-auth-service/internal/logger"
	"pinstack-auth-service/internal/model"
	"pinstack-auth-service/internal/repository/token"
	"time"
)

type Repository struct {
	log *logger.Logger
}

func NewUserRepository(log *logger.Logger) *Repository {
	return &Repository{log}
}

func (r *Repository) CreateRefreshToken(ctx context.Context, q auth_repository.Querier, token *model.RefreshToken) error {
	args := pgx.NamedArgs{
		"token":      token.Token,
		"user_id":    token.UserID,
		"jti":        token.JTI,
		"expires_at": token.ExpiresAt,
		"created_at": token.CreatedAt,
	}

	query := `INSERT INTO refresh_tokens(user_id, token, jti, expires_at, created_at)
				VALUES (@user_id, @token, @jti, @expires_at, @created_at)`

	_, err := q.Exec(ctx, query, args)
	if err != nil {
		r.log.Error("Error creating refresh token", slog.String("error", err.Error()))
		return err
	}

	return nil
}

func (r *Repository) GetRefreshToken(ctx context.Context, q auth_repository.Querier, token string) (*model.RefreshToken, error) {
	var refreshToken model.RefreshToken
	args := pgx.NamedArgs{
		"token": token,
	}

	query := `SELECT id, user_id, token, jti, expires_at, created_at 
			  FROM refresh_tokens 
			  WHERE token = @token`

	err := q.QueryRow(ctx, query, args).Scan(
		&refreshToken.ID,
		&refreshToken.UserID,
		&refreshToken.Token,
		&refreshToken.JTI,
		&refreshToken.ExpiresAt,
		&refreshToken.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		r.log.Error("Error getting refresh token", slog.String("error", err.Error()))
		return nil, err
	}

	return &refreshToken, nil
}

func (r *Repository) GetRefreshTokenByJTI(ctx context.Context, q auth_repository.Querier, jti string) (*model.RefreshToken, error) {
	var refreshToken model.RefreshToken
	args := pgx.NamedArgs{
		"jti": jti,
	}

	query := `SELECT id, user_id, token, jti, expires_at, created_at 
			  FROM refresh_tokens 
			  WHERE jti = @jti`

	err := q.QueryRow(ctx, query, args).Scan(
		&refreshToken.ID,
		&refreshToken.UserID,
		&refreshToken.Token,
		&refreshToken.JTI,
		&refreshToken.ExpiresAt,
		&refreshToken.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		r.log.Error("Error getting refresh token by JTI", slog.String("error", err.Error()))
		return nil, err
	}

	return &refreshToken, nil
}

func (r *Repository) DeleteRefreshToken(ctx context.Context, q auth_repository.Querier, token string) error {
	args := pgx.NamedArgs{
		"token": token,
	}

	query := `DELETE FROM refresh_tokens WHERE token = @token`
	_, err := q.Exec(ctx, query, args)
	if err != nil {
		r.log.Error("Error deleting refresh token", slog.String("error", err.Error()))
		return err
	}
	return nil
}

func (r *Repository) DeleteRefreshTokenByJTI(ctx context.Context, q auth_repository.Querier, jti string) error {
	args := pgx.NamedArgs{
		"jti": jti,
	}

	query := `DELETE FROM refresh_tokens WHERE jti = @jti`
	_, err := q.Exec(ctx, query, args)
	if err != nil {
		r.log.Error("Error deleting refresh token by JTI", slog.String("error", err.Error()))
		return err
	}
	return nil
}

func (r *Repository) DeleteUserRefreshTokens(ctx context.Context, q auth_repository.Querier, userID int64) error {
	args := pgx.NamedArgs{
		"user_id": userID,
	}

	query := `DELETE FROM refresh_tokens WHERE user_id = @user_id`
	_, err := q.Exec(ctx, query, args)
	if err != nil {
		r.log.Error("Error deleting user refresh tokens", slog.String("error", err.Error()))
		return err
	}
	return nil
}

func (r *Repository) DeleteExpiredTokens(ctx context.Context, q auth_repository.Querier, before time.Time) error {
	args := pgx.NamedArgs{
		"before": before,
	}

	query := `DELETE FROM refresh_tokens WHERE expires_at < @before`
	_, err := q.Exec(ctx, query, args)
	if err != nil {
		r.log.Error("Error deleting expired tokens", slog.String("error", err.Error()))
		return err
	}
	return nil
}
