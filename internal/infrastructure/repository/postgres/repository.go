package auth_repository

import (
	"context"
	"errors"
	"log/slog"
	"pinstack-auth-service/internal/domain/models"
	ports "pinstack-auth-service/internal/domain/ports"
	"time"

	"github.com/soloda1/pinstack-proto-definitions/custom_errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Repository struct {
	pool *pgxpool.Pool
	log  ports.Logger
}

func NewTokenRepository(pool *pgxpool.Pool, log ports.Logger) *Repository {
	return &Repository{
		pool: pool,
		log:  log,
	}
}

func (r *Repository) CreateRefreshToken(ctx context.Context, token *models.RefreshToken) error {
	args := pgx.NamedArgs{
		"token":      token.Token,
		"user_id":    token.UserID,
		"jti":        token.JTI,
		"expires_at": token.ExpiresAt,
		"created_at": token.CreatedAt,
	}

	query := `INSERT INTO refresh_tokens(user_id, token, jti, expires_at, created_at)
				VALUES (@user_id, @token, @jti, @expires_at, @created_at)`

	_, err := r.pool.Exec(ctx, query, args)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			switch pgErr.Code {
			case "23505": // unique_violation
				r.log.Error("Refresh token already exists",
					slog.String("error", err.Error()),
					slog.String("jti", token.JTI))
				return custom_errors.ErrOperationNotAllowed
			}
		}
		r.log.Error("Failed to create refresh token",
			slog.String("error", err.Error()),
			slog.String("jti", token.JTI),
			slog.Int64("user_id", token.UserID))
		return custom_errors.ErrDatabaseQuery
	}

	return nil
}

func (r *Repository) GetRefreshToken(ctx context.Context, token string) (*models.RefreshToken, error) {
	var refreshToken models.RefreshToken
	args := pgx.NamedArgs{
		"token": token,
	}

	query := `SELECT id, user_id, token, jti, expires_at, created_at 
			  FROM refresh_tokens 
			  WHERE token = @token`

	err := r.pool.QueryRow(ctx, query, args).Scan(
		&refreshToken.ID,
		&refreshToken.UserID,
		&refreshToken.Token,
		&refreshToken.JTI,
		&refreshToken.ExpiresAt,
		&refreshToken.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			r.log.Debug("Refresh token not found", slog.String("token", token))
			return nil, custom_errors.ErrInvalidToken
		}
		r.log.Error("Failed to get refresh token",
			slog.String("error", err.Error()),
			slog.String("token", token))
		return nil, custom_errors.ErrDatabaseQuery
	}

	if time.Now().After(refreshToken.ExpiresAt) {
		r.log.Debug("Refresh token expired",
			slog.String("token", token),
			slog.Time("expires_at", refreshToken.ExpiresAt))
		return nil, custom_errors.ErrTokenExpired
	}

	return &refreshToken, nil
}

func (r *Repository) GetRefreshTokenByJTI(ctx context.Context, jti string) (*models.RefreshToken, error) {
	var refreshToken models.RefreshToken
	args := pgx.NamedArgs{
		"jti": jti,
	}

	query := `SELECT id, user_id, token, jti, expires_at, created_at 
			  FROM refresh_tokens 
			  WHERE jti = @jti`

	err := r.pool.QueryRow(ctx, query, args).Scan(
		&refreshToken.ID,
		&refreshToken.UserID,
		&refreshToken.Token,
		&refreshToken.JTI,
		&refreshToken.ExpiresAt,
		&refreshToken.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			r.log.Debug("Refresh token not found by JTI", slog.String("jti", jti))
			return nil, custom_errors.ErrInvalidToken
		}
		r.log.Error("Failed to get refresh token by JTI",
			slog.String("error", err.Error()),
			slog.String("jti", jti))
		return nil, custom_errors.ErrDatabaseQuery
	}

	if time.Now().After(refreshToken.ExpiresAt) {
		r.log.Debug("Refresh token expired",
			slog.String("jti", jti),
			slog.Time("expires_at", refreshToken.ExpiresAt))
		return nil, custom_errors.ErrTokenExpired
	}

	return &refreshToken, nil
}

func (r *Repository) DeleteRefreshToken(ctx context.Context, token string) error {
	args := pgx.NamedArgs{
		"token": token,
	}

	query := `DELETE FROM refresh_tokens WHERE token = @token`
	result, err := r.pool.Exec(ctx, query, args)
	if err != nil {
		r.log.Error("Failed to delete refresh token",
			slog.String("error", err.Error()),
			slog.String("token", token))
		return custom_errors.ErrDatabaseQuery
	}

	if result.RowsAffected() == 0 {
		r.log.Debug("No refresh token found to delete", slog.String("token", token))
		return custom_errors.ErrInvalidToken
	}

	return nil
}

func (r *Repository) DeleteRefreshTokenByJTI(ctx context.Context, jti string) error {
	args := pgx.NamedArgs{
		"jti": jti,
	}

	query := `DELETE FROM refresh_tokens WHERE jti = @jti`
	result, err := r.pool.Exec(ctx, query, args)
	if err != nil {
		r.log.Error("Failed to delete refresh token by JTI",
			slog.String("error", err.Error()),
			slog.String("jti", jti))
		return custom_errors.ErrDatabaseQuery
	}

	if result.RowsAffected() == 0 {
		r.log.Debug("No refresh token found to delete by JTI", slog.String("jti", jti))
		return custom_errors.ErrInvalidToken
	}

	return nil
}

func (r *Repository) DeleteUserRefreshTokens(ctx context.Context, userID int64) error {
	args := pgx.NamedArgs{
		"user_id": userID,
	}

	query := `DELETE FROM refresh_tokens WHERE user_id = @user_id`
	_, err := r.pool.Exec(ctx, query, args)
	if err != nil {
		r.log.Error("Failed to delete user refresh tokens",
			slog.String("error", err.Error()),
			slog.Int64("user_id", userID))
		return custom_errors.ErrDatabaseQuery
	}

	return nil
}

func (r *Repository) DeleteExpiredTokens(ctx context.Context, before time.Time) error {
	args := pgx.NamedArgs{
		"before": before,
	}

	query := `DELETE FROM refresh_tokens WHERE expires_at < @before`
	_, err := r.pool.Exec(ctx, query, args)
	if err != nil {
		r.log.Error("Failed to delete expired tokens",
			slog.String("error", err.Error()),
			slog.Time("before", before))
		return custom_errors.ErrDatabaseQuery
	}

	return nil
}
