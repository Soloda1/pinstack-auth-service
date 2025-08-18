package auth_repository

import (
	"context"
	"errors"
	"log/slog"
	"pinstack-auth-service/internal/domain/models"
	ports "pinstack-auth-service/internal/domain/ports/output"
	"time"

	"github.com/soloda1/pinstack-proto-definitions/custom_errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Repository struct {
	pool    *pgxpool.Pool
	log     ports.Logger
	metrics ports.MetricsProvider
}

func NewTokenRepository(pool *pgxpool.Pool, log ports.Logger, metrics ports.MetricsProvider) *Repository {
	return &Repository{
		pool:    pool,
		log:     log,
		metrics: metrics,
	}
}

func (r *Repository) CreateRefreshToken(ctx context.Context, token *models.RefreshToken) (err error) {
	start := time.Now()
	defer func() {
		r.metrics.RecordDatabaseQueryDuration("create_refresh_token", time.Since(start))
		r.metrics.IncrementDatabaseQueries("create_refresh_token", err == nil)
		r.metrics.IncrementTokenOperations("create", err == nil)
	}()

	args := pgx.NamedArgs{
		"token":      token.Token,
		"user_id":    token.UserID,
		"jti":        token.JTI,
		"expires_at": token.ExpiresAt,
		"created_at": token.CreatedAt,
	}

	query := `INSERT INTO refresh_tokens(user_id, token, jti, expires_at, created_at)
				VALUES (@user_id, @token, @jti, @expires_at, @created_at)`

	_, err = r.pool.Exec(ctx, query, args)
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

func (r *Repository) GetRefreshToken(ctx context.Context, token string) (refreshToken *models.RefreshToken, err error) {
	start := time.Now()
	defer func() {
		r.metrics.RecordDatabaseQueryDuration("get_refresh_token", time.Since(start))
		r.metrics.IncrementDatabaseQueries("get_refresh_token", err == nil)
		r.metrics.IncrementTokenOperations("get", err == nil)
	}()

	var rt models.RefreshToken
	args := pgx.NamedArgs{
		"token": token,
	}

	query := `SELECT id, user_id, token, jti, expires_at, created_at 
			  FROM refresh_tokens 
			  WHERE token = @token`

	err = r.pool.QueryRow(ctx, query, args).Scan(
		&rt.ID,
		&rt.UserID,
		&rt.Token,
		&rt.JTI,
		&rt.ExpiresAt,
		&rt.CreatedAt,
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

	if time.Now().After(rt.ExpiresAt) {
		r.log.Debug("Refresh token expired",
			slog.String("token", token),
			slog.Time("expires_at", rt.ExpiresAt))
		return nil, custom_errors.ErrTokenExpired
	}

	return &rt, nil
}

func (r *Repository) GetRefreshTokenByJTI(ctx context.Context, jti string) (refreshToken *models.RefreshToken, err error) {
	start := time.Now()
	defer func() {
		r.metrics.RecordDatabaseQueryDuration("get_refresh_token_by_jti", time.Since(start))
		r.metrics.IncrementDatabaseQueries("get_refresh_token_by_jti", err == nil)
		r.metrics.IncrementTokenOperations("get_by_jti", err == nil)
	}()

	var rt models.RefreshToken
	args := pgx.NamedArgs{
		"jti": jti,
	}

	query := `SELECT id, user_id, token, jti, expires_at, created_at 
			  FROM refresh_tokens 
			  WHERE jti = @jti`

	err = r.pool.QueryRow(ctx, query, args).Scan(
		&rt.ID,
		&rt.UserID,
		&rt.Token,
		&rt.JTI,
		&rt.ExpiresAt,
		&rt.CreatedAt,
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

	if time.Now().After(rt.ExpiresAt) {
		r.log.Debug("Refresh token expired",
			slog.String("jti", jti),
			slog.Time("expires_at", rt.ExpiresAt))
		return nil, custom_errors.ErrTokenExpired
	}

	return &rt, nil
}

func (r *Repository) DeleteRefreshToken(ctx context.Context, token string) (err error) {
	start := time.Now()
	defer func() {
		r.metrics.RecordDatabaseQueryDuration("delete_refresh_token", time.Since(start))
		r.metrics.IncrementDatabaseQueries("delete_refresh_token", err == nil)
		r.metrics.IncrementTokenOperations("delete", err == nil)
	}()

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

func (r *Repository) DeleteRefreshTokenByJTI(ctx context.Context, jti string) (err error) {
	start := time.Now()
	defer func() {
		r.metrics.RecordDatabaseQueryDuration("delete_refresh_token_by_jti", time.Since(start))
		r.metrics.IncrementDatabaseQueries("delete_refresh_token_by_jti", err == nil)
		r.metrics.IncrementTokenOperations("delete_by_jti", err == nil)
	}()

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

func (r *Repository) DeleteUserRefreshTokens(ctx context.Context, userID int64) (err error) {
	start := time.Now()
	defer func() {
		r.metrics.RecordDatabaseQueryDuration("delete_user_refresh_tokens", time.Since(start))
		r.metrics.IncrementDatabaseQueries("delete_user_refresh_tokens", err == nil)
		r.metrics.IncrementTokenOperations("delete_user_tokens", err == nil)
	}()

	args := pgx.NamedArgs{
		"user_id": userID,
	}

	query := `DELETE FROM refresh_tokens WHERE user_id = @user_id`
	_, err = r.pool.Exec(ctx, query, args)
	if err != nil {
		r.log.Error("Failed to delete user refresh tokens",
			slog.String("error", err.Error()),
			slog.Int64("user_id", userID))
		return custom_errors.ErrDatabaseQuery
	}

	return nil
}

func (r *Repository) DeleteExpiredTokens(ctx context.Context, before time.Time) (err error) {
	start := time.Now()
	defer func() {
		r.metrics.RecordDatabaseQueryDuration("delete_expired_tokens", time.Since(start))
		r.metrics.IncrementDatabaseQueries("delete_expired_tokens", err == nil)
		r.metrics.IncrementTokenOperations("delete_expired", err == nil)
	}()

	args := pgx.NamedArgs{
		"before": before,
	}

	query := `DELETE FROM refresh_tokens WHERE expires_at < @before`
	_, err = r.pool.Exec(ctx, query, args)
	if err != nil {
		r.log.Error("Failed to delete expired tokens",
			slog.String("error", err.Error()),
			slog.Time("before", before))
		return custom_errors.ErrDatabaseQuery
	}

	return nil
}
