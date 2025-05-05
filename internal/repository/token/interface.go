package auth_repository

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"pinstack-auth-service/internal/model"
)

type TokenRepository interface {
	CreateRefreshToken(ctx context.Context, q Querier, token *model.RefreshToken) error
	GetRefreshToken(ctx context.Context, q Querier, token string) (*model.RefreshToken, error)
	GetRefreshTokenByJTI(ctx context.Context, q Querier, jti string) (*model.RefreshToken, error)
	DeleteRefreshToken(ctx context.Context, q Querier, token string) error
	DeleteRefreshTokenByJTI(ctx context.Context, q Querier, jti string) error
	DeleteUserRefreshTokens(ctx context.Context, q Querier, userID int64) error
	DeleteExpiredTokens(ctx context.Context, q Querier, before time.Time) error
}

type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	Begin(ctx context.Context) (pgx.Tx, error)
	BeginTx(ctx context.Context, txOptions pgx.TxOptions) (pgx.Tx, error)
	CopyFrom(ctx context.Context, tableName pgx.Identifier, columnNames []string, rowSrc pgx.CopyFromSource) (int64, error)
	SendBatch(ctx context.Context, b *pgx.Batch) pgx.BatchResults
}
