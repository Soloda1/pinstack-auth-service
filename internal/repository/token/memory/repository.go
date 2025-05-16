package memory

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"pinstack-auth-service/internal/custom_errors"
	"pinstack-auth-service/internal/logger"
	"pinstack-auth-service/internal/model"
	auth_repository "pinstack-auth-service/internal/repository/token"
)

type Repository struct {
	tokens map[string]*model.RefreshToken
	mu     sync.RWMutex
	log    *logger.Logger
	nextID int64
}

func NewTokenRepository(log *logger.Logger) *Repository {
	return &Repository{
		tokens: make(map[string]*model.RefreshToken),
		log:    log,
		nextID: 1,
	}
}

func (r *Repository) CreateRefreshToken(ctx context.Context, q auth_repository.Querier, token *model.RefreshToken) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, t := range r.tokens {
		if t.JTI == token.JTI {
			r.log.Error("Refresh token already exists",
				"jti", token.JTI)
			return custom_errors.ErrOperationNotAllowed
		}
	}

	now := time.Now()
	token.ID = atomic.AddInt64(&r.nextID, 1)
	token.CreatedAt = now
	r.tokens[token.Token] = token

	return nil
}

func (r *Repository) GetRefreshToken(ctx context.Context, q auth_repository.Querier, token string) (*model.RefreshToken, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	t, exists := r.tokens[token]
	if !exists {
		r.log.Debug("Refresh token not found", "token", token)
		return nil, custom_errors.ErrInvalidToken
	}

	if time.Now().After(t.ExpiresAt) {
		r.log.Debug("Refresh token expired",
			"token", token,
			"expires_at", t.ExpiresAt)
		return nil, custom_errors.ErrExpiredToken
	}

	return t, nil
}

func (r *Repository) GetRefreshTokenByJTI(ctx context.Context, q auth_repository.Querier, jti string) (*model.RefreshToken, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, t := range r.tokens {
		if t.JTI == jti {
			if time.Now().After(t.ExpiresAt) {
				r.log.Debug("Refresh token expired",
					"jti", jti,
					"expires_at", t.ExpiresAt)
				return nil, custom_errors.ErrExpiredToken
			}
			return t, nil
		}
	}

	r.log.Debug("Refresh token not found by JTI", "jti", jti)
	return nil, custom_errors.ErrInvalidToken
}

func (r *Repository) DeleteRefreshToken(ctx context.Context, q auth_repository.Querier, token string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.tokens[token]; !exists {
		r.log.Debug("No refresh token found to delete", "token", token)
		return custom_errors.ErrInvalidToken
	}

	delete(r.tokens, token)
	return nil
}

func (r *Repository) DeleteRefreshTokenByJTI(ctx context.Context, q auth_repository.Querier, jti string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for token, t := range r.tokens {
		if t.JTI == jti {
			delete(r.tokens, token)
			return nil
		}
	}

	r.log.Debug("No refresh token found to delete by JTI", "jti", jti)
	return custom_errors.ErrInvalidToken
}

func (r *Repository) DeleteUserRefreshTokens(ctx context.Context, q auth_repository.Querier, userID int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for token, t := range r.tokens {
		if t.UserID == userID {
			delete(r.tokens, token)
		}
	}

	return nil
}

func (r *Repository) DeleteExpiredTokens(ctx context.Context, q auth_repository.Querier, before time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for token, t := range r.tokens {
		if t.ExpiresAt.Before(before) {
			delete(r.tokens, token)
		}
	}

	return nil
}
