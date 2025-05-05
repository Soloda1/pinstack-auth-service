package auth_service

import (
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
	"pinstack-auth-service/internal/auth"
	"pinstack-auth-service/internal/logger"
	"pinstack-auth-service/internal/model"
	"pinstack-auth-service/internal/repository/token"
)

type TokenService struct {
	db   *pgxpool.Pool
	repo auth_repository.TokenRepository
	log  *logger.Logger
}

func NewService(db *pgxpool.Pool, repo auth_repository.TokenRepository, log *logger.Logger) *TokenService {
	return &TokenService{
		db:   db,
		repo: repo,
		log:  log,
	}
}

func (s *TokenService) Login(ctx context.Context, login, password string) (*auth.TokenPair, error) {
	return nil, nil
}

func (s *TokenService) Register(ctx context.Context, user *model.UserDTO) (*auth.TokenPair, error) {
	return nil, nil
}

func (s *TokenService) Refresh(ctx context.Context, refreshToken string) (*auth.TokenPair, error) {
	return nil, nil
}

func (s *TokenService) Logout(ctx context.Context, refreshToken string) error {
	return nil
}
