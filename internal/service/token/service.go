package auth_service

import (
	"github.com/jackc/pgx/v5/pgxpool"
	"pinstack-auth-service/internal/logger"
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
