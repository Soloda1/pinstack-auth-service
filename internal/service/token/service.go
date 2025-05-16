package auth_service

import (
	"context"
	"errors"
	"log/slog"
	"pinstack-auth-service/internal/auth"
	user_client "pinstack-auth-service/internal/clients/user"
	"pinstack-auth-service/internal/custom_errors"
	"pinstack-auth-service/internal/logger"
	"pinstack-auth-service/internal/model"
	auth_repository "pinstack-auth-service/internal/repository/token"
	"pinstack-auth-service/internal/utils"
	"regexp"

	"github.com/jackc/pgx/v5/pgxpool"
)

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

type Service struct {
	db           *pgxpool.Pool
	repo         auth_repository.TokenRepository
	userClient   user_client.UserClient
	tokenManager auth.TokenManager
	log          *logger.Logger
}

func NewService(db *pgxpool.Pool, repo auth_repository.TokenRepository, tokenManager auth.TokenManager, userClient user_client.UserClient, log *logger.Logger) *Service {
	return &Service{
		db:           db,
		repo:         repo,
		log:          log,
		userClient:   userClient,
		tokenManager: tokenManager,
	}
}

func (s *Service) Login(ctx context.Context, login, password string) (*auth.TokenPair, error) {
	isEmail := emailRegex.MatchString(login)
	var user *model.User
	var err error

	if isEmail {
		user, err = s.userClient.GetUserByEmail(ctx, login)
		if err != nil {
			s.log.Debug("Failed to get user by email", slog.String("error", err.Error()), slog.String("login", login))
			if errors.Is(err, custom_errors.ErrUserNotFound) {
				return nil, custom_errors.ErrUserNotFound
			}
			if errors.Is(err, custom_errors.ErrExternalServiceError) {
				return nil, custom_errors.ErrExternalServiceError
			}
			return nil, custom_errors.ErrInternalServiceError
		}
	} else {
		user, err = s.userClient.GetUserByUsername(ctx, login)
		if err != nil {
			s.log.Debug("Failed to get user by username", slog.String("error", err.Error()), slog.String("login", login))
			if errors.Is(err, custom_errors.ErrUserNotFound) {
				return nil, custom_errors.ErrUserNotFound
			}
			if errors.Is(err, custom_errors.ErrExternalServiceError) {
				return nil, custom_errors.ErrExternalServiceError
			}
			return nil, custom_errors.ErrInternalServiceError
		}
	}

	if !utils.CheckPasswordHash(password, user.Password) {
		s.log.Info("Invalid password", slog.String("login", login))
		return nil, custom_errors.ErrInvalidPassword
	}

	tokens, err := s.tokenManager.NewJWT(user.ID)
	if err != nil {
		s.log.Error("Failed to create token", slog.String("error", err.Error()), slog.String("login", login))
		return nil, custom_errors.ErrInternalServiceError
	}

	claims, err := s.tokenManager.ParseRefreshToken(tokens.RefreshToken)
	if err != nil {
		s.log.Error("Failed to parse refresh token", slog.String("error", err.Error()), slog.String("login", login))
		return nil, custom_errors.ErrInternalServiceError
	}

	refreshToken := &model.RefreshToken{
		UserID:    user.ID,
		Token:     tokens.RefreshToken,
		JTI:       claims.JTI,
		ExpiresAt: claims.ExpiresAt.Time,
	}

	err = s.repo.CreateRefreshToken(ctx, s.db, refreshToken)
	if err != nil {
		s.log.Error("Failed to create refresh token", slog.String("error", err.Error()), slog.String("login", login))
		if errors.Is(err, custom_errors.ErrOperationNotAllowed) {
			return nil, custom_errors.ErrOperationNotAllowed
		}
		return nil, custom_errors.ErrInternalServiceError
	}

	s.log.Info("User logged in successfully", slog.String("login", login), slog.Int64("userID", user.ID))

	return tokens, nil
}

func (s *Service) Register(ctx context.Context, user *model.User) (*auth.TokenPair, error) {
	if user.Username == "" || user.Email == "" || user.Password == "" {
		s.log.Debug("Invalid input data", slog.String("username", user.Username), slog.String("email", user.Email))
		return nil, custom_errors.ErrInvalidInput
	}

	if !emailRegex.MatchString(user.Email) {
		s.log.Debug("Invalid email format", slog.String("email", user.Email))
		return nil, custom_errors.ErrInvalidEmail
	}

	if len(user.Password) < 8 {
		s.log.Debug("Password too short", slog.String("username", user.Username))
		return nil, custom_errors.ErrInvalidPassword
	}

	hashedPassword, err := utils.HashPassword(user.Password)
	if err != nil {
		s.log.Error("Failed to hash password", slog.String("error", err.Error()), slog.String("username", user.Username))
		return nil, custom_errors.ErrInternalServiceError
	}
	user.Password = hashedPassword

	createdUser, err := s.userClient.CreateUser(ctx, user)
	if err != nil {
		s.log.Error("Failed to create user", slog.String("error", err.Error()), slog.String("username", user.Username))
		switch {
		case errors.Is(err, custom_errors.ErrUserAlreadyExists):
			return nil, custom_errors.ErrUserAlreadyExists
		case errors.Is(err, custom_errors.ErrInvalidUsername):
			return nil, custom_errors.ErrInvalidUsername
		case errors.Is(err, custom_errors.ErrInvalidEmail):
			return nil, custom_errors.ErrInvalidEmail
		case errors.Is(err, custom_errors.ErrInvalidPassword):
			return nil, custom_errors.ErrInvalidPassword
		case errors.Is(err, custom_errors.ErrExternalServiceError):
			return nil, custom_errors.ErrExternalServiceError
		default:
			return nil, custom_errors.ErrInternalServiceError
		}
	}

	tokens, err := s.tokenManager.NewJWT(createdUser.ID)
	if err != nil {
		s.log.Error("Failed to create token", slog.String("error", err.Error()), slog.String("username", user.Username))
		return nil, custom_errors.ErrInternalServiceError
	}

	claims, err := s.tokenManager.ParseRefreshToken(tokens.RefreshToken)
	if err != nil {
		s.log.Error("Failed to parse refresh token", slog.String("error", err.Error()), slog.String("username", user.Username))
		return nil, custom_errors.ErrInternalServiceError
	}

	refreshToken := &model.RefreshToken{
		UserID:    createdUser.ID,
		Token:     tokens.RefreshToken,
		JTI:       claims.JTI,
		ExpiresAt: claims.ExpiresAt.Time,
	}

	err = s.repo.CreateRefreshToken(ctx, s.db, refreshToken)
	if err != nil {
		s.log.Error("Failed to create refresh token", slog.String("error", err.Error()), slog.String("username", user.Username))
		if errors.Is(err, custom_errors.ErrOperationNotAllowed) {
			return nil, custom_errors.ErrOperationNotAllowed
		}
		return nil, custom_errors.ErrInternalServiceError
	}

	s.log.Info("User registered successfully", slog.String("username", user.Username), slog.String("email", user.Email), slog.Int64("userID", createdUser.ID))

	return tokens, nil
}

func (s *Service) Refresh(ctx context.Context, refreshToken string) (*auth.TokenPair, error) {
	claims, err := s.tokenManager.ParseRefreshToken(refreshToken)
	if err != nil {
		s.log.Error("Failed to parse refresh token", slog.String("error", err.Error()))
		if errors.Is(err, custom_errors.ErrExpiredToken) {
			return nil, custom_errors.ErrExpiredToken
		}
		return nil, custom_errors.ErrInvalidToken
	}

	_, err = s.repo.GetRefreshTokenByJTI(ctx, s.db, claims.JTI)
	if err != nil {
		s.log.Error("Failed to get refresh token", slog.String("error", err.Error()), slog.String("jti", claims.JTI))
		if errors.Is(err, custom_errors.ErrExpiredToken) {
			return nil, custom_errors.ErrExpiredToken
		}
		if errors.Is(err, custom_errors.ErrInvalidToken) {
			return nil, custom_errors.ErrInvalidToken
		}
		return nil, custom_errors.ErrInternalServiceError
	}

	user, err := s.userClient.GetUser(ctx, claims.UserID)
	if err != nil {
		s.log.Error("Failed to get user", slog.String("error", err.Error()), slog.Int64("userID", claims.UserID))
		switch {
		case errors.Is(err, custom_errors.ErrUserNotFound):
			return nil, custom_errors.ErrUserNotFound
		case errors.Is(err, custom_errors.ErrExternalServiceError):
			return nil, custom_errors.ErrExternalServiceError
		default:
			return nil, custom_errors.ErrInternalServiceError
		}
	}

	tokens, err := s.tokenManager.NewJWT(user.ID)
	if err != nil {
		s.log.Error("Failed to create token", slog.String("error", err.Error()), slog.Int64("userID", user.ID))
		return nil, custom_errors.ErrInternalServiceError
	}

	newClaims, err := s.tokenManager.ParseRefreshToken(tokens.RefreshToken)
	if err != nil {
		s.log.Error("Failed to parse new refresh token", slog.String("error", err.Error()))
		return nil, custom_errors.ErrInternalServiceError
	}

	newRefreshToken := &model.RefreshToken{
		UserID:    user.ID,
		Token:     tokens.RefreshToken,
		JTI:       newClaims.JTI,
		ExpiresAt: newClaims.ExpiresAt.Time,
	}

	err = s.repo.CreateRefreshToken(ctx, s.db, newRefreshToken)
	if err != nil {
		s.log.Error("Failed to create refresh token", slog.String("error", err.Error()), slog.Int64("userID", user.ID))
		if errors.Is(err, custom_errors.ErrOperationNotAllowed) {
			return nil, custom_errors.ErrOperationNotAllowed
		}
		return nil, custom_errors.ErrInternalServiceError
	}

	err = s.repo.DeleteRefreshTokenByJTI(ctx, s.db, claims.JTI)
	if err != nil {
		s.log.Error("Failed to delete old refresh token", slog.String("error", err.Error()), slog.String("jti", claims.JTI))
		if errors.Is(err, custom_errors.ErrInvalidToken) {
			return nil, custom_errors.ErrInvalidToken
		}
		return nil, custom_errors.ErrInternalServiceError
	}

	s.log.Info("Tokens refreshed successfully", slog.Int64("userID", user.ID))

	return tokens, nil
}

func (s *Service) Logout(ctx context.Context, refreshToken string) error {
	claims, err := s.tokenManager.ParseRefreshToken(refreshToken)
	if err != nil {
		s.log.Error("Failed to parse refresh token", slog.String("error", err.Error()))
		if errors.Is(err, custom_errors.ErrExpiredToken) {
			return nil
		}
		return custom_errors.ErrInvalidToken
	}

	err = s.repo.DeleteRefreshTokenByJTI(ctx, s.db, claims.JTI)
	if err != nil {
		s.log.Error("Failed to delete refresh token", slog.String("error", err.Error()), slog.String("jti", claims.JTI))
		if errors.Is(err, custom_errors.ErrInvalidToken) {
			return nil
		}
		return custom_errors.ErrInternalServiceError
	}

	s.log.Info("User logged out successfully", slog.Int64("userID", claims.UserID))

	return nil
}

func (s *Service) UpdatePassword(ctx context.Context, id int64, oldPassword, newPassword string) error {
	if len(newPassword) < 8 {
		s.log.Debug("Password too short", slog.Int64("userID", id))
		return custom_errors.ErrInvalidPassword
	}

	user, err := s.userClient.GetUser(ctx, id)
	if err != nil {
		s.log.Error("Failed to get user", slog.String("error", err.Error()), slog.Int64("userID", id))
		switch {
		case errors.Is(err, custom_errors.ErrUserNotFound):
			return custom_errors.ErrUserNotFound
		case errors.Is(err, custom_errors.ErrExternalServiceError):
			return custom_errors.ErrExternalServiceError
		default:
			return custom_errors.ErrInternalServiceError
		}
	}

	if !utils.CheckPasswordHash(oldPassword, user.Password) {
		s.log.Info("Invalid old password", slog.Int64("userID", id))
		return custom_errors.ErrInvalidPassword
	}

	hashedNewPassword, err := utils.HashPassword(newPassword)
	if err != nil {
		s.log.Error("Failed to hash new password", slog.String("error", err.Error()), slog.Int64("userID", id))
		return custom_errors.ErrInternalServiceError
	}

	hashedOldPassword, err := utils.HashPassword(oldPassword)
	if err != nil {
		s.log.Error("Failed to hash old password", slog.Int64("userID", id))
		return custom_errors.ErrInternalServiceError
	}

	err = s.userClient.UpdatePassword(ctx, id, hashedOldPassword, hashedNewPassword)
	if err != nil {
		s.log.Error("Failed to update password", slog.String("error", err.Error()), slog.Int64("userID", id))
		switch {
		case errors.Is(err, custom_errors.ErrUserNotFound):
			return custom_errors.ErrUserNotFound
		case errors.Is(err, custom_errors.ErrInvalidPassword):
			return custom_errors.ErrInvalidPassword
		case errors.Is(err, custom_errors.ErrExternalServiceError):
			return custom_errors.ErrExternalServiceError
		default:
			return custom_errors.ErrInternalServiceError
		}
	}

	err = s.repo.DeleteUserRefreshTokens(ctx, s.db, id)
	if err != nil {
		s.log.Error("Failed to delete refresh tokens", slog.String("error", err.Error()), slog.Int64("userID", id))
		return custom_errors.ErrInternalServiceError
	}

	s.log.Info("Password updated successfully", slog.Int64("userID", id))

	return nil
}
