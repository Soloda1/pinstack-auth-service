package service_test

import (
	"context"
	"testing"
	"time"

	prometheus_metrics "pinstack-auth-service/internal/infrastructure/outbound/metrics/prometheus"

	"github.com/golang-jwt/jwt/v5"
	"github.com/soloda1/pinstack-proto-definitions/custom_errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	. "pinstack-auth-service/internal/application/service"
	"pinstack-auth-service/internal/domain/models"
	ports "pinstack-auth-service/internal/domain/ports/input"
	"pinstack-auth-service/internal/infrastructure/logger"
	"pinstack-auth-service/internal/utils"
	"pinstack-auth-service/mocks"
)

func setupTest(t *testing.T) (ports.TokenService, *mocks.TokenRepository, *mocks.UserClient, *mocks.TokenManager, func()) {
	mockUserClient := mocks.NewUserClient(t)
	mockTokenManager := mocks.NewTokenManager(t)
	log := logger.New("test")
	repo := mocks.NewTokenRepository(t)
	metrics := prometheus_metrics.NewPrometheusMetricsProvider()
	service := NewService(repo, mockTokenManager, mockUserClient, log, metrics)
	return service, repo, mockUserClient, mockTokenManager, func() {}
}

func TestService_Login(t *testing.T) {
	service, repo, mockUserClient, mockTokenManager, cleanup := setupTest(t)
	defer cleanup()

	// Хеш пароля "password123"
	hashedPassword, err := utils.HashPassword("password123")
	require.NoError(t, err)

	t.Run("успешный логин", func(t *testing.T) {
		mockUserClient.ExpectedCalls = nil
		mockUserClient.Calls = nil
		mockTokenManager.ExpectedCalls = nil
		mockTokenManager.Calls = nil

		user := &models.User{ID: 1, Email: "test@example.com", Password: hashedPassword}
		mockUserClient.On("GetUserByEmail", mock.Anything, "test@example.com").Return(user, nil)
		tokens := &models.TokenPair{AccessToken: "access-token", RefreshToken: "refresh-token"}
		mockTokenManager.On("NewJWT", int64(1)).Return(tokens, nil)
		claims := &models.TokenClaims{UserID: 1, JTI: "test-jti", RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}}
		mockTokenManager.On("ParseRefreshToken", "refresh-token").Return(claims, nil)
		repo.On("CreateRefreshToken", mock.Anything, mock.Anything).Return(nil)

		gotTokens, err := service.Login(context.Background(), "test@example.com", "password123")
		assert.NoError(t, err)
		assert.NotNil(t, gotTokens)
		assert.Equal(t, tokens.AccessToken, gotTokens.AccessToken)
		assert.Equal(t, tokens.RefreshToken, gotTokens.RefreshToken)
	})

	t.Run("пользователь не найден", func(t *testing.T) {
		mockUserClient.ExpectedCalls = nil
		mockUserClient.Calls = nil
		mockTokenManager.ExpectedCalls = nil
		mockTokenManager.Calls = nil

		mockUserClient.On("GetUserByEmail", mock.Anything, "notfound@example.com").Return(nil, custom_errors.ErrUserNotFound)

		gotTokens, err := service.Login(context.Background(), "notfound@example.com", "password123")
		assert.Error(t, err)
		assert.Equal(t, custom_errors.ErrUserNotFound, err)
		assert.Nil(t, gotTokens)
	})

	t.Run("неверный пароль", func(t *testing.T) {
		mockUserClient.ExpectedCalls = nil
		mockUserClient.Calls = nil
		mockTokenManager.ExpectedCalls = nil
		mockTokenManager.Calls = nil

		user := &models.User{ID: 1, Email: "test@example.com", Password: hashedPassword}
		mockUserClient.On("GetUserByEmail", mock.Anything, "test@example.com").Return(user, nil)

		gotTokens, err := service.Login(context.Background(), "test@example.com", "wrongpassword")
		assert.Error(t, err)
		assert.Equal(t, custom_errors.ErrInvalidPassword, err)
		assert.Nil(t, gotTokens)
	})

	t.Run("ошибка внешнего сервиса", func(t *testing.T) {
		mockUserClient.ExpectedCalls = nil
		mockUserClient.Calls = nil
		mockTokenManager.ExpectedCalls = nil
		mockTokenManager.Calls = nil

		mockUserClient.On("GetUserByEmail", mock.Anything, "test@example.com").Return(nil, custom_errors.ErrExternalServiceError)

		gotTokens, err := service.Login(context.Background(), "test@example.com", "password123")
		assert.Error(t, err)
		assert.Equal(t, custom_errors.ErrExternalServiceError, err)
		assert.Nil(t, gotTokens)
	})

	t.Run("ошибка при создании токена", func(t *testing.T) {
		mockUserClient.ExpectedCalls = nil
		mockUserClient.Calls = nil
		mockTokenManager.ExpectedCalls = nil
		mockTokenManager.Calls = nil

		user := &models.User{ID: 1, Email: "test@example.com", Password: hashedPassword}
		mockUserClient.On("GetUserByEmail", mock.Anything, "test@example.com").Return(user, nil)
		mockTokenManager.On("NewJWT", int64(1)).Return(nil, custom_errors.ErrInternalServiceError)

		gotTokens, err := service.Login(context.Background(), "test@example.com", "password123")
		assert.Error(t, err)
		assert.Equal(t, custom_errors.ErrInternalServiceError, err)
		assert.Nil(t, gotTokens)
	})

	t.Run("operation not allowed (refresh token exists)", func(t *testing.T) {
		repo := mocks.NewTokenRepository(t)
		tokenManager := mocks.NewTokenManager(t)
		userClient := mocks.NewUserClient(t)
		log := logger.New("test")
		metrics := prometheus_metrics.NewPrometheusMetricsProvider()
		service := NewService(repo, tokenManager, userClient, log, metrics)

		user := &models.User{ID: 1, Email: "test@example.com", Password: hashedPassword}
		userClient.On("GetUserByEmail", mock.Anything, "test@example.com").Return(user, nil)
		tokens := &models.TokenPair{AccessToken: "access-token", RefreshToken: "refresh-token"}
		tokenManager.On("NewJWT", int64(1)).Return(tokens, nil)
		claims := &models.TokenClaims{UserID: 1, JTI: "test-jti", RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}}
		tokenManager.On("ParseRefreshToken", "refresh-token").Return(claims, nil)
		repo.On("CreateRefreshToken", mock.Anything, mock.MatchedBy(func(token *models.RefreshToken) bool {
			return token.JTI == "test-jti"
		})).Return(custom_errors.ErrOperationNotAllowed)

		gotTokens, err := service.Login(context.Background(), "test@example.com", "password123")
		assert.Error(t, err)
		assert.Equal(t, custom_errors.ErrOperationNotAllowed, err)
		assert.Nil(t, gotTokens)
	})
}

func TestService_Register(t *testing.T) {
	service, _, mockUserClient, mockTokenManager, cleanup := setupTest(t)
	defer cleanup()

	t.Run("успешная регистрация", func(t *testing.T) {
		repo := mocks.NewTokenRepository(t)
		tokenManager := mocks.NewTokenManager(t)
		userClient := mocks.NewUserClient(t)
		log := logger.New("test")
		metrics := prometheus_metrics.NewPrometheusMetricsProvider()
		service := NewService(repo, tokenManager, userClient, log, metrics)

		user := &models.User{ID: 1, Username: "testuser", Email: "test@example.com", Password: "$2a$10$abcdefghijklmnopqrstuvwxyz"}
		userClient.On("CreateUser", mock.Anything, mock.AnythingOfType("*models.User")).Return(user, nil)
		tokens := &models.TokenPair{AccessToken: "access-token", RefreshToken: "refresh-token"}
		tokenManager.On("NewJWT", int64(1)).Return(tokens, nil)
		claims := &models.TokenClaims{UserID: 1, JTI: "test-jti", RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}}
		tokenManager.On("ParseRefreshToken", "refresh-token").Return(claims, nil)
		repo.On("CreateRefreshToken", mock.Anything, mock.MatchedBy(func(token *models.RefreshToken) bool {
			return token.JTI == "test-jti"
		})).Return(nil)

		gotTokens, err := service.Register(context.Background(), &models.User{
			Username: "testuser",
			Email:    "test@example.com",
			Password: "password123",
		})
		assert.NoError(t, err)
		assert.NotNil(t, gotTokens)
		assert.Equal(t, tokens.AccessToken, gotTokens.AccessToken)
		assert.Equal(t, tokens.RefreshToken, gotTokens.RefreshToken)
	})

	t.Run("invalid email", func(t *testing.T) {
		mockUserClient.ExpectedCalls = nil
		mockUserClient.Calls = nil
		mockTokenManager.ExpectedCalls = nil
		mockTokenManager.Calls = nil

		gotTokens, err := service.Register(context.Background(), &models.User{
			Username: "testuser",
			Email:    "invalid-email",
			Password: "password123",
		})
		assert.Error(t, err)
		assert.Equal(t, custom_errors.ErrInvalidEmail, err)
		assert.Nil(t, gotTokens)
	})

	t.Run("password too short", func(t *testing.T) {
		mockUserClient.ExpectedCalls = nil
		mockUserClient.Calls = nil
		mockTokenManager.ExpectedCalls = nil
		mockTokenManager.Calls = nil

		gotTokens, err := service.Register(context.Background(), &models.User{
			Username: "testuser",
			Email:    "test@example.com",
			Password: "short",
		})
		assert.Error(t, err)
		assert.Equal(t, custom_errors.ErrInvalidPassword, err)
		assert.Nil(t, gotTokens)
	})

	t.Run("username already exists", func(t *testing.T) {
		mockUserClient.ExpectedCalls = nil
		mockUserClient.Calls = nil
		mockTokenManager.ExpectedCalls = nil
		mockTokenManager.Calls = nil

		mockUserClient.On("CreateUser", mock.Anything, mock.AnythingOfType("*models.User")).Return(nil, custom_errors.ErrUsernameExists).Once()

		gotTokens, err := service.Register(context.Background(), &models.User{
			Username: "testuser",
			Email:    "test@example.com",
			Password: "password123",
		})
		assert.Error(t, err)
		assert.Equal(t, custom_errors.ErrUsernameExists, err)
		assert.Nil(t, gotTokens)
	})

	t.Run("email already exists", func(t *testing.T) {
		mockUserClient.ExpectedCalls = nil
		mockUserClient.Calls = nil
		mockTokenManager.ExpectedCalls = nil
		mockTokenManager.Calls = nil

		mockUserClient.On("CreateUser", mock.Anything, mock.AnythingOfType("*models.User")).Return(nil, custom_errors.ErrEmailExists).Once()

		gotTokens, err := service.Register(context.Background(), &models.User{
			Username: "testuser",
			Email:    "test@example.com",
			Password: "password123",
		})
		assert.Error(t, err)
		assert.Equal(t, custom_errors.ErrEmailExists, err)
		assert.Nil(t, gotTokens)
	})

	t.Run("invalid username", func(t *testing.T) {
		mockUserClient.ExpectedCalls = nil
		mockUserClient.Calls = nil
		mockTokenManager.ExpectedCalls = nil
		mockTokenManager.Calls = nil

		mockUserClient.On("CreateUser", mock.Anything, mock.AnythingOfType("*models.User")).Return(nil, custom_errors.ErrInvalidUsername).Once()

		gotTokens, err := service.Register(context.Background(), &models.User{
			Username: "testuser",
			Email:    "test@example.com",
			Password: "password123",
		})
		assert.Error(t, err)
		assert.Equal(t, custom_errors.ErrInvalidUsername, err)
		assert.Nil(t, gotTokens)
	})

	t.Run("external service error", func(t *testing.T) {
		mockUserClient.ExpectedCalls = nil
		mockUserClient.Calls = nil
		mockTokenManager.ExpectedCalls = nil
		mockTokenManager.Calls = nil

		mockUserClient.On("CreateUser", mock.Anything, mock.AnythingOfType("*models.User")).Return(nil, custom_errors.ErrExternalServiceError).Once()

		gotTokens, err := service.Register(context.Background(), &models.User{
			Username: "testuser",
			Email:    "test@example.com",
			Password: "password123",
		})
		assert.Error(t, err)
		assert.Equal(t, custom_errors.ErrExternalServiceError, err)
		assert.Nil(t, gotTokens)
	})

	t.Run("operation not allowed", func(t *testing.T) {
		repo := mocks.NewTokenRepository(t)
		tokenManager := mocks.NewTokenManager(t)
		userClient := mocks.NewUserClient(t)
		log := logger.New("test")
		metrics := prometheus_metrics.NewPrometheusMetricsProvider()
		service := NewService(repo, tokenManager, userClient, log, metrics)

		user := &models.User{ID: 1, Username: "testuser", Email: "test@example.com", Password: "$2a$10$abcdefghijklmnopqrstuvwxyz"}
		userClient.On("CreateUser", mock.Anything, mock.AnythingOfType("*models.User")).Return(user, nil)
		tokens := &models.TokenPair{AccessToken: "access-token", RefreshToken: "refresh-token"}
		tokenManager.On("NewJWT", int64(1)).Return(tokens, nil)
		claims := &models.TokenClaims{UserID: 1, JTI: "test-jti", RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}}
		tokenManager.On("ParseRefreshToken", "refresh-token").Return(claims, nil)
		repo.On("CreateRefreshToken", mock.Anything, mock.MatchedBy(func(token *models.RefreshToken) bool {
			return token.JTI == "test-jti"
		})).Return(custom_errors.ErrOperationNotAllowed)

		gotTokens, err := service.Register(context.Background(), &models.User{
			Username: "testuser",
			Email:    "test@example.com",
			Password: "password123",
		})
		assert.Error(t, err)
		assert.Equal(t, custom_errors.ErrOperationNotAllowed, err)
		assert.Nil(t, gotTokens)
	})
}

func TestService_Refresh(t *testing.T) {
	t.Run("successful token refresh", func(t *testing.T) {
		repo := mocks.NewTokenRepository(t)
		tokenManager := mocks.NewTokenManager(t)
		userClient := mocks.NewUserClient(t)
		log := logger.New("test")
		metrics := prometheus_metrics.NewPrometheusMetricsProvider()
		service := NewService(repo, tokenManager, userClient, log, metrics)

		claims := &models.TokenClaims{UserID: 1, JTI: "test-jti", RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}}
		tokenManager.On("ParseRefreshToken", "valid-refresh-token").Return(claims, nil)
		repo.On("GetRefreshTokenByJTI", mock.Anything, "test-jti").Return(&models.RefreshToken{UserID: 1, Token: "valid-refresh-token", JTI: "test-jti", ExpiresAt: time.Now().Add(time.Hour)}, nil)
		user := &models.User{ID: 1, Username: "testuser", Email: "test@example.com"}
		userClient.On("GetUser", mock.Anything, int64(1)).Return(user, nil)
		tokens := &models.TokenPair{AccessToken: "new-access-token", RefreshToken: "new-refresh-token"}
		tokenManager.On("NewJWT", int64(1)).Return(tokens, nil)
		newClaims := &models.TokenClaims{UserID: 1, JTI: "new-jti", RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}}
		tokenManager.On("ParseRefreshToken", "new-refresh-token").Return(newClaims, nil)
		repo.On("CreateRefreshToken", mock.Anything, mock.MatchedBy(func(token *models.RefreshToken) bool {
			return token.JTI == "new-jti"
		})).Return(nil)
		repo.On("DeleteRefreshTokenByJTI", mock.Anything, "test-jti").Return(nil)

		gotTokens, err := service.Refresh(context.Background(), "valid-refresh-token")
		assert.NoError(t, err)
		assert.NotNil(t, gotTokens)
		assert.Equal(t, tokens.AccessToken, gotTokens.AccessToken)
		assert.Equal(t, tokens.RefreshToken, gotTokens.RefreshToken)
	})

	t.Run("expired token", func(t *testing.T) {
		repo := mocks.NewTokenRepository(t)
		tokenManager := mocks.NewTokenManager(t)
		userClient := mocks.NewUserClient(t)
		log := logger.New("test")
		metrics := prometheus_metrics.NewPrometheusMetricsProvider()
		service := NewService(repo, tokenManager, userClient, log, metrics)

		tokenManager.On("ParseRefreshToken", "expired-refresh-token").Return(nil, custom_errors.ErrTokenExpired)

		gotTokens, err := service.Refresh(context.Background(), "expired-refresh-token")
		assert.Error(t, err)
		assert.Equal(t, custom_errors.ErrTokenExpired, err)
		assert.Nil(t, gotTokens)
	})

	t.Run("invalid token", func(t *testing.T) {
		repo := mocks.NewTokenRepository(t)
		tokenManager := mocks.NewTokenManager(t)
		userClient := mocks.NewUserClient(t)
		log := logger.New("test")
		metrics := prometheus_metrics.NewPrometheusMetricsProvider()
		service := NewService(repo, tokenManager, userClient, log, metrics)

		tokenManager.On("ParseRefreshToken", "invalid-refresh-token").Return(nil, custom_errors.ErrInvalidToken)

		gotTokens, err := service.Refresh(context.Background(), "invalid-refresh-token")
		assert.Error(t, err)
		assert.Equal(t, custom_errors.ErrInvalidToken, err)
		assert.Nil(t, gotTokens)
	})

	t.Run("user not found", func(t *testing.T) {
		repo := mocks.NewTokenRepository(t)
		tokenManager := mocks.NewTokenManager(t)
		userClient := mocks.NewUserClient(t)
		log := logger.New("test")
		metrics := prometheus_metrics.NewPrometheusMetricsProvider()
		service := NewService(repo, tokenManager, userClient, log, metrics)

		claims := &models.TokenClaims{UserID: 1, JTI: "test-jti", RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}}
		tokenManager.On("ParseRefreshToken", "valid-refresh-token").Return(claims, nil)
		repo.On("GetRefreshTokenByJTI", mock.Anything, "test-jti").Return(&models.RefreshToken{UserID: 1, Token: "valid-refresh-token", JTI: "test-jti", ExpiresAt: time.Now().Add(time.Hour)}, nil)
		userClient.On("GetUser", mock.Anything, int64(1)).Return(nil, custom_errors.ErrUserNotFound)

		gotTokens, err := service.Refresh(context.Background(), "valid-refresh-token")
		assert.Error(t, err)
		assert.Equal(t, custom_errors.ErrUserNotFound, err)
		assert.Nil(t, gotTokens)
	})

	t.Run("external service error", func(t *testing.T) {
		repo := mocks.NewTokenRepository(t)
		tokenManager := mocks.NewTokenManager(t)
		userClient := mocks.NewUserClient(t)
		log := logger.New("test")
		metrics := prometheus_metrics.NewPrometheusMetricsProvider()
		service := NewService(repo, tokenManager, userClient, log, metrics)

		tokenManager.On("ParseRefreshToken", "valid-refresh-token").Return(nil, custom_errors.ErrExternalServiceError)

		gotTokens, err := service.Refresh(context.Background(), "valid-refresh-token")
		assert.Error(t, err)
		assert.Equal(t, custom_errors.ErrExternalServiceError, err)
		assert.Nil(t, gotTokens)
	})

	t.Run("operation not allowed", func(t *testing.T) {
		repo := mocks.NewTokenRepository(t)
		tokenManager := mocks.NewTokenManager(t)
		userClient := mocks.NewUserClient(t)
		log := logger.New("test")
		metrics := prometheus_metrics.NewPrometheusMetricsProvider()
		service := NewService(repo, tokenManager, userClient, log, metrics)

		claims := &models.TokenClaims{UserID: 1, JTI: "test-jti", RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}}
		tokenManager.On("ParseRefreshToken", "valid-refresh-token").Return(claims, nil)
		repo.On("GetRefreshTokenByJTI", mock.Anything, "test-jti").Return(nil, custom_errors.ErrOperationNotAllowed)

		gotTokens, err := service.Refresh(context.Background(), "valid-refresh-token")
		assert.Error(t, err)
		assert.Equal(t, custom_errors.ErrOperationNotAllowed, err)
		assert.Nil(t, gotTokens)
	})
}

func TestService_Logout(t *testing.T) {
	t.Run("successful logout", func(t *testing.T) {
		repo := mocks.NewTokenRepository(t)
		tokenManager := mocks.NewTokenManager(t)
		userClient := mocks.NewUserClient(t)
		log := logger.New("test")
		metrics := prometheus_metrics.NewPrometheusMetricsProvider()
		service := NewService(repo, tokenManager, userClient, log, metrics)

		claims := &models.TokenClaims{UserID: 1, JTI: "test-jti", RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}}
		tokenManager.On("ParseRefreshToken", "valid-refresh-token").Return(claims, nil)
		repo.On("DeleteRefreshTokenByJTI", mock.Anything, "test-jti").Return(nil)

		err := service.Logout(context.Background(), "valid-refresh-token")
		assert.NoError(t, err)
	})

	t.Run("expired token", func(t *testing.T) {
		repo := mocks.NewTokenRepository(t)
		tokenManager := mocks.NewTokenManager(t)
		userClient := mocks.NewUserClient(t)
		log := logger.New("test")
		metrics := prometheus_metrics.NewPrometheusMetricsProvider()
		service := NewService(repo, tokenManager, userClient, log, metrics)

		tokenManager.On("ParseRefreshToken", "expired-refresh-token").Return(nil, custom_errors.ErrTokenExpired)

		err := service.Logout(context.Background(), "expired-refresh-token")
		assert.NoError(t, err)
	})

	t.Run("invalid token", func(t *testing.T) {
		repo := mocks.NewTokenRepository(t)
		tokenManager := mocks.NewTokenManager(t)
		userClient := mocks.NewUserClient(t)
		log := logger.New("test")
		metrics := prometheus_metrics.NewPrometheusMetricsProvider()
		service := NewService(repo, tokenManager, userClient, log, metrics)

		tokenManager.On("ParseRefreshToken", "invalid-refresh-token").Return(nil, custom_errors.ErrInvalidToken)

		err := service.Logout(context.Background(), "invalid-refresh-token")
		assert.Error(t, err)
		assert.Equal(t, custom_errors.ErrInvalidToken, err)
	})
}

func TestService_UpdatePassword(t *testing.T) {
	hashedOldPassword, err := utils.HashPassword("oldpassword123")
	require.NoError(t, err)

	t.Run("successful password update", func(t *testing.T) {
		repo := mocks.NewTokenRepository(t)
		tokenManager := mocks.NewTokenManager(t)
		userClient := mocks.NewUserClient(t)
		log := logger.New("test")
		metrics := prometheus_metrics.NewPrometheusMetricsProvider()
		service := NewService(repo, tokenManager, userClient, log, metrics)

		user := &models.User{ID: 1, Password: hashedOldPassword}
		userClient.On("GetUser", mock.Anything, int64(1)).Return(user, nil)
		userClient.On("UpdatePassword", mock.Anything, int64(1), mock.AnythingOfType("string"), mock.AnythingOfType("string")).Return(nil)
		repo.On("DeleteUserRefreshTokens", mock.Anything, int64(1)).Return(nil)

		err := service.UpdatePassword(context.Background(), 1, "oldpassword123", "newpassword123")
		assert.NoError(t, err)
	})

	t.Run("password too short", func(t *testing.T) {
		repo := mocks.NewTokenRepository(t)
		tokenManager := mocks.NewTokenManager(t)
		userClient := mocks.NewUserClient(t)
		log := logger.New("test")
		metrics := prometheus_metrics.NewPrometheusMetricsProvider()
		service := NewService(repo, tokenManager, userClient, log, metrics)

		err := service.UpdatePassword(context.Background(), 1, "oldpass", "short")
		assert.Error(t, err)
		assert.Equal(t, custom_errors.ErrInvalidPassword, err)
	})

	t.Run("user not found", func(t *testing.T) {
		repo := mocks.NewTokenRepository(t)
		tokenManager := mocks.NewTokenManager(t)
		userClient := mocks.NewUserClient(t)
		log := logger.New("test")
		metrics := prometheus_metrics.NewPrometheusMetricsProvider()
		service := NewService(repo, tokenManager, userClient, log, metrics)

		userClient.On("GetUser", mock.Anything, int64(999)).Return(nil, custom_errors.ErrUserNotFound)

		err := service.UpdatePassword(context.Background(), 999, "oldpassword123", "newpassword123")
		assert.Error(t, err)
		assert.Equal(t, custom_errors.ErrUserNotFound, err)
	})

	t.Run("invalid old password", func(t *testing.T) {
		repo := mocks.NewTokenRepository(t)
		tokenManager := mocks.NewTokenManager(t)
		userClient := mocks.NewUserClient(t)
		log := logger.New("test")
		metrics := prometheus_metrics.NewPrometheusMetricsProvider()
		service := NewService(repo, tokenManager, userClient, log, metrics)

		user := &models.User{ID: 1, Password: hashedOldPassword}
		userClient.On("GetUser", mock.Anything, int64(1)).Return(user, nil)

		err := service.UpdatePassword(context.Background(), 1, "wrongpassword", "newpassword123")
		assert.Error(t, err)
		assert.Equal(t, custom_errors.ErrInvalidPassword, err)
	})

	t.Run("external service error when getting user", func(t *testing.T) {
		repo := mocks.NewTokenRepository(t)
		tokenManager := mocks.NewTokenManager(t)
		userClient := mocks.NewUserClient(t)
		log := logger.New("test")
		metrics := prometheus_metrics.NewPrometheusMetricsProvider()
		service := NewService(repo, tokenManager, userClient, log, metrics)

		userClient.On("GetUser", mock.Anything, int64(1)).Return(nil, custom_errors.ErrExternalServiceError)

		err := service.UpdatePassword(context.Background(), 1, "oldpassword123", "newpassword123")
		assert.Error(t, err)
		assert.Equal(t, custom_errors.ErrExternalServiceError, err)
	})

	t.Run("external service error when updating password", func(t *testing.T) {
		repo := mocks.NewTokenRepository(t)
		tokenManager := mocks.NewTokenManager(t)
		userClient := mocks.NewUserClient(t)
		log := logger.New("test")
		metrics := prometheus_metrics.NewPrometheusMetricsProvider()
		service := NewService(repo, tokenManager, userClient, log, metrics)

		user := &models.User{ID: 1, Password: hashedOldPassword}
		userClient.On("GetUser", mock.Anything, int64(1)).Return(user, nil)
		userClient.On("UpdatePassword", mock.Anything, int64(1), mock.AnythingOfType("string"), mock.AnythingOfType("string")).Return(custom_errors.ErrExternalServiceError)

		err := service.UpdatePassword(context.Background(), 1, "oldpassword123", "newpassword123")
		assert.Error(t, err)
		assert.Equal(t, custom_errors.ErrExternalServiceError, err)
	})

	t.Run("internal service error when deleting tokens", func(t *testing.T) {
		repo := mocks.NewTokenRepository(t)
		tokenManager := mocks.NewTokenManager(t)
		userClient := mocks.NewUserClient(t)
		log := logger.New("test")
		metrics := prometheus_metrics.NewPrometheusMetricsProvider()
		service := NewService(repo, tokenManager, userClient, log, metrics)

		user := &models.User{ID: 1, Password: hashedOldPassword}
		userClient.On("GetUser", mock.Anything, int64(1)).Return(user, nil)
		userClient.On("UpdatePassword", mock.Anything, int64(1), mock.AnythingOfType("string"), mock.AnythingOfType("string")).Return(nil)
		repo.On("DeleteUserRefreshTokens", mock.Anything, int64(1)).Return(custom_errors.ErrOperationNotAllowed)

		err := service.UpdatePassword(context.Background(), 1, "oldpassword123", "newpassword123")
		assert.Error(t, err)
		assert.Equal(t, custom_errors.ErrOperationNotAllowed, err)
	})
}
