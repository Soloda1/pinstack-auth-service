package auth

import (
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/soloda1/pinstack-proto-definitions/custom_errors"

	model "pinstack-auth-service/internal/domain/models"
	"pinstack-auth-service/internal/infrastructure/logger"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Token types are defined in domain/models

type Manager struct {
	accessSecretKey  []byte
	refreshSecretKey []byte
	accessTTL        time.Duration
	refreshTTL       time.Duration
	logger           *logger.Logger
}

func NewTokenManager(accessSecretKey, refreshSecretKey string, accessTTL, refreshTTL time.Duration, logger *logger.Logger) *Manager {
	return &Manager{
		accessSecretKey:  []byte(accessSecretKey),
		refreshSecretKey: []byte(refreshSecretKey),
		accessTTL:        accessTTL,
		refreshTTL:       refreshTTL,
		logger:           logger,
	}
}

func (m *Manager) NewJWT(userID int64) (*model.TokenPair, error) {
	m.logger.Debug("generating new JWT pair", slog.Int64("user_id", userID))

	jti, err := generateJTI()
	if err != nil {
		m.logger.Error("failed to generate JTI", slog.String("error", err.Error()))
		return nil, fmt.Errorf("failed to generate JTI: %w", err)
	}

	accessToken, err := m.createAccessToken(userID)
	if err != nil {
		m.logger.Error("failed to create access token",
			slog.String("error", err.Error()),
			slog.Int64("user_id", userID))
		return nil, fmt.Errorf("failed to create access token: %w", err)
	}

	refreshToken, err := m.createRefreshToken(userID, jti)
	if err != nil {
		m.logger.Error("failed to create refresh token",
			slog.String("error", err.Error()),
			slog.Int64("user_id", userID))
		return nil, fmt.Errorf("failed to create refresh token: %w", err)
	}

	m.logger.Debug("successfully generated JWT pair", slog.Int64("user_id", userID))
	return &model.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (m *Manager) createAccessToken(userID int64) (string, error) {
	claims := model.TokenClaims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(m.accessTTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.accessSecretKey)
}

func (m *Manager) createRefreshToken(userID int64, jti string) (string, error) {
	claims := model.TokenClaims{
		UserID: userID,
		JTI:    jti,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(m.refreshTTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.refreshSecretKey)
}

func (m *Manager) ParseRefreshToken(tokenString string) (*model.TokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &model.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			m.logger.Warn("unexpected signing method", slog.String("alg", fmt.Sprintf("%v", token.Header["alg"])))
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return m.refreshSecretKey, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			m.logger.Debug("refresh token expired", slog.String("token", tokenString))
			return nil, custom_errors.ErrTokenExpired
		}
		m.logger.Error("failed to parse refresh token", slog.String("error", err.Error()))
		return nil, custom_errors.ErrInvalidToken
	}

	claims, ok := token.Claims.(*model.TokenClaims)
	if !ok {
		m.logger.Error("invalid token claims")
		return nil, custom_errors.ErrInvalidToken
	}

	return claims, nil
}

func generateJTI() (string, error) {
	return uuid.New().String(), nil
}
