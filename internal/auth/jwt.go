package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"pinstack-auth-service/internal/logger"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrInvalidToken = errors.New("invalid token")
	ErrExpiredToken = errors.New("token has expired")
)

type TokenPair struct {
	AccessToken  string
	RefreshToken string
}

type TokenClaims struct {
	UserID int64  `json:"user_id"`
	JTI    string `json:"jti"`
	jwt.RegisteredClaims
}

type TokenManager struct {
	accessSecretKey  []byte
	refreshSecretKey []byte
	accessTTL        time.Duration
	refreshTTL       time.Duration
	logger           *logger.Logger
}

func NewTokenManager(accessSecretKey, refreshSecretKey string, accessTTL, refreshTTL time.Duration, logger *logger.Logger) *TokenManager {
	return &TokenManager{
		accessSecretKey:  []byte(accessSecretKey),
		refreshSecretKey: []byte(refreshSecretKey),
		accessTTL:        accessTTL,
		refreshTTL:       refreshTTL,
		logger:           logger,
	}
}

func (m *TokenManager) NewJWT(userID int64) (*TokenPair, error) {
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
	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (m *TokenManager) createAccessToken(userID int64) (string, error) {
	claims := TokenClaims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(m.accessTTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.accessSecretKey)
}

func (m *TokenManager) createRefreshToken(userID int64, jti string) (string, error) {
	claims := TokenClaims{
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

func (m *TokenManager) ParseRefreshToken(tokenString string) (*TokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			m.logger.Warn("unexpected signing method", slog.String("alg", fmt.Sprintf("%v", token.Header["alg"])))
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return m.refreshSecretKey, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			m.logger.Debug("refresh token expired", slog.String("token", tokenString))
			return nil, ErrExpiredToken
		}
		m.logger.Error("failed to parse refresh token", slog.String("error", err.Error()))
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*TokenClaims)
	if !ok {
		m.logger.Error("invalid token claims")
		return nil, ErrInvalidToken
	}

	return claims, nil
}

func generateJTI() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
