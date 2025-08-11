package models

import (
	"github.com/golang-jwt/jwt/v5"
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
