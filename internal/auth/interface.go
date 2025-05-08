package auth

type TokenManager interface {
	NewJWT(userID int64) (*TokenPair, error)
	ParseRefreshToken(tokenString string) (*TokenClaims, error)
}
