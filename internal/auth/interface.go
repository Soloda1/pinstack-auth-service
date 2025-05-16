package auth

//go:generate mockery --name TokenManager --dir . --output ../../mocks --outpkg mocks --with-expecter
type TokenManager interface {
	NewJWT(userID int64) (*TokenPair, error)
	ParseRefreshToken(tokenString string) (*TokenClaims, error)
}
