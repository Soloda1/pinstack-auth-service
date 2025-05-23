package model

import "time"

type RefreshToken struct {
	ID        int64     `json:"id"`
	UserID    int64     `json:"user_id"`
	Token     string    `json:"token"`
	JTI       string    `json:"jti"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}
