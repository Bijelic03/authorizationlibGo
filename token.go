package authorizationlib

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

type TokenClaims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
}

type Auth struct {
	SecretKey string
}

func NewAuth(secretKey string) *Auth {
	return &Auth{SecretKey: secretKey}
}

func (a *Auth) VerifyToken(tokenString string) (*TokenClaims, error) {
	// Parse the token with claims
	token, err := jwt.ParseWithClaims(tokenString, &jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		return a.SecretKey, nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	claims, ok := token.Claims.(*jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("unable to parse token claims")
	}

	tokenClaims := &TokenClaims{}

	if username, ok := (*claims)["username"].(string); ok {
		tokenClaims.Username = username
	}
	if role, ok := (*claims)["role"].(string); ok {
		tokenClaims.Role = role
	}

	return tokenClaims, nil
}
