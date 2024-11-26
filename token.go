package authorizationlib

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

type TokenClaims struct {
	Username string `json:"username"`
	Name     string `json:"name"`
	Surname  string `json:"surname"`
	Email    string `json:"email"`
	Role     string `json:"role"`
	Exp      int64  `json:"exp"`
}

type Auth struct {
	SecretKey string
}

func NewAuth(secretKey string) *Auth {
	return &Auth{SecretKey: secretKey}
}

func (a *Auth) VerifyToken(tokenString string) (*TokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(a.SecretKey), nil
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
	if name, ok := (*claims)["name"].(string); ok {
		tokenClaims.Name = name
	}
	if surname, ok := (*claims)["surname"].(string); ok {
		tokenClaims.Surname = surname
	}
	if email, ok := (*claims)["email"].(string); ok {
		tokenClaims.Email = email
	}
	if role, ok := (*claims)["role"].(string); ok {
		tokenClaims.Role = role
	}
	if exp, ok := (*claims)["exp"].(float64); ok {
		tokenClaims.Exp = int64(exp)
	}

	return tokenClaims, nil
}
