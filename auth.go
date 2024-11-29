package authorizationlib

import (
	"context"
	"net/http"
	"strings"
)

type AuthHandler struct {
	auth *Auth
}

func NewAuthHandler(secretKey []byte) *AuthHandler {
	return &AuthHandler{auth: NewAuth(secretKey)}
}

func parseBearerToken(header string) string {
	const bearerPrefix = "Bearer "
	if len(header) > len(bearerPrefix) && strings.HasPrefix(header, bearerPrefix) {
		return header[len(bearerPrefix):]
	}
	return ""
}

type contextKey string

const (
	UsernameKey contextKey = "username"
	RoleKey     contextKey = "role"
)

func (h *AuthHandler) verifyTokenAndSetContext(ctx context.Context, w http.ResponseWriter, r *http.Request, allowedRoles []string) (context.Context, bool) {
	tokenString := parseBearerToken(r.Header.Get("Authorization"))
	if tokenString == "" {
		http.Error(w, `{"error": "Invalid or missing authorization header"}`, http.StatusUnauthorized)
		return ctx, false
	}

	tokenClaims, err := h.auth.VerifyToken(tokenString)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return ctx, false
	}

	if len(allowedRoles) > 0 {
		roleAllowed := false
		for _, role := range allowedRoles {
			if tokenClaims.Role == role {
				roleAllowed = true
				break
			}
		}

		if !roleAllowed {
			http.Error(w, `{"error": "Access denied for the required role"}`, http.StatusForbidden)
			return ctx, false
		}
	}

	// Dodavanje username i role u context
	ctx = context.WithValue(ctx, UsernameKey, tokenClaims.Username)
	ctx = context.WithValue(ctx, RoleKey, tokenClaims.Role)
	return ctx, true
}
