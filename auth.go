package authorizationlib

import (
	"net/http"
	"strings"
)

type AuthHandler struct {
	auth *Auth
}

func NewAuthHandler(secretKey string) *AuthHandler {
	return &AuthHandler{auth: NewAuth(secretKey)}
}

func parseBearerToken(header string) string {
	const bearerPrefix = "Bearer "
	if len(header) > len(bearerPrefix) && strings.HasPrefix(header, bearerPrefix) {
		return header[len(bearerPrefix):]
	}
	return ""
}

func (h *AuthHandler) verifyTokenAndSetHeaders(w http.ResponseWriter, r *http.Request, allowedRoles []string) bool {
	tokenString := parseBearerToken(r.Header.Get("Authorization"))
	if tokenString == "" {
		http.Error(w, `{"error": "Invalid or missing authorization header"}`, http.StatusUnauthorized)
		return false
	}

	tokenClaims, err := h.auth.VerifyToken(tokenString)
	if err != nil {
		http.Error(w, `{"error": "Invalid token"}`, http.StatusUnauthorized)
		return false
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
			return false
		}
	}

	w.Header().Set("username", tokenClaims.Username)
	w.Header().Set("role", tokenClaims.Role)
	return true
}
