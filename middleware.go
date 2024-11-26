package authorizationlib

import (
	"net/http"
)

func (h *AuthHandler) MiddlewareAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !h.verifyTokenAndSetHeaders(w, r, []string{"PROJECT_MEMBER", "PROJECT_MANAGER"}) {
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (h *AuthHandler) MiddlewareAuthManager(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !h.verifyTokenAndSetHeaders(w, r, []string{"PROJECT_MANAGER"}) {
			return
		}
		next.ServeHTTP(w, r)
	})
}
