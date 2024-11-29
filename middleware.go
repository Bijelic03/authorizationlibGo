package authorizationlib

import (
	"net/http"
)

func (h *AuthHandler) MiddlewareAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, ok := h.verifyTokenAndSetContext(r.Context(), w, r, []string{"PROJECT_MEMBER", "PROJECT_MANAGER"})
		if !ok {
			return
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (h *AuthHandler) MiddlewareAuthManager(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, ok := h.verifyTokenAndSetContext(r.Context(), w, r, []string{"PROJECT_MANAGER"})
		if !ok {
			return
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
