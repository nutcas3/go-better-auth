package middleware

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"slices"

	"github.com/GoBetterAuth/go-better-auth/internal/auth"
	"github.com/GoBetterAuth/go-better-auth/internal/util"
)

type ctxKey string

const ContextUserID ctxKey = "user_id"

func AuthMiddleware(authService *auth.Service, cookieName string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(cookieName)
			if err != nil || cookie.Value == "" {
				util.JSONResponse(w, http.StatusUnauthorized, map[string]any{"message": "unauthorized"})
				return
			}

			sess, err := authService.SessionService.GetSessionByToken(authService.TokenService.HashToken(cookie.Value))
			if err != nil || sess == nil {
				util.JSONResponse(w, http.StatusUnauthorized, map[string]any{"message": "invalid session"})
				return
			}

			ctx := context.WithValue(r.Context(), ContextUserID, sess.UserID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func OptionalAuthMiddleware(authService *auth.Service, cookieName string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(cookieName)
			if err == nil && cookie.Value != "" {
				if sess, _ := authService.SessionService.GetSessionByToken(authService.TokenService.HashToken(cookie.Value)); sess != nil {
					r = r.WithContext(context.WithValue(r.Context(), ContextUserID, sess.UserID))
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

func CorsMiddleware(allowedOrigins []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			slog.Debug(fmt.Sprintf("Origin: %s", origin))
			allowed := slices.Contains(allowedOrigins, origin)

			if allowed {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization,Cookie,Set-Cookie")
				w.Header().Set("Access-Control-Max-Age", "86400")
			}

			// Handle preflight requests
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
