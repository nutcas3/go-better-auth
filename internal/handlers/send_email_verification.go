package handlers

import (
	"net/http"

	"github.com/GoBetterAuth/go-better-auth/internal/auth"
	"github.com/GoBetterAuth/go-better-auth/internal/middleware"
	"github.com/GoBetterAuth/go-better-auth/internal/util"
	"github.com/GoBetterAuth/go-better-auth/pkg/domain"
)

type SendEmailVerificationResponse struct {
	Message string `json:"message"`
}

type SendEmailVerificationHandler struct {
	Config      *domain.Config
	AuthService *auth.Service
}

func (h *SendEmailVerificationHandler) Handle(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(middleware.ContextUserID).(string)
	if !ok || userID == "" {
		util.JSONResponse(w, http.StatusUnauthorized, map[string]any{"message": "unauthorized"})
		return
	}

	if err := h.AuthService.SendVerificationEmail(userID); err != nil {
		util.JSONResponse(w, http.StatusInternalServerError, map[string]any{"message": err.Error()})
		return
	}

	resp := SendEmailVerificationResponse{Message: "Verification email sent"}
	util.JSONResponse(w, http.StatusOK, resp)
}

func (h *SendEmailVerificationHandler) Handler() http.Handler {
	return Wrap(h)
}
