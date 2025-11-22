package auth

import (
	"github.com/GoBetterAuth/go-better-auth/pkg/domain"
)

// Service encapsulates all authentication use-cases
type Service struct {
	config              *domain.Config
	UserService         *UserService
	AccountService      *AccountService
	SessionService      *SessionService
	VerificationService *VerificationService
	TokenService        *TokenService
}

// NewService creates a new Auth service with all dependencies
func NewService(
	config *domain.Config,
	userService *UserService,
	accountService *AccountService,
	sessionService *SessionService,
	verificationService *VerificationService,
	tokenService *TokenService,
) *Service {
	return &Service{
		config:              config,
		UserService:         userService,
		AccountService:      accountService,
		SessionService:      sessionService,
		VerificationService: verificationService,
		TokenService:        tokenService,
	}
}
