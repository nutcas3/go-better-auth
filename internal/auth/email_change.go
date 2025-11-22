package auth

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/GoBetterAuth/go-better-auth/internal/util"
	"github.com/GoBetterAuth/go-better-auth/pkg/domain"
)

// EmailChange initiates an email change by sending a verification email to the new address
func (s *Service) EmailChange(userID string, newEmail string, callbackURL *string) error {
	user, err := s.UserService.GetUserByID(userID)
	if err != nil {
		slog.Error("failed to get user", "user_id", userID, "error", err)
		return fmt.Errorf("%w: %w", ErrUserNotFound, err)
	}
	if user == nil {
		return ErrUserNotFound
	}

	existingUser, err := s.UserService.GetUserByEmail(newEmail)
	if err != nil {
		slog.Error("failed to check email", "email", newEmail, "error", err)
		return fmt.Errorf("failed to check email: %w", err)
	}
	if existingUser != nil && existingUser.ID != userID {
		return ErrEmailAlreadyExists
	}

	token, err := s.TokenService.GenerateToken()
	if err != nil {
		slog.Error("failed to generate token", "error", err)
		return fmt.Errorf("%w: %w", ErrTokenGenerationFailed, err)
	}

	ver := &domain.Verification{
		UserID:     &user.ID,
		Identifier: newEmail, // store new email in identifier
		Token:      s.TokenService.HashToken(token),
		Type:       domain.TypeEmailChange,
		ExpiresAt:  time.Now().UTC().Add(s.config.EmailVerification.ExpiresIn),
	}
	if err := s.VerificationService.CreateVerification(ver); err != nil {
		slog.Error("failed to create verification record", "user_id", user.ID, "error", err)
		return fmt.Errorf("failed to create verification: %w", err)
	}

	if s.config.User.ChangeEmail.Enabled {
		url := util.BuildVerificationURL(
			s.config.BaseURL,
			s.config.BasePath,
			token,
			callbackURL,
		)
		go func() {
			if err := s.config.User.ChangeEmail.SendEmailChangeVerification(user, newEmail, url, token); err != nil {
				slog.Error("failed to send email change verification", "user_id", user.ID, "error", err)
			}
		}()
	}

	return nil
}

// ConfirmEmailChange confirms an email change with a verification token
func (s *Service) ConfirmEmailChange(rawToken string) (*EmailChangeResult, error) {
	if rawToken == "" {
		return nil, ErrInvalidToken
	}

	ver, err := s.VerificationService.GetVerificationByToken(s.TokenService.HashToken(rawToken))
	if err != nil {
		slog.Error("failed to get verification token", "error", err)
		return nil, fmt.Errorf("%w: %w", ErrVerificationNotFound, err)
	}
	if ver == nil || ver.Type != domain.TypeEmailChange {
		return nil, ErrVerificationInvalid
	}

	if s.VerificationService.IsExpired(ver) {
		return nil, ErrVerificationExpired
	}

	if ver.UserID == nil {
		return nil, ErrUserNotFound
	}

	user, err := s.UserService.GetUserByID(*ver.UserID)
	if err != nil {
		slog.Error("failed to get user", "user_id", *ver.UserID, "error", err)
		return nil, fmt.Errorf("%w: %w", ErrUserNotFound, err)
	}
	if user == nil {
		return nil, ErrUserNotFound
	}

	user.Email = ver.Identifier
	if err := s.UserService.UpdateUser(user); err != nil {
		slog.Error("failed to update user email", "user_id", user.ID, "error", err)
		return nil, fmt.Errorf("failed to update user email: %w", err)
	}

	if err := s.VerificationService.DeleteVerification(ver.ID); err != nil {
		slog.Warn("failed to delete verification", "verification_id", ver.ID, "error", err)
	}

	s.callHook(s.config.Hooks.OnChangedEmail, user)

	return &EmailChangeResult{
		Message: "Email changed successfully",
		User:    user,
	}, nil
}
