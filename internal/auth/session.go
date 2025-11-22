package auth

import (
	"fmt"
	"log/slog"
	"time"
)

// CreateSession creates a new session for a user
func (s *Service) CreateSession(userID string) (string, error) {
	if userID == "" {
		return "", fmt.Errorf("user ID is required")
	}

	token, err := s.TokenService.GenerateToken()
	if err != nil {
		slog.Error("failed to generate token", "error", err)
		return "", fmt.Errorf("%w: %w", ErrTokenGenerationFailed, err)
	}

	_, err = s.SessionService.CreateSession(userID, s.TokenService.HashToken(token))
	if err != nil {
		slog.Error("failed to create session", "user_id", userID, "error", err)
		return "", fmt.Errorf("%w: %w", ErrSessionCreationFailed, err)
	}

	return token, nil
}

// RefreshSession refreshes an existing session token
func (s *Service) RefreshSession(sessionToken string) (string, error) {
	if sessionToken == "" {
		return "", ErrInvalidToken
	}

	// Get existing session
	sess, err := s.SessionService.GetSessionByToken(s.TokenService.HashToken(sessionToken))
	if err != nil {
		slog.Error("failed to get session", "error", err)
		return "", fmt.Errorf("%w: %w", ErrSessionNotFound, err)
	}
	if sess == nil {
		return "", ErrSessionNotFound
	}

	// Check if session is expired
	if time.Now().UTC().After(sess.ExpiresAt) {
		return "", ErrSessionExpired
	}

	// Generate new token
	newToken, err := s.TokenService.GenerateToken()
	if err != nil {
		slog.Error("failed to generate new token", "error", err)
		return "", fmt.Errorf("%w: %w", ErrTokenGenerationFailed, err)
	}

	// Delete old session
	if err := s.SessionService.DeleteSessionByID(sess.ID); err != nil {
		slog.Warn("failed to delete old session", "session_id", sess.ID, "error", err)
	}

	// Create new session
	_, err = s.SessionService.CreateSession(sess.UserID, s.TokenService.HashToken(newToken))
	if err != nil {
		slog.Error("failed to create new session", "user_id", sess.UserID, "error", err)
		return "", fmt.Errorf("%w: %w", ErrSessionCreationFailed, err)
	}

	return newToken, nil
}

// DeleteSession deletes a session
func (s *Service) DeleteSession(sessionToken string) error {
	if sessionToken == "" {
		return ErrInvalidToken
	}

	sess, err := s.SessionService.GetSessionByToken(s.TokenService.HashToken(sessionToken))
	if err != nil {
		slog.Error("failed to get session", "error", err)
		return fmt.Errorf("%w: %w", ErrSessionNotFound, err)
	}
	if sess == nil {
		return ErrSessionNotFound
	}

	if err := s.SessionService.DeleteSessionByID(sess.ID); err != nil {
		slog.Error("failed to delete session", "session_id", sess.ID, "error", err)
		return fmt.Errorf("%w: %w", ErrSessionDeletionFailed, err)
	}

	return nil
}

// Define missing error variable
var ErrSessionExpired = fmt.Errorf("session expired")
