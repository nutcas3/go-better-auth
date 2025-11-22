package auth

import (
	"fmt"
	"log/slog"
)

// SignOut handles user sign-out by deleting their session
func (s *Service) SignOut(sessionToken string) error {
	if sessionToken == "" {
		return ErrInvalidToken
	}

	// Find session by token
	sess, err := s.SessionService.GetSessionByToken(s.TokenService.HashToken(sessionToken))
	if err != nil {
		slog.Error("failed to get session by token", "error", err)
		return fmt.Errorf("%w: %w", ErrSessionNotFound, err)
	}
	if sess == nil {
		return ErrSessionNotFound
	}

	// Delete the session
	if err := s.SessionService.DeleteSessionByID(sess.ID); err != nil {
		slog.Error("failed to delete session", "session_id", sess.ID, "error", err)
		return fmt.Errorf("%w: %w", ErrSessionDeletionFailed, err)
	}

	return nil
}
