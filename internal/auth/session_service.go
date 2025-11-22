package auth

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/GoBetterAuth/go-better-auth/pkg/domain"
)

type SessionService struct {
	config *domain.Config
	db     *gorm.DB
}

func NewSessionService(config *domain.Config, db *gorm.DB) *SessionService {
	return &SessionService{config: config, db: db}
}

// CreateSession creates a new session for a user
func (s *SessionService) CreateSession(userID string, token string) (*domain.Session, error) {
	sess := &domain.Session{
		ID:        uuid.NewString(),
		UserID:    userID,
		Token:     token,
		ExpiresAt: time.Now().UTC().Add(7 * 24 * time.Hour),
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}

	if s.config.DatabaseHooks.Sessions != nil && s.config.DatabaseHooks.Sessions.BeforeCreate != nil {
		if err := s.config.DatabaseHooks.Sessions.BeforeCreate(sess); err != nil {
			return nil, err
		}
	}

	if err := s.db.Create(sess).Error; err != nil {
		return nil, err
	}

	if s.config.DatabaseHooks.Sessions != nil && s.config.DatabaseHooks.Sessions.AfterCreate != nil {
		if err := s.config.DatabaseHooks.Sessions.AfterCreate(sess); err != nil {
			return nil, err
		}
	}

	return sess, nil
}

// GetSessionByUserID retrieves a session by the associated userID.
func (s *SessionService) GetSessionByUserID(userID string) (*domain.Session, error) {
	var sess domain.Session
	if err := s.db.Where("user_id = ?", userID).First(&sess).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &sess, nil
}

// GetSessionByToken retrieves a session by its token.
func (s *SessionService) GetSessionByToken(token string) (*domain.Session, error) {
	var sess domain.Session
	if err := s.db.Where("token = ?", token).First(&sess).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &sess, nil
}

// DeleteSessionByID deletes a session by its ID.
func (s *SessionService) DeleteSessionByID(ID string) error {
	return s.db.Where("id = ?", ID).Delete(&domain.Session{}).Error
}
