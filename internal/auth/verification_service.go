package auth

import (
	"log/slog"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/GoBetterAuth/go-better-auth/pkg/domain"
)

type VerificationService struct {
	config *domain.Config
	db     *gorm.DB
}

func NewVerificationService(config *domain.Config, db *gorm.DB) *VerificationService {
	return &VerificationService{config: config, db: db}
}

// Creates a new verification record
func (s *VerificationService) CreateVerification(v *domain.Verification) error {
	v.ID = uuid.NewString()

	now := time.Now().UTC()
	v.CreatedAt = now
	v.UpdatedAt = now
	slog.Debug("Setting ExpiresAt now...")
	v.ExpiresAt = now.Add(time.Hour)

	if s.config.DatabaseHooks.Verifications != nil && s.config.DatabaseHooks.Verifications.BeforeCreate != nil {
		if err := s.config.DatabaseHooks.Verifications.BeforeCreate(v); err != nil {
			return err
		}
	}

	if err := s.db.Create(v).Error; err != nil {
		return err
	}

	if s.config.DatabaseHooks.Verifications != nil && s.config.DatabaseHooks.Verifications.AfterCreate != nil {
		if err := s.config.DatabaseHooks.Verifications.AfterCreate(v); err != nil {
			return err
		}
	}

	return nil
}

// Retrieves a verification record by token
func (s *VerificationService) GetVerificationByToken(token string) (*domain.Verification, error) {
	var v domain.Verification
	if err := s.db.Where("token = ?", token).First(&v).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &v, nil
}

// Deletes a verification record by ID
func (s *VerificationService) DeleteVerification(id string) error {
	return s.db.Delete(&domain.Verification{}, "id = ?", id).Error
}

// Checks if the verification token is expired
func (s *VerificationService) IsExpired(verification *domain.Verification) bool {
	return time.Now().UTC().After(verification.ExpiresAt)
}
