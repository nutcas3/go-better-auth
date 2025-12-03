package auth

import (
	"log/slog"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/GoBetterAuth/go-better-auth/pkg/domain"
)

type UserService struct {
	config *domain.Config
	db     *gorm.DB
}

func NewUserService(config *domain.Config, db *gorm.DB) *UserService {
	return &UserService{config: config, db: db}
}

// CreateUser creates a new user in the database.
func (s *UserService) CreateUser(user *domain.User) error {
	user.ID = uuid.NewString()
	user.CreatedAt = time.Now().UTC()
	user.UpdatedAt = time.Now().UTC()

	if s.config.DatabaseHooks.Users != nil && s.config.DatabaseHooks.Users.BeforeCreate != nil {
		if err := s.config.DatabaseHooks.Users.BeforeCreate(user); err != nil {
			return err
		}
	}

	if err := s.db.Create(user).Error; err != nil {
		return err
	}

	if s.config.DatabaseHooks.Users != nil && s.config.DatabaseHooks.Users.AfterCreate != nil {
		go func() {
			if err := s.config.DatabaseHooks.Users.AfterCreate(*user); err != nil {
				slog.Error("user after create hook failed", "error", err.Error())
			}
		}()
	}

	return nil
}

// GetUserByID retrieves a user by their ID.
func (s *UserService) GetUserByID(id string) (*domain.User, error) {
	var user domain.User
	if err := s.db.First(&user, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

// GetUserByEmail retrieves a user by their email.
func (s *UserService) GetUserByEmail(email string) (*domain.User, error) {
	var user domain.User
	if err := s.db.Where("email = ?", email).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

// UpdateUser updates an existing user in the database.
func (s *UserService) UpdateUser(user *domain.User) error {
	user.UpdatedAt = time.Now().UTC()

	if s.config.DatabaseHooks.Users != nil && s.config.DatabaseHooks.Users.BeforeUpdate != nil {
		if err := s.config.DatabaseHooks.Users.BeforeUpdate(user); err != nil {
			return err
		}
	}

	if err := s.db.Save(user).Error; err != nil {
		return err
	}

	if s.config.DatabaseHooks.Users != nil && s.config.DatabaseHooks.Users.AfterUpdate != nil {
		go func() {
			if err := s.config.DatabaseHooks.Users.AfterUpdate(*user); err != nil {
				slog.Error("user after update hook failed", "error", err.Error())
			}
		}()
	}

	return nil
}
