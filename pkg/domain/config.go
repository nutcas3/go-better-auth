package domain

import (
	"os"
	"time"
)

// =======================
// Main Config Structure
// =======================

// Config holds all configurable options for the GoBetterAuth library.
type Config struct {
	AppName           string
	BaseURL           string
	BasePath          string
	Secret            string
	Database          DatabaseConfig
	EmailPassword     EmailPasswordConfig
	EmailVerification EmailVerificationConfig
	User              UserConfig
	Session           SessionConfig
	TrustedOrigins    TrustedOriginsConfig
	DatabaseHooks     DatabaseHooksConfig
	Hooks             HooksConfig
}

// =======================
// Functional Options
// =======================

type ConfigOption func(*Config)

// NewConfig builds a Config using functional options with sensible defaults.
func NewConfig(opts ...ConfigOption) *Config {
	baseURL := os.Getenv("GO_BETTER_AUTH_BASE_URL")
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}

	secret := os.Getenv("GO_BETTER_AUTH_SECRET")
	if secret == "" {
		env := os.Getenv("GO_ENV")
		// Must be set in production
		if env == "production" {
			panic("GO_BETTER_AUTH_SECRET environment variable must be set in production")
		}
		// Use default secret for non-production environments
		secret = "go-better-auth-secret-0123456789"
	}

	// Define sensible defaults first
	c := &Config{
		AppName:  "GoBetterAuth",
		BaseURL:  baseURL,
		BasePath: "/auth",
		Secret:   secret,
		Database: DatabaseConfig{
			MaxOpenConns:    25,
			MaxIdleConns:    5,
			ConnMaxLifetime: time.Hour,
		},
		EmailPassword: EmailPasswordConfig{
			Enabled:                  false,
			RequireEmailVerification: false,
			MinPasswordLength:        8,
			MaxPasswordLength:        32,
		},
		EmailVerification: EmailVerificationConfig{
			AutoSignIn:   false,
			SendOnSignUp: false,
			SendOnSignIn: false,
			ExpiresIn:    1 * time.Hour,
		},
		User: UserConfig{
			ChangeEmail: ChangeEmailConfig{},
		},
		Session: SessionConfig{
			CookieName: "go-better-auth.session_token",
			ExpiresIn:  7 * 24 * time.Hour, // (default: 7 days)
			UpdateAge:  24 * time.Hour,
		},
		TrustedOrigins: TrustedOriginsConfig{
			Origins: []string{},
		},
		DatabaseHooks: DatabaseHooksConfig{},
		Hooks:         HooksConfig{},
	}

	// Apply the options
	for _, opt := range opts {
		opt(c)
	}

	return c
}

// =======================
// Database Config
// =======================

type DatabaseConfig struct {
	Provider         string
	ConnectionString string
	MaxOpenConns     int
	MaxIdleConns     int
	ConnMaxLifetime  time.Duration
}

// =======================
// Email/Password Auth Config
// =======================

type EmailPasswordConfig struct {
	Enabled                  bool
	MinPasswordLength        int
	MaxPasswordLength        int
	DisableSignUp            bool
	RequireEmailVerification bool
	AutoSignIn               bool
	SendResetPassword        func(user User, url string, token string) error
	ResetTokenExpiry         time.Duration
	Password                 *PasswordConfig
}

// =======================
// Password Config
// =======================

type PasswordConfig struct {
	Hash   func(password string) (string, error)
	Verify func(hashedPassword, password string) bool
}

// =======================
// Email Verification Config
// =======================

type EmailVerificationConfig struct {
	SendVerificationEmail func(user User, url string, token string) error
	AutoSignIn            bool
	SendOnSignUp          bool
	SendOnSignIn          bool
	ExpiresIn             time.Duration
}

// =======================
// User Config
// =======================

type UserConfig struct {
	ChangeEmail ChangeEmailConfig
}

type ChangeEmailConfig struct {
	Enabled                     bool
	SendEmailChangeVerification func(user User, newEmail string, url string, token string) error
}

// =======================
// SessionConfig Config
// =======================

type SessionConfig struct {
	ExpiresIn  time.Duration
	UpdateAge  time.Duration
	CookieName string
}

// =======================
// Trutsted Origins Config
// =======================

type TrustedOriginsConfig struct {
	Origins []string
}

// =======================
// DatabaseHooks Config
// =======================

type DatabaseHooksConfig struct {
	Users         *UserDatabaseHooksConfig
	Accounts      *AccountDatabaseHooksConfig
	Sessions      *SessionDatabaseHooksConfig
	Verifications *VerificationDatabaseHooksConfig
}

type UserDatabaseHooksConfig struct {
	BeforeCreate func(user *User) error
	AfterCreate  func(user User) error
	BeforeUpdate func(user *User) error
	AfterUpdate  func(user User) error
}

type AccountDatabaseHooksConfig struct {
	BeforeCreate func(account *Account) error
	AfterCreate  func(account Account) error
	BeforeUpdate func(account *Account) error
	AfterUpdate  func(account Account) error
}

type SessionDatabaseHooksConfig struct {
	BeforeCreate func(session *Session) error
	AfterCreate  func(session Session) error
}

type VerificationDatabaseHooksConfig struct {
	BeforeCreate func(verification *Verification) error
	AfterCreate  func(verification Verification) error
}

// =======================
// Hooks Config
// =======================

type HooksConfig struct {
	OnUserSignedUp    func(user User) error
	OnUserLoggedIn    func(user User) error
	OnEmailVerified   func(user User) error
	OnPasswordChanged func(user User) error
	OnEmailChanged    func(user User) error
}

// =======================
// Functional Options
// =======================

func WithAppName(name string) ConfigOption {
	return func(c *Config) {
		c.AppName = name
	}
}

func WithBaseURL(url string) ConfigOption {
	return func(c *Config) {
		c.BaseURL = url
	}
}

func WithBasePath(path string) ConfigOption {
	return func(c *Config) {
		c.BasePath = path
	}
}

func WithSecret(secret string) ConfigOption {
	return func(c *Config) {
		c.Secret = secret
	}
}

func WithDatabase(db DatabaseConfig) ConfigOption {
	return func(c *Config) {
		c.Database = db
	}
}

func WithEmailPassword(config EmailPasswordConfig) ConfigOption {
	return func(c *Config) {
		c.EmailPassword = config
	}
}

func WithEmailVerification(config EmailVerificationConfig) ConfigOption {
	return func(c *Config) {
		c.EmailVerification = config
	}
}

func WithUser(userConfig UserConfig) ConfigOption {
	return func(c *Config) {
		c.User = userConfig
	}
}

func WithSession(sessionConfig SessionConfig) ConfigOption {
	return func(c *Config) {
		c.Session = sessionConfig
	}
}

func WithTrustedOrigins(trustedOriginsConfig TrustedOriginsConfig) ConfigOption {
	return func(c *Config) {
		c.TrustedOrigins = trustedOriginsConfig
	}
}

func WithDatabaseHooks(databaseHooksConfig DatabaseHooksConfig) ConfigOption {
	return func(c *Config) {
		c.DatabaseHooks = databaseHooksConfig
	}
}

func WithHooks(hooksConfig HooksConfig) ConfigOption {
	return func(c *Config) {
		c.Hooks = hooksConfig
	}
}
