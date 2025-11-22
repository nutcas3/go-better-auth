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

// NewConfig builds a Config using functional options.
func NewConfig() *Config {
	baseURL := os.Getenv("GO_BETTER_AUTH_URL")
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
	SendResetPassword        func(user *User, url string, token string) error
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
	SendVerificationEmail func(user *User, url string, token string) error
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
	SendEmailChangeVerification func(user *User, newEmail string, url string, token string) error
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
	AfterCreate  func(user *User) error
	BeforeUpdate func(user *User) error
	AfterUpdate  func(user *User) error
}

type AccountDatabaseHooksConfig struct {
	BeforeCreate func(account *Account) error
	AfterCreate  func(account *Account) error
	BeforeUpdate func(account *Account) error
	AfterUpdate  func(account *Account) error
}

type SessionDatabaseHooksConfig struct {
	BeforeCreate func(session *Session) error
	AfterCreate  func(session *Session) error
	BeforeUpdate func(session *Session) error
	AfterUpdate  func(session *Session) error
}

type VerificationDatabaseHooksConfig struct {
	BeforeCreate func(verification *Verification) error
	AfterCreate  func(verification *Verification) error
}

// =======================
// Hooks Config
// =======================

type HooksConfig struct {
	OnUserSignedUp    func(user User) error
	OnUserLoggedIn    func(user User) error
	OnEmailVerified   func(user User) error
	OnEmailChanged    func(user User) error
	OnPasswordChanged func(user User) error
}

// =======================
// Builder Methods
// =======================

func (c *Config) WithAppName(name string) *Config {
	c.AppName = name
	return c
}

func (c *Config) WithBaseURL(url string) *Config {
	c.BaseURL = url
	return c
}

func (c *Config) WithBasePath(path string) *Config {
	c.BasePath = path
	return c
}

func (c *Config) WithSecret(secret string) *Config {
	c.Secret = secret
	return c
}

func (c *Config) WithDatabase(db DatabaseConfig) *Config {
	c.Database = db
	return c
}

func (c *Config) WithEmailPassword(config EmailPasswordConfig) *Config {
	c.EmailPassword = config
	return c
}

func (c *Config) WithEmailVerification(config EmailVerificationConfig) *Config {
	c.EmailVerification = config
	return c
}

func (c *Config) WithUser(userConfig UserConfig) *Config {
	c.User = userConfig
	return c
}

func (c *Config) WithSession(sessionConfig SessionConfig) *Config {
	c.Session = sessionConfig
	return c
}

func (c *Config) WithTrustedOrigins(trustedOriginsConfig TrustedOriginsConfig) *Config {
	c.TrustedOrigins = trustedOriginsConfig
	return c
}

func (c *Config) WithDatabaseHooks(databaseHooksConfig DatabaseHooksConfig) *Config {
	c.DatabaseHooks = databaseHooksConfig
	return c
}

func (c *Config) WithHooks(hooksConfig HooksConfig) *Config {
	c.Hooks = hooksConfig
	return c
}
