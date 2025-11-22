package auth

import (
	"github.com/GoBetterAuth/go-better-auth/pkg/domain"
)

// callHook safely calls a hook function if it's not nil
func (s *Service) callHook(hook func(domain.User) error, u *domain.User) {
	if hook != nil && u != nil {
		go hook(*u)
	}
}
