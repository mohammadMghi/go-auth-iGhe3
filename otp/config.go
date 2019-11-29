package otp

import (
	"github.com/go-m/auth/base"
	"time"
)

type Config struct {
	LoginHandler base.ILoginHandler

	CodeExpiration time.Duration
}
