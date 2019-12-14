package password

import (
	"github.com/go-m/auth/base"
	"time"
)

type Config struct {
	LoginHandler base.ILoginHandler
	Handler      IHandler

	MaxRetries           int
	MaxRetriesExpiration time.Duration
}

func (c *Config) Initialize() {
	if c.Handler == nil {
		c.Handler = &DefaultHandler{}
	}
	if c.MaxRetries == 0 {
		c.MaxRetries = 3
	}
	if c.MaxRetriesExpiration == 0 {
		c.MaxRetriesExpiration = time.Hour
	}
}
