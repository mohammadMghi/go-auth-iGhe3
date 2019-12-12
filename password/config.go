package password

import (
	"github.com/go-m/auth/base"
)

type Config struct {
	LoginHandler        base.ILoginHandler
	Handler             IHandler

	MaxRetries int
}

func (c *Config) Initialize() {
	if c.Handler == nil {
		c.Handler = &DefaultHandler{}
	}
	if c.MaxRetries == 0 {
		c.MaxRetries = 3
	}
}
