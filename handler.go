package auth

import (
	"errors"
	"github.com/go-m/auth/base"

	"github.com/go-m/auth/otp"
)

type Handler struct {
	config *Config
}

func (h *Handler) Initialize(config *Config, baseConfig interface{}) (err error) {
	if config == nil {
		err = errors.New("config can not be null")
		return
	}
	if config.TokenExpSecs == 0 {
		config.TokenExpSecs = 15 * 60 // 15 minutes
	}
	if config.RefreshTokenExpSecs == 0 {
		config.RefreshTokenExpSecs = 7 * 24 * 60 * 60 // one week
	}
	if config.LoginHandler == nil {
		config.LoginHandler = &base.JwtLoginHandler{}
	}
	config.LoginHandler.Initialize(config.LoginHandler)
	config.InitializeConfig(baseConfig)
	base.Initialize(&config.Config)
	if config.Otp != nil {
		if config.Otp.LoginHandler == nil {
			config.Otp.LoginHandler = config.LoginHandler
		}
		config.Otp.LoginHandler.Initialize(config.Otp.LoginHandler)
		otp.Initialize(config.Router, config.Otp)
	}
	h.config = config
	return
}
