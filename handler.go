package auth

import (
	"errors"
	"github.com/mohammadMghi/go-auth-iGhe3/base"
	"github.com/mohammadMghi/go-auth-iGhe3/handler"
	"github.com/mohammadMghi/go-auth-iGhe3/password"
	"github.com/mohammadMghi/go-auth-iGhe3/refresh"
	"math/rand"
	"net/http"
	"time"
)

type Handler struct {
	config *Config
}

func (h *Handler) Initialize(config *Config, baseConfig interface{}) (err error) {
	rand.Seed(time.Now().UTC().UnixNano())
	if config == nil {
		err = errors.New("config can not be null")
		return
	}
	if config.TokenExp == 0 {
		config.TokenExp = time.Minute * 15
	}
	if config.RefreshTokenExp == 0 {
		config.RefreshTokenExp = 7 * 24 * time.Hour
	}
	if config.LoginHandler == nil {
		config.LoginHandler = &handler.JwtLoginHandler{}
	}
	config.LoginHandler.Initialize(config.LoginHandler)
	config.InitializeConfig(baseConfig)
	base.Initialize(&config.Config)
	if config.Password != nil {
		if config.Password.LoginHandler == nil {
			config.Password.LoginHandler = config.LoginHandler
		}
		password.Initialize(config.Router, config.Password)
	}
	refresh.Initialize(config.Router)
	if config.CookieEnabled {
		if config.CookiePattern == nil {
			config.CookiePattern = &http.Cookie{
				Name:     "AccessToken",
				Path:     "/",
				Secure:   false,
				HttpOnly: false,
			}
		}
	}
	h.config = config
	if config.AuthRouters != nil {
		for _, routes := range config.AuthRouters {
			routes.Any(h.middleware)
		}
	}
	return
}
