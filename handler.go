package auth

import (
	"errors"
	"github.com/go-m/auth/base"
	"github.com/go-m/auth/handler"
	"github.com/go-m/auth/otp"
	"github.com/go-m/auth/password"
	"github.com/go-m/auth/refresh"
	"math/rand"
	"net/http"
	"regexp"
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
	if config.Otp != nil {
		if config.Otp.LoginHandler == nil {
			config.Otp.LoginHandler = config.LoginHandler
		}
		config.Otp.LoginHandler.Initialize(config.Otp.LoginHandler)
		if config.Otp.MobileValidationRegexPattern == nil {
			regex := `^(\(\d{1,3}\))(\d{10})$`
			config.Otp.MobileValidationRegexPattern = &regex
		}
		if *config.Otp.MobileValidationRegexPattern != "" {
			config.Otp.MobileValidationRegex, err = regexp.Compile(*config.Otp.MobileValidationRegexPattern)
		}
		otp.Initialize(config.Router, config.Otp)
	}
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
	if config.OptionalAuthOnAnyRequest {
		if config.AuthRouters != nil {
			for _, routes := range config.AuthRouters {
				routes.Any(middleware)
			}
		}
	}
	return
}
