package handler

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-m/auth/base"
	"github.com/go-m/auth/refresh"
	"net/http"
	"time"
)

type Jwt struct {
	base.ILoginHandler

	SecretKey     []byte
	SigningMethod jwt.SigningMethod
}

func (h *Jwt) Initialize(handler base.ILoginHandler) {
	if h.SigningMethod == nil {
		h.SigningMethod = jwt.SigningMethodHS256
	}
	if h.SecretKey == nil {
		h.SecretKey = []byte("secret key")
	}
	h.ILoginHandler = handler
}

func (h *Jwt) GetProperties(key string, keyType base.KeyType) (properties map[string]interface{}, err error) {
	properties = map[string]interface{}{}
	return
}

func (h *Jwt) Refresh(config *base.Config, token string) (result interface{},
	cookies []*http.Cookie, err error) {
	return
}

func (h *Jwt) Login(config *base.Config, key string, keyType base.KeyType) (result interface{},
	headers map[string]string, cookies []*http.Cookie, err error) {
	properties, err := h.ILoginHandler.GetProperties(key, keyType)
	if err != nil {
		return
	}
	claims := jwt.MapClaims(properties)
	claims["nbf"] = time.Now().UTC().Format("2006-01-02T15:04:05Z")
	expAt := time.Now().Add(config.TokenExp + time.Second).UTC().Format("2006-01-02T15:04:05Z")
	claims["exp"] = expAt
	token := jwt.NewWithClaims(h.SigningMethod, claims)
	tokenString, err := token.SignedString(h.SecretKey)
	if err != nil {
		return
	}
	refreshToken, err := refresh.New(key, keyType, config.RefreshTokenExp)
	if err != nil {
		return
	}
	expiresIn := int(config.TokenExp.Seconds())
	result = map[string]interface{}{
		"access_token":       tokenString,
		"refresh_token":      refreshToken.Value,
		"expires_in":         expiresIn,
		"refresh_expires_in": int(config.RefreshTokenExp.Seconds()),
	}
	if base.CurrentConfig.AllowAuthResponseHeaders {
		headers = map[string]string{
			"X-Access-Token":                         tokenString,
			base.CurrentConfig.RefreshTokenHeaderKey: refreshToken.Value,
			"X-Expires-In":                           fmt.Sprintf("%v", expiresIn),
			"X-Refresh-Expires-In":                   fmt.Sprintf("%v", int(config.RefreshTokenExp.Seconds())),
		}
	}
	if base.CurrentConfig.CookieEnabled {
		cookies = []*http.Cookie{
			{
				Name:     base.CurrentConfig.CookiePattern.Name,
				Value:    tokenString,
				MaxAge:   expiresIn,
				Path:     base.CurrentConfig.CookiePattern.Path,
				Secure:   base.CurrentConfig.CookiePattern.Secure,
				HttpOnly: base.CurrentConfig.CookiePattern.HttpOnly,
			},
		}
	}
	return
}
