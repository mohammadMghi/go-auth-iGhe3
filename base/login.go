package base

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"math/rand"
	"net/http"
	"time"
)

type ILoginHandler interface {
	Initialize(handler ILoginHandler)
	GetProperties(key string, keyType KeyType) (properties map[string]interface{})
	Login(config *Config, key string, keyType KeyType) (result interface{}, cookies []*http.Cookie, err error)
}

type JwtLoginHandler struct {
	ILoginHandler

	SecretKey     []byte
	SigningMethod jwt.SigningMethod
}

func (h *JwtLoginHandler) Initialize(handler ILoginHandler) {
	if h.SigningMethod == nil {
		h.SigningMethod = jwt.SigningMethodHS256
	}
	if h.SecretKey == nil {
		h.SecretKey = []byte("secret key")
	}
	h.ILoginHandler = handler
}

func (h *JwtLoginHandler) GetProperties(key string, keyType KeyType) (properties map[string]interface{}) {
	properties = map[string]interface{}{}
	return
}

func (h *JwtLoginHandler) NewRefreshToken(key string, keyType KeyType, exp time.Duration) (token string, err error) {
	b := make([]byte, 32)
	_, err = rand.Read(b)
	if err != nil {
		return
	}
	token = fmt.Sprintf("%x", b)
	err = RedisHandler.Set("refresh:"+token, refreshToken{
		Token:   token,
		Exp:     exp,
		Key:     key,
		KeyType: keyType,
	}, exp)
	return
}

func (h *JwtLoginHandler) Login(config *Config, key string, keyType KeyType) (result interface{},
	cookies []*http.Cookie, err error) {
	properties := h.ILoginHandler.GetProperties(key, keyType)
	claims := jwt.MapClaims(properties)
	claims["nbf"] = time.Now().UTC().Format("2006-01-02T15:04:05Z")
	expAt := time.Now().Add(time.Second*time.Duration(config.TokenExpSecs) +
		time.Second).UTC().Format("2006-01-02T15:04:05Z")
	claims["exp"] = expAt
	token := jwt.NewWithClaims(h.SigningMethod, claims)
	tokenString, err := token.SignedString(h.SecretKey)
	if err != nil {
		return
	}
	refreshExp := time.Second * time.Duration(config.RefreshTokenExpSecs)
	refreshToken, err := h.NewRefreshToken(key, keyType, refreshExp)
	if err != nil {
		return
	}
	result = map[string]interface{}{
		"access_token":       tokenString,
		"refresh_token":      refreshToken,
		"expires_in":         config.TokenExpSecs,
		"refresh_expires_in": config.RefreshTokenExpSecs,
	}
	if CurrentConfig.CookieEnabled {
		cookies = []*http.Cookie{
			{
				Name:     CurrentConfig.CookiePattern.Name,
				Value:    tokenString,
				MaxAge:   config.TokenExpSecs,
				Path:     CurrentConfig.CookiePattern.Path,
				Secure:   CurrentConfig.CookiePattern.Secure,
				HttpOnly: CurrentConfig.CookiePattern.HttpOnly,
			},
		}
	}
	return
}
