package handler

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	g "github.com/go-ginger/ginger"
	gm "github.com/go-ginger/models"
	"github.com/go-ginger/models/errors"
	"github.com/go-m/auth/base"
	"github.com/go-m/auth/refresh"
	"net/http"
	"strings"
	"time"
)

type Authorization struct {
	base.Authorization

	ParsedToken jwt.Token
	Claims      jwt.MapClaims
}

type Jwt struct {
	base.ILoginHandler
	*Authorization

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

func (h *Jwt) HandleError(request gm.IRequest, err error) (handled bool) {
	if err == nil {
		return false
	}
	e, ok := err.(errors.Error)
	if !ok {
		err = errors.GetUnAuthorizedError()
		e = err.(errors.Error)
	}
	req := request.GetBaseRequest()
	req.Context.JSON(e.Status, e)
	req.Context.Abort()
	return true
}

func (h *Jwt) Login(request gm.IRequest, config *base.Config, key string, keyType base.KeyType) (result interface{},
	headers map[string]string, cookies []*http.Cookie, err error) {
	properties, err := h.ILoginHandler.GetProperties(key, keyType)
	if err != nil {
		return
	}
	claims := jwt.MapClaims(properties)
	claims["nbf"] = time.Now().UTC().Unix()
	expAt := time.Now().Add(config.TokenExp + time.Second).UTC().Unix()
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
	req := request.GetBaseRequest()
	req.Auth = &Authorization{
		Authorization: base.Authorization{
			Token: tokenString,
		},
	}
	return
}

func (h *Jwt) Authenticate(request gm.IRequest) (err error) {
	req := request.GetBaseRequest()
	if req.Auth == nil {
		tokenStr := req.Context.GetHeader("Authorization")
		if tokenStr == "" {
			if base.CurrentConfig.CookieEnabled {
				tokenStr, err = req.Context.Cookie(base.CurrentConfig.CookiePattern.Name)
				if err != nil {
					return
				}
			}
		}
		if tokenStr == "" {
			err = errors.GetUnAuthorizedError()
			return
		}
		splitToken := strings.Split(tokenStr, "bearer")
		if len(splitToken) == 2 {
			tokenStr = strings.TrimSpace(splitToken[1])
		}
		req.Auth = &Authorization{
			Authorization: base.Authorization{
				Token: tokenStr,
			},
		}
	}
	authorization := req.Auth.(*Authorization)
	if authorization.IsAuthenticated {
		return
	}
	parsed, err := jwt.Parse(authorization.Token, func(token *jwt.Token) (interface{}, error) {
		return h.SecretKey, nil
	})
	if err != nil {
		return
	}
	authorization.Claims = parsed.Claims.(jwt.MapClaims)
	h.Authorization = authorization
	unixNow := time.Now().UTC().Unix()
	authorization.IsAuthenticated = parsed.Valid &&
		authorization.Claims.VerifyExpiresAt(unixNow, true) &&
		authorization.Claims.VerifyNotBefore(unixNow, true)
	return
}

func (h *Jwt) MustAuthenticate() g.HandlerFunc {
	return func(request gm.IRequest) (result interface{}) {
		var err error
		defer func() {
			h.HandleError(request, err)
		}()
		err = h.Authenticate(request)
		if err != nil {
			return
		}
		if !h.IsAuthenticated {
			err = errors.GetUnAuthorizedError()
			return
		}
		return
	}
}
func (h *Jwt) MustHaveRole(roles ...string) g.HandlerFunc {
	return func(request gm.IRequest) (result interface{}) {
		req := request.GetBaseRequest()
		var err error
		defer func() {
			if err != nil {
				h.HandleError(request, err)
			}
		}()
		err = h.Authenticate(request)
		if err != nil {
			return
		}
		if !h.IsAuthenticated {
			err = errors.GetUnAuthorizedError()
			return
		}
		hasRole := func() bool {
			for _, role := range roles {
				if role == "id" {
					// check id matches with current request id
					currentID, _ := h.Authorization.Claims["id"]
					if req.ID == currentID {
						return true
					}
					continue
				}
				if iCurrentRoles, ok := h.Authorization.Claims["roles"]; ok {
					currentRoles := iCurrentRoles.([]interface{})
					for _, currentRole := range currentRoles {
						if role == currentRole {
							return true
						}
					}
				}
			}
			return false
		}()
		if !hasRole {
			err = errors.GetForbiddenError()
			return
		}
		return
	}
}
