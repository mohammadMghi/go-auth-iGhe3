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

type JwtAuthorization struct {
	base.Authorization

	ParsedToken jwt.Token
	Claims      jwt.MapClaims
}

func (a *JwtAuthorization) GetCurrentAccountId(request gm.IRequest) (id interface{}) {
	id, _ = a.Claims["id"]
	return
}

func (a *JwtAuthorization) GetBase() gm.IAuthorization {
	return a
}

type JwtLoginHandler struct {
	base.ILoginHandler

	SecretKey     []byte
	SigningMethod jwt.SigningMethod
}

func (h *JwtLoginHandler) Initialize(handler base.ILoginHandler) {
	if h.SigningMethod == nil {
		h.SigningMethod = jwt.SigningMethodHS256
	}
	if h.SecretKey == nil {
		h.SecretKey = []byte("secret key")
	}
	h.ILoginHandler = handler
}

func (h *JwtLoginHandler) NewAuthorization(request gm.IRequest, authInfo interface{}) gm.IAuthorization {
	auth := &JwtAuthorization{
		Authorization: base.Authorization{
			Token: authInfo.(string),
		},
	}
	auth.Initialize(request, auth)
	return auth
}

func (h *JwtLoginHandler) GetProperties(key string, keyType base.KeyType) (properties map[string]interface{}, err error) {
	properties = map[string]interface{}{}
	return
}

func (h *JwtLoginHandler) Refresh(config *base.Config, token string) (result interface{},
	cookies []*http.Cookie, err error) {
	return
}

func (h *JwtLoginHandler) HandleError(request gm.IRequest, err error) (handled bool) {
	if err == nil {
		return false
	}
	e, ok := err.(*errors.Error)
	if !ok {
		err = errors.GetUnAuthorizedError(request)
		e = err.(*errors.Error)
	}
	req := request.GetBaseRequest()
	req.Context.JSON(e.Status, e)
	req.Context.Abort()
	return true
}

func (h *JwtLoginHandler) Login(request gm.IRequest, config *base.Config, key string,
	keyType base.KeyType) (result interface{}, headers map[string]string,
	cookies []*http.Cookie, err error) {
	info, err := h.ILoginHandler.GetInfo(request, key, keyType)
	if err != nil {
		return
	}
	var properties map[string]interface{}
	var accountID interface{}
	if info != nil {
		properties = info.GetProperties()
		accountID = info.GetAccountID()
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
	refreshToken, err := refresh.New(accountID, key, keyType, config.RefreshTokenExp)
	if err != nil {
		return
	}
	expiresIn := int(config.TokenExp.Seconds())
	resultMap := map[string]interface{}{
		"access_token":       tokenString,
		"refresh_token":      refreshToken.Value,
		"expires_in":         expiresIn,
		"refresh_expires_in": int(config.RefreshTokenExp.Seconds()),
	}
	if info != nil {
		extraData := info.GetExtraData()
		if extraData != nil {
			for k, v := range extraData {
				resultMap[k] = v
			}
		}
	}
	result = resultMap
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
	req.Auth = h.ILoginHandler.NewAuthorization(request, tokenString)
	return
}

func (h *JwtLoginHandler) Authenticate(request gm.IRequest) (err error) {
	req := request.GetBaseRequest()
	var authToken string
	// get authToken
	if req.Auth != nil {
		return
	} else {
		authToken = req.Context.GetHeader("Authorization")
		if authToken == "" {
			if base.CurrentConfig.CookieEnabled {
				authToken, err = req.Context.Cookie(base.CurrentConfig.CookiePattern.Name)
				if err != nil {
					return
				}
			}
		}
		if len(authToken) < 7 || strings.ToLower(authToken[:6]) != "bearer" {
			err = errors.GetUnAuthorizedError(request)
			return
		}
		authToken = authToken[7:]
		authToken = strings.TrimSpace(authToken)
	}
	// parse & validate auth token
	parsed, err := jwt.Parse(authToken, func(token *jwt.Token) (interface{}, error) {
		return h.SecretKey, nil
	})
	if err != nil {
		return
	}
	// just authenticated
	isFirstTime := req.Auth == nil // determines if its first time authentication handled
	// ensure auth is set in request model
	if req.Auth == nil {
		req.Auth = h.ILoginHandler.NewAuthorization(request, authToken)
	}
	jwtAuth := req.Auth.GetBase().(*JwtAuthorization)
	jwtAuth.Claims = parsed.Claims.(jwt.MapClaims)
	unixNow := time.Now().UTC().Unix()
	jwtAuth.IsAuthenticated = parsed.Valid &&
		jwtAuth.Claims.VerifyExpiresAt(unixNow, true) &&
		jwtAuth.Claims.VerifyNotBefore(unixNow, true)
	rolesFace, exists := jwtAuth.Claims["roles"]
	if exists {
		roles := make([]string, 0)
		for _, roleFace := range rolesFace.([]interface{}) {
			roles = append(roles, roleFace.(string))
		}
		jwtAuth.Roles = roles
	}
	if isFirstTime {
		req.Auth.Initialize(request, req.Auth)
	}
	return
}

func (h *JwtLoginHandler) MustAuthenticate() g.HandlerFunc {
	return func(request gm.IRequest) (result interface{}) {
		var err error
		defer func() {
			h.HandleError(request, err)
		}()
		err = h.Authenticate(request)
		if err != nil {
			return
		}
		auth := request.GetAuth()
		if !auth.Authenticated() {
			err = errors.GetUnAuthorizedError(request)
			return
		}
		return
	}
}
func (h *JwtLoginHandler) MustHaveRole(roles ...string) g.HandlerFunc {
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
		auth := request.GetAuth().GetBase().(*JwtAuthorization)
		if !auth.IsAuthenticated {
			err = errors.GetUnAuthorizedError(request)
			return
		}
		hasRole := func() bool {
			for _, role := range roles {
				if role == "id" {
					// check id matches with current request id
					currentID, _ := auth.Claims["id"]
					if req.ID == currentID {
						return true
					}
					continue
				}
				if iCurrentRoles, ok := auth.Claims["roles"]; ok {
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
			err = errors.GetForbiddenError(request)
			return
		}
		return
	}
}
