package password

import (
	"fmt"
	g "github.com/go-ginger/ginger"
	gm "github.com/go-ginger/models"
	"github.com/go-ginger/models/errors"
	"github.com/go-m/auth/base"
	"github.com/go-m/auth/refresh"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"golang.org/x/crypto/bcrypt"
)

type IHandler interface {
	Initialize(handler IHandler)
	HashPassword(password string) (hash string, err error)
	VerifyPassword(hash string, password string) (err error)
	ValidateKey(key string) (err error)
	NormalizeKey(key string) (normalized string)
	ValidatePass(pass string) (err error)
	VerifyPass(request gm.IRequest, key string, keyType base.KeyType, pass string) (err error)
	VerifyPassById(request gm.IRequest, id interface{}, pass string) (err error)
	Login(request gm.IRequest) (key string, keyType base.KeyType, err error)
	ValidateChangePass(request gm.IRequest, oldPass string, newPass string) (err error)
	DoChangePass(request gm.IRequest, newPass string) (err error)
	ChangePass(request gm.IRequest, newPass string) (err error)
}

type DefaultHandler struct {
	IHandler
}

func (h *DefaultHandler) Initialize(handler IHandler) {
	h.IHandler = handler
}

func (h *DefaultHandler) HashPassword(password string) (hash string, err error) {
	passwordBytes := []byte(password)
	hashBytes, err := bcrypt.GenerateFromPassword(passwordBytes, bcrypt.DefaultCost)
	if err != nil {
		return
	}
	hash = string(hashBytes)
	return
}

func (h *DefaultHandler) VerifyPassword(hash string, password string) (err error) {
	hashBytes := []byte(hash)
	passwordBytes := []byte(password)
	err = bcrypt.CompareHashAndPassword(hashBytes, passwordBytes)
	return
}

func (h *DefaultHandler) NormalizeKey(key string) (normalized string) {
	normalized = key
	return
}

func (h *DefaultHandler) ValidateKey(key string) (err error) {
	return
}

func (h *DefaultHandler) ValidatePass(pass string) (err error) {
	return
}

func (h *DefaultHandler) VerifyPass(request gm.IRequest, key string, keyType base.KeyType, pass string) (err error) {
	return
}

func (h *DefaultHandler) VerifyPassById(request gm.IRequest, id interface{}, pass string) (err error) {
	return
}

func (h *DefaultHandler) Login(request gm.IRequest) (key string, keyType base.KeyType, err error) {
	keyType = base.Password
	var body map[string]interface{}
	err = g.BindJSON(request.GetContext(), &body)
	if err != nil {
		return
	}
	keyFace, ok := body["key"]
	if !ok {
		err = errors.GetValidationError(request, request.MustLocalize(&i18n.LocalizeConfig{
			DefaultMessage: &i18n.Message{
				ID:    "KeyRequired",
				Other: "key required",
			},
		}))
		return
	}
	passFace, ok := body["pass"]
	if !ok {
		err = errors.GetValidationError(request)
		return
	}
	key = fmt.Sprintf("%v", keyFace)
	key = h.IHandler.NormalizeKey(key)
	err = h.IHandler.ValidateKey(key)
	if err != nil {
		return
	}
	pass := fmt.Sprintf("%v", passFace)
	err = h.IHandler.ValidatePass(pass)
	if err != nil {
		return
	}
	err, retries := getRetries(keyType, key)
	if err != nil {
		return
	}
	err = retries.Validate(request)
	if err != nil {
		return
	}
	err = h.IHandler.VerifyPass(request, key, keyType, pass)
	defer func() {
		e := retries.TryMore(request)
		if e != nil {
			err = e
			return
		}
	}()
	if err != nil {
		err = errors.GetValidationError(request)
		return
	}
	return
}

func (h *DefaultHandler) ValidateChangePass(request gm.IRequest, oldPass string, newPass string) (err error) {
	err = h.IHandler.ValidatePass(newPass)
	if err != nil {
		return
	}
	auth := request.GetAuth()
	accID := auth.GetCurrentAccountId()
	err = h.IHandler.VerifyPassById(request, accID, oldPass)
	if err != nil {
		return
	}
	return
}

func (h *DefaultHandler) DoChangePass(request gm.IRequest, newPass string) (err error) {
	err = h.IHandler.ChangePass(request, newPass)
	refresh.DeleteAllAccountTokens(request, request.GetAuth().GetCurrentAccountId())
	return
}

func (h *DefaultHandler) ChangePass(request gm.IRequest, newPass string) (err error) {
	// change password logic
	return
}
