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
	HashPassword(request gm.IRequest, password string) (hash string, err error)
	VerifyPassword(request gm.IRequest, hash string, password string) (err error)
	ValidateKey(request gm.IRequest, key string) (err error)
	NormalizeKey(request gm.IRequest, key string) (normalized string)
	ValidatePass(request gm.IRequest, pass string) (err error)
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

func (h *DefaultHandler) HashPassword(request gm.IRequest, password string) (hash string, err error) {
	passwordBytes := []byte(password)
	hashBytes, err := bcrypt.GenerateFromPassword(passwordBytes, bcrypt.DefaultCost)
	if err != nil {
		return
	}
	hash = string(hashBytes)
	return
}

func (h *DefaultHandler) VerifyPassword(request gm.IRequest, hash string, password string) (err error) {
	hashBytes := []byte(hash)
	passwordBytes := []byte(password)
	err = bcrypt.CompareHashAndPassword(hashBytes, passwordBytes)
	return
}

func (h *DefaultHandler) NormalizeKey(request gm.IRequest, key string) (normalized string) {
	normalized = key
	return
}

func (h *DefaultHandler) ValidateKey(request gm.IRequest, key string) (err error) {
	return
}

func (h *DefaultHandler) ValidatePass(request gm.IRequest, pass string) (err error) {
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
	key = h.IHandler.NormalizeKey(request, key)
	err = h.IHandler.ValidateKey(request, key)
	if err != nil {
		return
	}
	pass := fmt.Sprintf("%v", passFace)
	err = h.IHandler.ValidatePass(request, pass)
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
	err = h.IHandler.ValidatePass(request, newPass)
	if err != nil {
		return
	}
	auth := request.GetAuth()
	accID := auth.GetCurrentAccountId(request)
	err = h.IHandler.VerifyPassById(request, accID, oldPass)
	if err != nil {
		return
	}
	return
}

func (h *DefaultHandler) DoChangePass(request gm.IRequest, newPass string) (err error) {
	err = h.IHandler.ChangePass(request, newPass)
	refresh.DeleteAllAccountTokens(request, request.GetAuth().GetCurrentAccountId(request))
	return
}

func (h *DefaultHandler) ChangePass(request gm.IRequest, newPass string) (err error) {
	// change password logic
	return
}
