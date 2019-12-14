package base

import (
	g "github.com/go-ginger/ginger"
	gm "github.com/go-ginger/models"
	"github.com/go-ginger/models/errors"
	"net/http"
)

type ILoginInfo interface {
	GetProperties() map[string]interface{}
	GetExtraData() map[string]interface{}
	GetAccountID() interface{}
}
type LoginInfo struct {
	ILoginInfo
	Properties map[string]interface{}
	ExtraData  map[string]interface{}
	AccountID  interface{}
}

func (l *LoginInfo) GetProperties() map[string]interface{} {
	return l.Properties
}
func (l *LoginInfo) GetExtraData() map[string]interface{} {
	return l.ExtraData
}
func (l *LoginInfo) GetAccountID() interface{} {
	return l.AccountID
}

type ILoginHandler interface {
	Initialize(handler ILoginHandler)
	NewAuthorization(authInfo interface{}) gm.IAuthorization
	GetInfo(request gm.IRequest, key string, keyType KeyType) (info ILoginInfo, err error)
	Login(request gm.IRequest, config *Config, key string, keyType KeyType) (result interface{},
		headers map[string]string, cookies []*http.Cookie, err error)
	Authenticate(request gm.IRequest) (err error)
	MustAuthenticate() g.HandlerFunc
	MustHaveRole(roles ...string) g.HandlerFunc
}

func HandleLoginResponse(request gm.IRequest, key string, keyType KeyType, preventResponseBody ...bool) (err error) {
	result, headers, cookies, err := CurrentConfig.LoginHandler.Login(request, CurrentConfig, key, keyType)
	if err != nil {
		return
	}
	if result == nil {
		err = errors.GetUnAuthorizedError()
		return
	}
	err = CurrentConfig.LoginHandler.Authenticate(request)
	if err != nil {
		return
	}
	ctx := request.GetContext()
	if cookies != nil {
		for _, cookie := range cookies {
			http.SetCookie(ctx.Writer, cookie)
		}
	}
	if headers != nil {
		for k, v := range headers {
			ctx.Header(k, v)
		}
	}
	if preventResponseBody != nil && preventResponseBody[0] {
		return
	}
	ctx.JSON(200, result)
	return
}
