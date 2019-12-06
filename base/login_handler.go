package base

import (
	gm "github.com/go-ginger/models"
	"github.com/go-ginger/models/errors"
	"net/http"
)

type ILoginHandler interface {
	Initialize(handler ILoginHandler)
	GetProperties(key string, keyType KeyType) (properties map[string]interface{}, err error)
	Login(config *Config, key string, keyType KeyType) (result interface{}, headers map[string]string,
		cookies []*http.Cookie, err error)
}

func HandleLoginResponse(request gm.IRequest, key string, keyType KeyType) (err error) {
	result, headers, cookies, err := CurrentConfig.LoginHandler.Login(CurrentConfig, key, keyType)
	if err != nil {
		return
	}
	if result == nil {
		err = errors.GetUnAuthorizedError()
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
	ctx.JSON(200, result)
	return
}
