package base

import (
	"net/http"
)

type ILoginHandler interface {
	Initialize(handler ILoginHandler)
	GetProperties(key string, keyType KeyType) (properties map[string]interface{}, err error)
	Login(config *Config, key string, keyType KeyType) (result interface{}, cookies []*http.Cookie, err error)
}
