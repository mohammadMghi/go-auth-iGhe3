package otp

import (
	"fmt"
	"github.com/go-m/auth/base"
)

type RequestModel interface {
	WithKeyType(keyType base.KeyType) RequestModel
	WithKey(key string) RequestModel
	WithCode(code string) RequestModel
	GetID() string
	GetKeyType() base.KeyType
	GetKey() string
	GetCode() string
}

type request struct {
	keyType base.KeyType
	key     string
	code    string
}

func NewRequest() RequestModel {
	r := new(request)
	return r
}

func (r request) GetID() string {
	return fmt.Sprintf("otp:%s:%s", r.keyType, r.key)
}

func (r *request) WithKeyType(keyType base.KeyType) RequestModel {
	r.keyType = keyType
	return r
}

func (r *request) WithKey(key string) RequestModel {
	r.key = key
	return r
}

func (r *request) WithCode(code string) RequestModel {
	r.code = code
	return r
}

func (r request) GetKeyType() base.KeyType {
	return r.keyType
}

func (r request) GetKey() string {
	return r.key
}

func (r request) GetCode() string {
	return r.code
}
