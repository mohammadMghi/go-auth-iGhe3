package otp

import (
	"fmt"
	"github.com/go-m/auth/base"
)

type RequestModel interface {
	SetKeyType(keyType base.KeyType)
	SetKey(key string)
	SetCode(code string)
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

func (r *request) SetKeyType(keyType base.KeyType) {
	r.keyType = keyType
}

func (r *request) SetKey(key string) {
	r.key = key
}

func (r *request) SetCode(code string) {
	r.code = code
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
