package auth

import (
	g "github.com/go-ginger/ginger"
	"github.com/go-m/auth/base"
	"github.com/go-m/auth/password"
)

type Config struct {
	base.Config

	AuthRouters []*g.RouterGroup
	Router      *g.RouterGroup
	Password    *password.Config
}
