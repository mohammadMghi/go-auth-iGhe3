package auth

import (
	g "github.com/go-ginger/ginger"
	"github.com/mohammadMghi/go-auth-iGhe3/base"
	"github.com/mohammadMghi/go-auth-iGhe3/password"
)

type Config struct {
	base.Config

	AuthRouters []*g.RouterGroup
	Router      *g.RouterGroup
	Password    *password.Config
}
