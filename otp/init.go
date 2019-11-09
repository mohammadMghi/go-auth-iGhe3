package otp

import (
	g "github.com/go-ginger/ginger"
)

var CurrentConfig *Config

func Initialize(router *g.RouterGroup, config *Config) {
	CurrentConfig = config

	request.Init(request, &LogicHandler, nil)
	verify.Init(verify, &LogicHandler, nil)

	RegisterRoutes(router)
}
