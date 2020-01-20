package otp

import (
	g "github.com/go-ginger/ginger"
	"time"
)

var CurrentConfig *Config

func Initialize(router *g.RouterGroup, config *Config) {
	if config.CodeExpiration == 0 {
		config.CodeExpiration = time.Minute
	}
	if config.ValidationExpiration == 0 {
		config.ValidationExpiration = time.Minute * 30
	}
	if config.RequestRetryLimitDuration == 0 {
		config.RequestRetryLimitDuration = time.Minute
	}
	CurrentConfig = config

	request.Init(request, &LogicHandler, nil)
	verify.Init(verify, &LogicHandler, nil)

	RegisterRoutes(router)
}
