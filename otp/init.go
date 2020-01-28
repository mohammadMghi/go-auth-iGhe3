package otp

import (
	g "github.com/go-ginger/ginger"
	gl "github.com/go-ginger/logic"
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
	if config.LogicHandler == nil {
		logicHandler := BaseLogicHandler{
			IBaseLogicHandler: &gl.BaseLogicHandler{},
		}
		config.LogicHandler = &logicHandler
	}
	config.LogicHandler.Init(config.LogicHandler)
	CurrentConfig = config
	gingerLogicHandler := config.LogicHandler.GetGingerLogicHandler()
	gingerLogicHandler.Init(gingerLogicHandler, nil)
	request.Init(request, gingerLogicHandler, nil)
	verify.Init(verify, gingerLogicHandler, nil)

	RegisterRoutes(router)
}
