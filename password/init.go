package password

import (
	g "github.com/go-ginger/ginger"
)

var CurrentConfig *Config

func Initialize(router *g.RouterGroup, config *Config) {
	CurrentConfig = config
	CurrentConfig.Initialize()
	CurrentConfig.Handler.Initialize(CurrentConfig.Handler)

	login.Init(login, nil, nil)
	change.Init(change, nil, nil)

	RegisterRoutes(router)
}
