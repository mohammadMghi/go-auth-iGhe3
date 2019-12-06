package refresh

import (
	g "github.com/go-ginger/ginger"
)

func Initialize(router *g.RouterGroup) {
	refresh.Init(refresh, nil, nil)

	RegisterRoutes(router)
}
