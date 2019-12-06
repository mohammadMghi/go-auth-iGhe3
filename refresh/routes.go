package refresh

import (
	g "github.com/go-ginger/ginger"
)

var refresh = new(refreshController)

func RegisterRoutes(router *g.RouterGroup) {
	refresh.AddRoute("Post")

	refresh.RegisterRoutes(refresh, "/refresh", router)
}
