package password

import (
	g "github.com/go-ginger/ginger"
)

var login = new(loginController)
var change = new(changeController)

func RegisterRoutes(router *g.RouterGroup) {
	login.AddRoute("Post")
	change.AddRoute("Post", CurrentConfig.LoginHandler.MustAuthenticate())

	login.RegisterRoutes(login, "/password", router)
	change.RegisterRoutes(change, "/change_password", router)
}
