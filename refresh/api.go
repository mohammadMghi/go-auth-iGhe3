package refresh

import (
	"fmt"
	"github.com/go-ginger/ginger"
	g "github.com/go-ginger/ginger"
	gm "github.com/go-ginger/models"
	"github.com/go-ginger/models/errors"
	"github.com/go-m/auth/base"
	"net/http"
)

type refreshController struct {
	ginger.BaseItemsController
}

func (c *refreshController) Post(request gm.IRequest) (result interface{}) {
	var body map[string]interface{}
	err := g.BindJSON(request.GetContext(), &body)
	if c.HandleError(request, body, err) {
		return
	}
	tokenFace, ok := body["token"]
	if !ok {
		err = errors.GetValidationError("token required to refresh authentication")
		return
	}
	token := fmt.Sprintf("%v", tokenFace)
	refresh, err := getToken(token)
	if err == nil && (refresh == nil || !deleteToken(refresh.Value)) {
		err = errors.GetUnAuthorizedError()
	}
	if c.HandleError(request, refresh, err) {
		return
	}
	result, cookies, err := base.CurrentConfig.LoginHandler.Login(
		base.CurrentConfig, refresh.Key, refresh.KeyType)
	if c.HandleError(request, result, err) {
		return
	}
	ctx := request.GetContext()
	if cookies != nil {
		for _, cookie := range cookies {
			http.SetCookie(ctx.Writer, cookie)
		}
	}
	ctx.JSON(200, result)
	return
}
