package refresh

import (
	"fmt"
	"github.com/go-ginger/ginger"
	g "github.com/go-ginger/ginger"
	gm "github.com/go-ginger/models"
	"github.com/go-ginger/models/errors"
	"github.com/go-m/auth/base"
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
	refresh, err := GetAndDeleteToken(token)
	if err != nil || refresh == nil {
		err = errors.GetUnAuthorizedError()
	}
	if c.HandleError(request, refresh, err) {
		return
	}
	err = base.HandleLoginResponse(request, refresh.Key, refresh.KeyType)
	if c.HandleErrorNoResult(request, err) {
		return
	}
	return
}
