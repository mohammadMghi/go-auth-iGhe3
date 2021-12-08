package refresh

import (
	"fmt"
	"github.com/go-ginger/ginger"
	g "github.com/go-ginger/ginger"
	gm "github.com/go-ginger/models"
	"github.com/go-ginger/models/errors"
	"github.com/mohammadMghi/go-auth-iGhe3/base"
	"github.com/nicksnyder/go-i18n/v2/i18n"
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
		err = errors.GetValidationError(request, request.MustLocalize(&i18n.LocalizeConfig{
			DefaultMessage: &i18n.Message{
				ID:    "RefreshTokenRequired",
				Other: "token required to refresh authentication",
			},
		}))
		return
	}
	token := fmt.Sprintf("%v", tokenFace)
	refresh, err := GetAndDeleteToken(request, token)
	if err != nil || refresh == nil {
		err = errors.GetUnAuthorizedError(request)
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
