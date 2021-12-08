package password

import (
	"fmt"
	"github.com/go-ginger/ginger"
	g "github.com/go-ginger/ginger"
	gm "github.com/go-ginger/models"
	"github.com/go-ginger/models/errors"
	"github.com/mohammadMghi/go-auth-iGhe3/base"
	"github.com/nicksnyder/go-i18n/v2/i18n"
)

type loginController struct {
	ginger.BaseItemsController
}

func (c *loginController) Post(request gm.IRequest) (result interface{}) {
	key, keyType, err := CurrentConfig.Handler.Login(request)
	if c.HandleErrorNoResult(request, err) {
		return
	}
	err = base.HandleLoginResponse(request, key, keyType)
	if c.HandleErrorNoResult(request, err) {
		return
	}
	return
}

type changeController struct {
	ginger.BaseItemsController
}

func (c *changeController) Post(request gm.IRequest) (result interface{}) {
	var body map[string]interface{}
	err := g.BindJSON(request.GetContext(), &body)
	if c.HandleErrorNoResult(request, err) {
		return
	}
	currentPassFace, ok := body["current"]
	if !ok {
		err := errors.GetValidationError(request, request.MustLocalize(&i18n.LocalizeConfig{
			DefaultMessage: &i18n.Message{
				ID:    "OldPasswordRequired",
				Other: "old password is required",
			},
		}))
		c.HandleErrorNoResult(request, err)
		return
	}
	newPassFace, ok := body["new"]
	if !ok {
		err := errors.GetValidationError(request, request.MustLocalize(&i18n.LocalizeConfig{
			DefaultMessage: &i18n.Message{
				ID:    "NewPasswordRequired",
				Other: "new password is required",
			},
		}))
		c.HandleErrorNoResult(request, err)
		return
	}
	currentPass := fmt.Sprintf("%v", currentPassFace)
	newPass := fmt.Sprintf("%v", newPassFace)
	err = CurrentConfig.Handler.ValidateChangePass(request, currentPass, newPass)
	if c.HandleErrorNoResult(request, err) {
		return
	}
	if currentPass != newPass {
		err = CurrentConfig.Handler.DoChangePass(request, newPass)
		if c.HandleErrorNoResult(request, err) {
			return
		}
	}
	auth := request.GetAuth()
	err = base.HandleLoginResponse(request,
		fmt.Sprintf("%v", auth.GetCurrentAccountId(request)),
		base.ID)
	if c.HandleErrorNoResult(request, err) {
		return
	}
	ctx := request.GetContext()
	ctx.Status(204)
	return
}
