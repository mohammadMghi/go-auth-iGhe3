package password

import (
	"fmt"
	"github.com/go-ginger/ginger"
	g "github.com/go-ginger/ginger"
	gm "github.com/go-ginger/models"
	"github.com/go-ginger/models/errors"
	"github.com/go-m/auth/base"
)

type loginController struct {
	ginger.BaseItemsController
}

func (c *loginController) Post(request gm.IRequest) (result interface{}) {
	key, keyType, err := CurrentConfig.Handler.Login(request)
	if c.HandleErrorNoResult(request, err) {
		return
	}
	tempKey := fmt.Sprintf("%v", keyType)
	accountInfoFace := request.GetTemp(tempKey)
	if accountInfoFace == nil {
		err = errors.GetUnAuthorizedError()
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
	oldPassFace, ok := body["old"]
	if !ok {
		err := errors.GetValidationError("old password is required")
		c.HandleErrorNoResult(request, err)
		return
	}
	newPassFace, ok := body["new"]
	if !ok {
		err := errors.GetValidationError("new password is required")
		c.HandleErrorNoResult(request, err)
		return
	}
	oldPass := fmt.Sprintf("%v", oldPassFace)
	newPass := fmt.Sprintf("%v", newPassFace)
	err = CurrentConfig.Handler.ValidateChangePass(request, oldPass, newPass)
	if c.HandleErrorNoResult(request, err) {
		return
	}
	if oldPass != newPass {
		err = CurrentConfig.Handler.ChangePass(request, newPass)
		if c.HandleErrorNoResult(request, err) {
			return
		}
	}
	ctx := request.GetContext()
	ctx.Status(204)
	return
}
