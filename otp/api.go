package otp

import (
	"github.com/go-ginger/ginger"
	gm "github.com/go-ginger/models"
	"github.com/go-m/auth/base"
)

type requestOtpController struct {
	ginger.BaseItemsController
}

func (c *requestOtpController) Post(request gm.IRequest) (result interface{}) {
	otp, err := CurrentConfig.LogicHandler.RequestOTP(request)
	if c.HandleErrorNoResult(request, err) {
		return
	}
	err = CurrentConfig.LogicHandler.AfterRequestOTP(request, otp)
	if c.HandleErrorNoResult(request, err) {
		return
	}
	request.GetContext().Status(204)
	return
}

type verifyOtpController struct {
	ginger.BaseItemsController
}

func (c *verifyOtpController) Post(request gm.IRequest) (result interface{}) {
	key, keyType, err := CurrentConfig.LogicHandler.VerifyOTP(request)
	if c.HandleErrorNoResult(request, err) {
		return
	}
	err = base.HandleLoginResponse(request, key, keyType)
	if c.HandleErrorNoResult(request, err) {
		return
	}
	return
}
