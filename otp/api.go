package otp

import (
	"github.com/go-ginger/ginger"
	gm "github.com/go-ginger/models"
)

type requestOtpController struct {
	ginger.BaseItemsController
}

func (c *requestOtpController) Post(request gm.IRequest) (result interface{}) {
	err := LogicHandler.RequestOTP(request)
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
	result, err := LogicHandler.VerifyOTP(request)
	if c.HandleError(request, result, err) {
		return
	}
	request.GetContext().JSON(200, result)
	return
}
