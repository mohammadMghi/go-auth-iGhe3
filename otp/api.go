package otp

import (
	"github.com/go-ginger/ginger"
	gm "github.com/go-ginger/models"
	"net/http"
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
	result, cookies, err := LogicHandler.VerifyOTP(request)
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
