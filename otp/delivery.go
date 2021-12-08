package otp

import (
	"github.com/go-ginger/ginger"
	gm "github.com/go-ginger/models"
	"github.com/mohammadMghi/go-auth-iGhe3/base"
)

/*
Request
*/
type RequestHooks interface {
	AfterRequestOTP(request gm.IRequest, otp OTP) (err error)
}
type RequestModelMaker interface {
	New() RequestModel
}
type requestHandler struct {
	ginger.BaseItemsController
	uc                UseCaseModel
	requestModelMaker RequestModelMaker
	hooks             RequestHooks
}

func NewRequestHandler(uc UseCaseModel, requestModelMaker RequestModelMaker, hooks RequestHooks) ginger.IController {
	h := new(requestHandler)
	h.uc = uc
	h.requestModelMaker = requestModelMaker
	h.hooks = hooks
	h.Init(h, uc, nil)
	return h
}

func (c requestHandler) Post(request gm.IRequest) (result interface{}) {
	model := c.requestModelMaker.New()
	if err := ginger.BindJSON(request.GetContext(), model); c.HandleErrorNoResult(request, err) {
		return
	}
	otp, err := c.uc.Request(request, model)
	if c.HandleErrorNoResult(request, err) {
		return
	}
	if c.hooks.AfterRequestOTP != nil {
		if err = c.hooks.AfterRequestOTP(request, otp); c.HandleErrorNoResult(request, err) {
			return
		}
	}
	request.GetContext().Status(204)
	return
}

/*
Verify
*/
type VerifyRequestModelMaker interface {
	New() RequestModel
}
type verifyHandler struct {
	ginger.BaseItemsController
	uc                 UseCaseModel
	verifyRequestMaker VerifyRequestModelMaker
}

func NewVerifyHandler(uc UseCaseModel, verifyRequestMaker VerifyRequestModelMaker) ginger.IController {
	h := new(verifyHandler)
	h.uc = uc
	h.verifyRequestMaker = verifyRequestMaker
	h.Init(h, uc, nil)
	return h
}

func (c verifyHandler) Post(request gm.IRequest) (result interface{}) {
	model := c.verifyRequestMaker.New()
	if err := ginger.BindJSON(request.GetContext(), model); c.HandleErrorNoResult(request, err) {
		return
	}
	if err := c.uc.Verify(request, model); c.HandleErrorNoResult(request, err) {
		return
	}
	if err := base.HandleLoginResponse(request, model.GetKey(),
		model.GetKeyType()); c.HandleErrorNoResult(request, err) {
		return
	}
	return
}
