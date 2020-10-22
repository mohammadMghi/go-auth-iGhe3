package otp

import (
	"github.com/go-ginger/logic"
	gm "github.com/go-ginger/models"
	"github.com/go-ginger/models/errors"
)

type UseCaseModel interface {
	logic.IBaseLogicHandler
	Request(request gm.IRequest, otpRequest RequestModel) (otp OTP, err error)
	Verify(request gm.IRequest, otpRequest RequestModel) (err error)
}

type useCase struct {
	logic.BaseLogicHandler
	otpHandler HandlerModel
}

func NewUseCase(otpHandler HandlerModel) UseCaseModel {
	uc := new(useCase)
	uc.otpHandler = otpHandler
	uc.Init(uc, nil)
	return uc
}

func (uc useCase) Request(request gm.IRequest, otpRequest RequestModel) (otp OTP, err error) {
	otp, err = uc.otpHandler.New(request, otpRequest)
	if err != nil {
		return
	}
	uc.otpHandler.RefreshCode(otp)
	if err = uc.otpHandler.Save(request, otp); err != nil {
		return nil, err
	}
	return
}

func (uc useCase) Verify(request gm.IRequest, otpRequest RequestModel) (err error) {
	code := otpRequest.GetCode()
	if code == "" {
		err = errors.GetValidationError(request)
		return
	}
	return uc.otpHandler.Verify(request, otpRequest)
}
