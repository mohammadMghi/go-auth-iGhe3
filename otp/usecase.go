package otp

import (
	"github.com/go-ginger/logic"
	gm "github.com/go-ginger/models"
	"github.com/go-ginger/models/errors"
	"github.com/go-m/auth/base"
)

type UseCaseModel interface {
	logic.IBaseLogicHandler
	Request(request gm.IRequest, otpRequest RequestModel) (otp OTP, err error)
	Verify(request gm.IRequest, otpRequest RequestModel) (err error)
	RegisterNewHandler(keyType base.KeyType, handler HandlerModel)
}

type useCase struct {
	logic.BaseLogicHandler
	otpHandler  HandlerModel
	otpHandlers map[base.KeyType]HandlerModel
}

func NewUseCase(otpHandler HandlerModel) UseCaseModel {
	uc := new(useCase)
	uc.otpHandler = otpHandler
	uc.Init(uc, nil)
	return uc
}

func (uc *useCase) RegisterNewHandler(keyType base.KeyType, handler HandlerModel) {
	if uc.otpHandlers == nil {
		uc.otpHandlers = make(map[base.KeyType]HandlerModel)
	}
	uc.otpHandlers[keyType] = handler
}

func (uc useCase) Request(request gm.IRequest, otpRequest RequestModel) (otp OTP, err error) {
	otpHandler := uc.otpHandler
	if h, ok := uc.otpHandlers[otpRequest.GetKeyType()]; ok {
		otpHandler = h
	}
	otp, err = otpHandler.New(request, otpRequest)
	if err != nil {
		return
	}
	otpHandler.RefreshCode(otp)
	if err = otpHandler.Save(request, otp); err != nil {
		return nil, err
	}
	return
}

func (uc useCase) Verify(request gm.IRequest, otpRequest RequestModel) (err error) {
	otpHandler := uc.otpHandler
	if h, ok := uc.otpHandlers[otpRequest.GetKeyType()]; ok {
		otpHandler = h
	}
	code := otpRequest.GetCode()
	if code == "" {
		err = errors.GetValidationError(request)
		return
	}
	return otpHandler.Verify(request, otpRequest)
}
