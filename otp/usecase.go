package otp

import (
	"github.com/go-ginger/logic"
	gm "github.com/go-ginger/models"
	"github.com/go-ginger/models/errors"
	"github.com/mohammadMghi/go-auth-iGhe3/base"
)

type UseCaseModel interface {
	logic.IBaseLogicHandler
	Request(request gm.IRequest, otpRequest RequestModel) (otp OTP, err error)
	Verify(request gm.IRequest, otpRequest RequestModel) (err error)
	RegisterNewHandler(keyType base.KeyType, handler HandlerModel)
	RegisterHooks(keyType base.KeyType, hooks Hooks)
}

type useCase struct {
	logic.BaseLogicHandler
	otpHandler  HandlerModel
	otpHandlers map[base.KeyType]HandlerModel
	hooks       map[base.KeyType]Hooks
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

func (uc *useCase) RegisterHooks(keyType base.KeyType, hooks Hooks) {
	if uc.hooks == nil {
		uc.hooks = make(map[base.KeyType]Hooks)
	}
	uc.hooks[keyType] = hooks
}

func (uc useCase) Request(request gm.IRequest, otpRequest RequestModel) (otp OTP, err error) {
	otpHandler := uc.otpHandler
	if h, ok := uc.otpHandlers[otpRequest.GetKeyType()]; ok {
		otpHandler = h
	}
	if err = otpHandler.Normalize(request, otpRequest); err != nil {
		return nil, err
	}
	if err = otpHandler.Validate(request, otpRequest); err != nil {
		return nil, err
	}
	otp, err = otpHandler.New(request, otpRequest)
	if err != nil {
		return
	}
	otpHandler.RefreshCode(otp)
	if err = otpHandler.Save(request, otp); err != nil {
		return nil, err
	}
	if h, ok := uc.hooks[otpRequest.GetKeyType()]; ok {
		if err = h.SuccessRequest(request, otpRequest, otp); err != nil {
			return nil, err
		}
	}
	return
}

func (uc useCase) Verify(request gm.IRequest, otpRequest RequestModel) (err error) {
	otpHandler := uc.otpHandler
	if h, ok := uc.otpHandlers[otpRequest.GetKeyType()]; ok {
		otpHandler = h
	}
	if err = otpHandler.Normalize(request, otpRequest); err != nil {
		return err
	}
	if err = otpHandler.Validate(request, otpRequest); err != nil {
		return err
	}
	code := otpRequest.GetCode()
	if code == "" {
		err = errors.GetValidationError(request)
		return
	}
	if err = otpHandler.Verify(request, otpRequest); err != nil {
		return err
	}
	if h, ok := uc.hooks[otpRequest.GetKeyType()]; ok {
		if err = h.SuccessVerify(request, otpRequest); err != nil {
			return err
		}
	}
	return
}
