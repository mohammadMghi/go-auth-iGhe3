package otp

import (
	"fmt"
	g "github.com/go-ginger/ginger"
	gl "github.com/go-ginger/logic"
	gm "github.com/go-ginger/models"
	"github.com/go-ginger/models/errors"
	"github.com/go-m/auth/base"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"log"
	"strings"
)

type IOtpLogicHandler interface {
	Init(logicHandler IOtpLogicHandler)
	GetGingerLogicHandler() (handler gl.IBaseLogicHandler)
	GenerateNewOTP(request gm.IRequest, mobile string) (otp *OTP, err error)
	RequestOTP(request gm.IRequest) (otp *OTP, err error)
	AfterRequestOTP(request gm.IRequest, otp *OTP) (err error)
	VerifyOTP(request gm.IRequest) (key string, keyType base.KeyType, err error)
}

type BaseLogicHandler struct {
	IOtpLogicHandler
	gl.IBaseLogicHandler
}

func (l *BaseLogicHandler) Init(logicHandler IOtpLogicHandler) {
	l.IOtpLogicHandler = logicHandler
}

func (l *BaseLogicHandler) GetGingerLogicHandler() (handler gl.IBaseLogicHandler) {
	return l.IBaseLogicHandler
}

func (l *BaseLogicHandler) normalizeMobile(mobile string) (normalized string) {
	normalized = mobile
	for strings.Contains(normalized, ")0") {
		normalized = strings.Replace(normalized, ")0", ")", -1)
	}
	return
}

func (l *BaseLogicHandler) validateMobile(request gm.IRequest, mobile string) (err error) {
	if CurrentConfig.MobileValidationRegex != nil {
		if !CurrentConfig.MobileValidationRegex.MatchString(mobile) {
			err = errors.GetValidationError(request, request.MustLocalize(&i18n.LocalizeConfig{
				DefaultMessage: &i18n.Message{
					ID:    "InvalidMobileNumber",
					Other: "Invalid mobile number",
				},
			}))
			return
		}
	}
	if CurrentConfig.ValidateMobile != nil {
		err = CurrentConfig.ValidateMobile(mobile)
		if err != nil {
			return
		}
	}
	return
}

func (l *BaseLogicHandler) GenerateNewOTP(request gm.IRequest, mobile string) (otp *OTP, err error) {
	otp, err = generateNewOTP(request, mobile)
	if err != nil {
		log.Println(fmt.Sprintf("error on generateNewOTP, err: %v", err))
	}
	return
}

func (l *BaseLogicHandler) RequestOTP(request gm.IRequest) (otp *OTP, err error) {
	var body map[string]interface{}
	err = g.BindJSON(request.GetContext(), &body)
	if err != nil {
		return
	}
	mobileFace, ok := body["mobile"]
	if !ok {
		err = errors.GetValidationError(request, request.MustLocalize(&i18n.LocalizeConfig{
			DefaultMessage: &i18n.Message{
				ID:    "MobileNumberRequired",
				Other: "mobile phone required",
			},
		}))
		return
	}
	mobile := fmt.Sprintf("%v", mobileFace)
	mobile = l.normalizeMobile(mobile)
	err = l.validateMobile(request, mobile)
	if err != nil {
		return
	}
	otp, err = l.IOtpLogicHandler.GenerateNewOTP(request, mobile)
	if err != nil {
		return
	}
	if otp != nil {
		log.Println(fmt.Sprintf("OTP for mobile: `%s` is `%s`", mobile, otp.Code))
	}
	return
}

func (l *BaseLogicHandler) AfterRequestOTP(request gm.IRequest, otp *OTP) (err error) {
	return
}

func (l *BaseLogicHandler) VerifyOTP(request gm.IRequest) (key string, keyType base.KeyType, err error) {
	var body map[string]interface{}
	err = g.BindJSON(request.GetContext(), &body)
	if err != nil {
		return
	}
	mobileFace, ok := body["mobile"]
	if !ok {
		err = errors.GetValidationError(request, request.MustLocalize(&i18n.LocalizeConfig{
			DefaultMessage: &i18n.Message{
				ID:    "MobileNumberRequired",
				Other: "mobile phone required",
			},
		}))
		return
	}
	codeFace, ok := body["code"]
	if !ok {
		err = errors.GetValidationError(request)
		return
	}
	mobile := fmt.Sprintf("%v", mobileFace)
	mobile = l.normalizeMobile(mobile)
	err = l.validateMobile(request, mobile)
	if err != nil {
		return
	}
	code := fmt.Sprintf("%v", codeFace)
	otp, err := getOTP(mobile)
	if err != nil {
		return
	}
	if otp == nil {
		err = errors.GetValidationError(request)
		return
	}
	err = otp.Verify(request, code)
	if err != nil {
		return
	}
	key = mobile
	keyType = base.Mobile
	return
}
