package otp

import (
	"fmt"
	g "github.com/go-ginger/ginger"
	gl "github.com/go-ginger/logic"
	gm "github.com/go-ginger/models"
	"github.com/go-ginger/models/errors"
	"github.com/go-m/auth/base"
	"log"
	"net/http"
	"strings"
)

type otpLogic struct {
	gl.IBaseLogicHandler
}

var LogicHandler otpLogic

func init() {
	LogicHandler = otpLogic{IBaseLogicHandler: &gl.BaseLogicHandler{}}
}

func (l *otpLogic) normalizeMobile(mobile string) (normalized string) {
	normalized = mobile
	for strings.Contains(normalized, ")0") {
		normalized = strings.Replace(normalized, ")0", ")", -1)
	}
	return
}

func (l *otpLogic) validateMobile(mobile string) (err error) {
	if CurrentConfig.MobileValidationRegex != nil {
		if !CurrentConfig.MobileValidationRegex.MatchString(mobile) {
			err = errors.GetValidationError("Invalid mobile number")
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

func (l *otpLogic) RequestOTP(request gm.IRequest) (err error) {
	var body map[string]interface{}
	err = g.BindJSON(request.GetContext(), &body)
	if err != nil {
		return
	}
	mobileFace, ok := body["mobile"]
	if !ok {
		err = errors.GetValidationError("mobile phone required")
		return
	}
	mobile := fmt.Sprintf("%v", mobileFace)
	mobile = l.normalizeMobile(mobile)
	err = l.validateMobile(mobile)
	if err != nil {
		return
	}
	otp, err := generateNewOTP(mobile)
	if err != nil {
		log.Println(fmt.Sprintf("error on generateNewOTP, err: %v", err))
	}
	if otp != nil {
		log.Println(fmt.Sprintf("OTP for mobile: `%s` is `%s`", mobile, otp.Code))
	}
	return
}

func (l *otpLogic) VerifyOTP(request gm.IRequest) (result interface{}, cookies []*http.Cookie, err error) {
	var body map[string]interface{}
	err = g.BindJSON(request.GetContext(), &body)
	if err != nil {
		return
	}
	mobileFace, ok := body["mobile"]
	if !ok {
		err = errors.GetValidationError("mobile phone required")
		return
	}
	codeFace, ok := body["code"]
	if !ok {
		err = errors.GetUnAuthorizedError()
		return
	}
	mobile := fmt.Sprintf("%v", mobileFace)
	mobile = l.normalizeMobile(mobile)
	err = l.validateMobile(mobile)
	if err != nil {
		return
	}
	code := fmt.Sprintf("%v", codeFace)
	otp, err := getOTP(mobile)
	if err != nil {
		return
	}
	if otp == nil {
		err = errors.GetUnAuthorizedError()
		return
	}
	err = otp.Verify(code)
	if err != nil {
		return
	}
	result, cookies, err = CurrentConfig.LoginHandler.Login(base.CurrentConfig, mobile, base.Mobile)
	return
}
