package otp

import (
	"fmt"
	g "github.com/go-ginger/ginger"
	gl "github.com/go-ginger/logic"
	gm "github.com/go-ginger/models"
	"github.com/go-ginger/models/errors"
	"github.com/go-m/auth/base"
	"log"
)

type otpLogic struct {
	gl.IBaseLogicHandler
}

var LogicHandler otpLogic

func init() {
	LogicHandler = otpLogic{IBaseLogicHandler: &gl.BaseLogicHandler{}}
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
	otp, err := generateNewOTP(mobile)
	if err != nil {
		log.Println(fmt.Sprintf("error on generateNewOTP, err: %v", err))
	}
	if otp != nil {
		log.Println(fmt.Sprintf("OTP for mobile: `%s` is `%s`", mobile, otp.Code))
	}
	return
}

func (l *otpLogic) VerifyOTP(request gm.IRequest) (result interface{}, err error) {
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
	code := fmt.Sprintf("%v", codeFace)
	otp, err := getOTP(mobile)
	if err != nil {
		return
	}
	err = verifyOTP(otp, code)
	if err != nil {
		return
	}
	result, err = CurrentConfig.LoginHandler.Login(base.CurrentConfig, mobile, base.Mobile)
	return
}
