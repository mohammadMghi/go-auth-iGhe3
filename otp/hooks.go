package otp

import gm "github.com/go-ginger/models"

type Hooks interface {
	SuccessRequest(request gm.IRequest, otpRequest RequestModel, otp OTP) (err error)
	SuccessVerify(request gm.IRequest, otpRequest RequestModel) (err error)
}
