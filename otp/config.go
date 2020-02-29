package otp

import (
	"github.com/go-m/auth/base"
	"regexp"
	"time"
)

type Config struct {
	LoginHandler base.ILoginHandler
	LogicHandler IOtpLogicHandler

	CodeExpiration                    time.Duration
	MaxRequestRetries                 int
	MaxVerifyRetries                  int
	ValidationExpiration              time.Duration
	RequestRetryLimitDuration         time.Duration
	ResetMaxVerifyRetriesOnNewRequest bool
	MobileValidationRegexPattern      *string
	ValidateMobile                    func(mobile string) error
	ValidateOtp                       func(otp *OTP, code string) error

	GenerateCodeFunc func(otp *OTP) (code string)

	MobileValidationRegex *regexp.Regexp
}
