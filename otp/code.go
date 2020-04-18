package otp

import (
	"encoding/json"
	"fmt"
	gm "github.com/go-ginger/models"
	"github.com/go-ginger/models/errors"
	"github.com/go-m/auth/base"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"log"
	"math"
	"math/rand"
	"strconv"
	"time"
)

type IOtp interface {
	GenerateCode(otp *OTP)
	Save() (err error)
	Verify(request gm.IRequest, code string) (err error)
}

type OTP struct {
	Code                         string
	Key                          string
	KeySource                    interface{}
	RequestRetriesRemainingCount int
	VerifyRetriesRemainingCount  int
	LastCodeRequestTime          string
}

func getKey(mobile string) (key string) {
	return fmt.Sprintf("otp:%s", mobile)
}

func (otp *OTP) Save() (err error) {
	err = base.RedisHandler.Set(otp.Key, otp,
		time.Duration(math.Max(
			float64(CurrentConfig.CodeExpiration),
			float64(CurrentConfig.ValidationExpiration),
		)),
	)
	if err != nil {
		return
	}
	return
}

func (otp *OTP) Verify(request gm.IRequest, code string) (err error) {
	if code == "" {
		err = errors.GetValidationError(request)
		return
	}
	client, err := base.RedisHandler.GetClient()
	if err != nil {
		return
	}
	defer func() {
		defer func() {
			e := client.Close()
			if e != nil {
				err = e
				log.Println(fmt.Sprintf("error while closing redis, err: %v", err))
			}
		}()
		if err != nil {
			// check err == nil -> may have verified the code and removed otp
			// so saving again will cause generate again otp and can verify
			// as many times as wants!
			if otp.VerifyRetriesRemainingCount > 0 {
				otp.VerifyRetriesRemainingCount--
				serializedOtp, e := json.Marshal(otp)
				if e != nil {
					err = e
					return
				}
				e = client.Set(otp.Key, serializedOtp,
					time.Duration(math.Max(float64(CurrentConfig.CodeExpiration),
						float64(CurrentConfig.ValidationExpiration)))).Err()
				if e != nil {
					err = e
				}
			}
		}
	}()
	lastCodeRequestTime, err := time.Parse(time.RFC3339, otp.LastCodeRequestTime)
	if err != nil {
		return
	}
	if otp.VerifyRetriesRemainingCount <= 0 {
		err = errors.GetValidationError(request, request.MustLocalize(&i18n.LocalizeConfig{
			DefaultMessage: &i18n.Message{
				ID:    "MaximumOtpRetriesExceeded",
				Other: "Maximum retries limit exceeded. try again later",
			},
		}))
		return
	}
	maxRequestValidTime := lastCodeRequestTime.Add(CurrentConfig.CodeExpiration)
	if code != otp.Code ||
		time.Now().UTC().After(maxRequestValidTime) {
		err = errors.GetValidationError(request)
		return
	}
	if CurrentConfig.ValidateOtp != nil {
		err = CurrentConfig.ValidateOtp(otp, code)
		if err != nil {
			return
		}
	}
	otp.Code = ""
	err = otp.Save()
	return
}

func (otp *OTP) GenerateCode() {
	if CurrentConfig.GenerateCodeFunc != nil {
		otp.Code = CurrentConfig.GenerateCodeFunc(otp)
	} else {
		min := 1000
		max := 10000
		otp.Code = fmt.Sprintf("%v", rand.Intn(max-min)+min)
		if base.CurrentConfig.Debug {
			otp.Code = "1111"
		}
	}
	return
}

func generateNewOTP(request gm.IRequest, mobile string) (otp *OTP, err error) {
	client, err := base.RedisHandler.GetClient()
	if err != nil {
		return
	}
	defer func() {
		e := client.Close()
		if e != nil {
			err = e
			log.Println(fmt.Sprintf("error while closing redis, err: %v", err))
		}
	}()
	maxRequestRetries := CurrentConfig.MaxRequestRetries
	maxVerifyRetries := CurrentConfig.MaxVerifyRetries
	existingOTP, _ := getOTP(mobile)
	if existingOTP != nil {
		maxRequestRetries = existingOTP.RequestRetriesRemainingCount
		if !CurrentConfig.ResetMaxVerifyRetriesOnNewRequest {
			maxVerifyRetries = existingOTP.VerifyRetriesRemainingCount
		}
		lastCodeRequestTime, e := time.Parse(time.RFC3339, existingOTP.LastCodeRequestTime)
		if e != nil {
			err = e
			return
		}
		now := time.Now().UTC()
		diff := lastCodeRequestTime.Add(CurrentConfig.RequestRetryLimitDuration).Sub(now)
		if diff > 0 {
			minutes := int(diff.Minutes())
			err = errors.GetValidationError(request, request.MustLocalize(&i18n.LocalizeConfig{
				DefaultMessage: &i18n.Message{
					ID:    "RetryOtpRequestAfter",
					One:   "You can retry request after {{.Seconds}} seconds",
					Other: "You can retry request after {{.Minutes}} minutes and {{.Seconds}} seconds",
				},
				TemplateData: map[string]string{
					"Minutes": strconv.Itoa(minutes),
					"Seconds": strconv.Itoa(int(diff.Seconds() + 1)),
				},
				PluralCount: minutes + 1,
			}))
			return
		}
	}
	if maxRequestRetries <= 0 || maxVerifyRetries <= 0 {
		err = errors.GetValidationError(request, request.MustLocalize(&i18n.LocalizeConfig{
			DefaultMessage: &i18n.Message{
				ID:    "MaximumOtpRetriesExceeded",
				Other: "Maximum retries limit exceeded. try again later",
			},
		}))
		return
	}
	otp = &OTP{
		KeySource:                    mobile,
		Key:                          getKey(mobile),
		RequestRetriesRemainingCount: maxRequestRetries - 1,
		VerifyRetriesRemainingCount:  maxVerifyRetries,
		LastCodeRequestTime:          time.Now().UTC().Format(time.RFC3339),
	}
	otp.GenerateCode()
	err = otp.Save()
	return
}

func getOTP(mobile string) (otp *OTP, err error) {
	client, err := base.RedisHandler.GetClient()
	if err != nil {
		return
	}
	defer func() {
		e := client.Close()
		if e != nil {
			err = e
			log.Println(fmt.Sprintf("error while closing redis, err: %v", err))
		}
	}()
	val := client.Get(getKey(mobile)).Val()
	if val != "" {
		otp = new(OTP)
		err = json.Unmarshal([]byte(val), &otp)
		if err != nil {
			otp = nil
			return
		}
	}
	return
}
