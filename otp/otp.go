package otp

import (
	"context"
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

type OTP interface {
	SetID(id string)
	SetKey(key string)
	SetCode(code string)
	SetRequestRetriesRemainingCount(requestRetriesRemainingCount int)
	SetVerifyRetriesRemainingCount(verifyRetriesRemainingCount int)
	SetLastCodeRequestTime(lastCodeRequestTime time.Time)
	SetExpirationTime(exp time.Time)

	GetID() string
	GetKey() string
	GetCode() string
	GetRequestRetriesRemainingCount() int
	GetVerifyRetriesRemainingCount() int
	GetLastCodeRequestTime() time.Time
	GetExpirationTime() time.Time
}

type otp struct {
	ID                           string
	Key                          string
	Code                         string
	RequestRetriesRemainingCount int
	VerifyRetriesRemainingCount  int
	LastCodeRequestTime          time.Time
	ExpirationTime               time.Time
}

func NewOTP() OTP {
	otp := new(otp)
	return otp
}

func (o *otp) SetID(id string) {
	o.ID = id
}

func (o *otp) SetKey(key string) {
	o.Key = key
}

func (o *otp) SetRequestRetriesRemainingCount(requestRetriesRemainingCount int) {
	o.RequestRetriesRemainingCount = requestRetriesRemainingCount
}

func (o *otp) SetVerifyRetriesRemainingCount(verifyRetriesRemainingCount int) {
	o.VerifyRetriesRemainingCount = verifyRetriesRemainingCount
}

func (o *otp) SetLastCodeRequestTime(lastCodeRequestTime time.Time) {
	o.LastCodeRequestTime = lastCodeRequestTime
}

func (o *otp) SetExpirationTime(exp time.Time) {
	o.ExpirationTime = exp
}

func (o otp) GetID() string {
	return o.ID
}

func (o otp) GetKey() string {
	return o.Key
}

func (o otp) GetCode() string {
	return o.Code
}

func (o otp) GetRequestRetriesRemainingCount() int {
	return o.RequestRetriesRemainingCount
}

func (o otp) GetVerifyRetriesRemainingCount() int {
	return o.VerifyRetriesRemainingCount
}

func (o otp) GetLastCodeRequestTime() time.Time {
	return o.LastCodeRequestTime
}

func (o otp) GetExpirationTime() time.Time {
	return o.ExpirationTime
}

func (o *otp) SetCode(code string) {
	o.Code = code
}

/*
Handler
*/
type HandlerConfig struct {
	CodeExpiration                    time.Duration
	MaxRequestRetries                 int
	MaxVerifyRetries                  int
	ValidationExpiration              time.Duration
	RequestRetryLimitDuration         time.Duration
	ResetMaxVerifyRetriesOnNewRequest bool
}
type HandlerModel interface {
	WithCodeGenerator(generator CodeGenerator) HandlerModel
	WithVerifier(verifier Verifier) HandlerModel
	Normalize(request gm.IRequest, otpRequest RequestModel) (err error)
	Validate(request gm.IRequest, otpRequest RequestModel) (err error)
	New(request gm.IRequest, otpRequest RequestModel) (otp OTP, err error)
	Get(request gm.IRequest, otpRequest RequestModel) (otp OTP)
	Save(request gm.IRequest, otp OTP) (err error)
	RefreshCode(otp OTP)
	ResetCode(otp OTP)
	Verify(request gm.IRequest, otpRequest RequestModel) (err error)
}
type CodeGenerator interface {
	Generate() string
}
type Verifier interface {
	Verify(request gm.IRequest, otp OTP, otpRequest RequestModel) (err error)
}
type handler struct {
	config        HandlerConfig
	codeGenerator CodeGenerator
	verifier      Verifier
}

func NewHandler(config HandlerConfig) HandlerModel {
	h := new(handler)
	h.config = config
	return h
}
func (h *handler) WithCodeGenerator(generator CodeGenerator) HandlerModel {
	h.codeGenerator = generator
	return h
}
func (h *handler) WithVerifier(verifier Verifier) HandlerModel {
	h.verifier = verifier
	return h
}

func (h handler) Normalize(request gm.IRequest, otpRequest RequestModel) (err error) {
	return
}

func (h handler) Validate(request gm.IRequest, otpRequest RequestModel) (err error) {
	return
}

func (h handler) New(request gm.IRequest, otpRequest RequestModel) (result OTP, err error) {
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
	maxRequestRetries := h.config.MaxRequestRetries
	maxVerifyRetries := h.config.MaxVerifyRetries
	existingOTP := h.Get(request, otpRequest)
	if existingOTP != nil {
		maxRequestRetries = existingOTP.GetRequestRetriesRemainingCount()
		if !h.config.ResetMaxVerifyRetriesOnNewRequest {
			maxVerifyRetries = existingOTP.GetVerifyRetriesRemainingCount()
		}
		now := time.Now().UTC()
		diff := existingOTP.GetLastCodeRequestTime().Add(h.config.RequestRetryLimitDuration).Sub(now)
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
	result = NewOTP()
	result.SetID(otpRequest.GetID())
	result.SetKey(otpRequest.GetKey())
	result.SetRequestRetriesRemainingCount(maxRequestRetries - 1)
	result.SetVerifyRetriesRemainingCount(maxVerifyRetries)
	result.SetLastCodeRequestTime(time.Now().UTC())
	return
}

func (h handler) Get(request gm.IRequest, otpRequest RequestModel) (result OTP) {
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
	val := client.Get(context.Background(), otpRequest.GetID()).Val()
	if val != "" {
		result = new(otp)
		err = json.Unmarshal([]byte(val), &result)
		if err != nil {
			result = nil
			return
		}
	}
	return
}

func (h handler) Save(request gm.IRequest, otp OTP) (err error) {
	otpExp := otp.GetExpirationTime()
	expDuration := time.Duration(
		math.Max(
			float64(h.config.CodeExpiration),
			float64(h.config.ValidationExpiration),
		),
	)
	now := time.Now().UTC()
	exp := now.Add(expDuration)
	if otpExp.After(exp) {
		expDuration = otpExp.Sub(now)
	}
	otp.SetExpirationTime(now.Add(expDuration))
	err = base.RedisHandler.Set(otp.GetID(), otp, expDuration)
	if err != nil {
		return
	}
	return
}

func (h handler) RefreshCode(otp OTP) {
	if h.codeGenerator != nil {
		otp.SetCode(h.codeGenerator.Generate())
		return
	}
	if base.CurrentConfig.Debug {
		otp.SetCode("1111")
		return
	}
	min := 1000
	max := 10000
	otp.SetCode(fmt.Sprintf("%v", rand.Intn(max-min)+min))
	return
}

func (h handler) ResetCode(otp OTP) {
	otp.SetCode("")
	return
}

func (h handler) Verify(request gm.IRequest, otpRequest RequestModel) (err error) {
	client, err := base.RedisHandler.GetClient()
	if err != nil {
		return
	}
	otp := h.Get(request, otpRequest)
	if otp == nil {
		err = errors.GetUnAuthorizedError(request)
		return
	}
	verifyRetriesRemainingCount := otp.GetVerifyRetriesRemainingCount()
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
			if verifyRetriesRemainingCount > 0 {
				otp.SetVerifyRetriesRemainingCount(verifyRetriesRemainingCount - 1)
				if e := h.Save(request, otp); e != nil {
					err = e
					return
				}
			}
		}
	}()
	if err != nil {
		return
	}
	if verifyRetriesRemainingCount <= 0 {
		err = errors.GetForbiddenError(request, request.MustLocalize(&i18n.LocalizeConfig{
			DefaultMessage: &i18n.Message{
				ID:    "MaximumOtpRetriesExceeded",
				Other: "Maximum retries limit exceeded. try again later",
			},
		}))
		return
	}
	lastRequestTime := otp.GetLastCodeRequestTime()
	maxRequestValidTime := lastRequestTime.Add(h.config.CodeExpiration)
	code := otpRequest.GetCode()
	if code != otp.GetCode() ||
		time.Now().UTC().After(maxRequestValidTime) {
		err = errors.GetUnAuthorizedError(request)
		return
	}
	if h.verifier != nil {
		if err = h.verifier.Verify(request, otp, otpRequest); err != nil {
			return
		}
	}
	h.ResetCode(otp)
	err = h.Save(request, otp)
	if err != nil {
		return
	}
	return
}
