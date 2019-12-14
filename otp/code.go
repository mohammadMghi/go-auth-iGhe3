package otp

import (
	"encoding/json"
	"fmt"
	"github.com/go-ginger/models/errors"
	"github.com/go-m/auth/base"
	"log"
	"math"
	"math/rand"
	"time"
)

type OTP struct {
	Code                         string
	Key                          string
	RequestRetriesRemainingCount int
	VerifyRetriesRemainingCount  int
	LastCodeRequestTime          string
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
	err = client.Set(otp.Key, otp,
		time.Duration(math.Max(float64(CurrentConfig.CodeExpiration),
			float64(CurrentConfig.ValidationExpiration)))).Err()
	return
}

func (otp *OTP) Verify(code string) (err error) {
	if code == "" {
		err = errors.GetUnAuthorizedError()
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
	maxRequestValidTime := lastCodeRequestTime.Add(CurrentConfig.CodeExpiration)
	if code != otp.Code || otp.VerifyRetriesRemainingCount <= 0 ||
		time.Now().UTC().After(maxRequestValidTime) {
		err = errors.GetUnAuthorizedError()
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

func getKey(mobile string) (key string) {
	return fmt.Sprintf("otp:%s", mobile)
}

func generateNewOTP(mobile string) (otp *OTP, err error) {
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
	}
	if maxRequestRetries <= 0 {
		err = errors.GetValidationError("Maximum retries limit exceeded. try again later")
		return
	}
	otp = &OTP{
		Code:                         fmt.Sprintf("%v", rand.Intn(10000)+1000),
		Key:                          getKey(mobile),
		RequestRetriesRemainingCount: maxRequestRetries - 1,
		VerifyRetriesRemainingCount:  maxVerifyRetries,
		LastCodeRequestTime:          time.Now().UTC().Format(time.RFC3339),
	}
	if base.CurrentConfig.Debug {
		otp.Code = "1111"
	}
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
