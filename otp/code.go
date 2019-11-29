package otp

import (
	"fmt"
	"github.com/go-m/auth/base"
	"log"
	"math/rand"
)

func getKey(mobile string) (key string) {
	return fmt.Sprintf("otp:%s", mobile)
}

func generateNewCode(mobile string) (code string, err error) {
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
	code = fmt.Sprintf("%v", rand.Intn(10000)+1000)
	if base.CurrentConfig.Debug {
		code = "1111"
	}
	err = client.Set(getKey(mobile), code, CurrentConfig.CodeExpiration).Err()
	return
}

func getCode(mobile string) (code string, err error) {
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
	code = client.Get(getKey(mobile)).Val()
	return
}

func removeCode(mobile string) (count int64, err error) {
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
	count = client.Del(getKey(mobile)).Val()
	return
}
