package refresh

import (
	"encoding/json"
	"fmt"
	"github.com/go-ginger/models/errors"
	"github.com/go-m/auth/base"
	"log"
	"math/rand"
	"time"
)

type Token struct {
	Value    string
	Exp      time.Duration
	Key      string
	KeyType  base.KeyType
	RedisKey string
}

func getKey(accountID interface{}, token string) (key string) {
	return fmt.Sprintf("refresh:%v:%s", accountID, token)
}

func New(accountID interface{}, key string, keyType base.KeyType, exp time.Duration) (token *Token, err error) {
	b := make([]byte, 32)
	_, err = rand.Read(b)
	if err != nil {
		return
	}
	value := fmt.Sprintf("%x", b)
	token = &Token{
		RedisKey: getKey(accountID, value),
		Value:    value,
		Exp:      exp,
		Key:      key,
		KeyType:  keyType,
	}
	err = base.RedisHandler.Set(token.RedisKey, token, exp)
	return
}

func GetToken(value string) (token *Token, err error) {
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
	key := getKey("*", value)
	cmdVal := client.Do("KEYS", key).Val()
	keys := cmdVal.([]interface{})
	if err != nil || len(keys) == 0 {
		err = errors.GetNotFoundError()
		return
	}
	key = keys[0].(string)
	val := client.Get(key).Val()
	if val != "" {
		token = new(Token)
		err = json.Unmarshal([]byte(val), &token)
		if err != nil {
			token = nil
			return
		}
	}
	return
}

func GetAndDeleteToken(value string) (token *Token, err error) {
	token, err = GetToken(value)
	if token != nil {
		deleted := deleteTokenByKey(token.RedisKey)
		if !deleted {
			err = errors.GetInternalServiceError("could not delete old refresh token")
			return
		}
	}
	return
}

func deleteTokenByKey(key string) (deleted bool) {
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
	count := client.Del(key).Val()
	deleted = count > 0
	return
}

func DeleteAllAccountTokens(accountID interface{}) {
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
	key := getKey(accountID, "*")
	cmdVal := client.Do("KEYS", key).Val()
	keys := cmdVal.([]interface{})
	if err != nil || len(keys) == 0 {
		err = errors.GetNotFoundError()
		return
	}
	for _, key := range keys {
		deleteTokenByKey(key.(string))
	}
	return
}
