package refresh

import (
	"encoding/json"
	"fmt"
	gm "github.com/go-ginger/models"
	"github.com/go-ginger/models/errors"
	"github.com/go-m/auth/base"
	"github.com/nicksnyder/go-i18n/v2/i18n"
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

func GetToken(request gm.IRequest, value string) (token *Token, err error) {
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
		err = errors.GetNotFoundError(request)
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

func GetAndDeleteToken(request gm.IRequest, value string) (token *Token, err error) {
	token, err = GetToken(request, value)
	if token != nil {
		deleted := deleteTokenByKey(token.RedisKey)
		if !deleted {
			err = errors.GetInternalServiceError(request, request.MustLocalize(&i18n.LocalizeConfig{
				DefaultMessage: &i18n.Message{
					ID:    "CouldNotDeleteOldRefreshToken",
					Other: "could not delete old refresh token",
				},
			}))
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

func DeleteAllAccountTokens(request gm.IRequest, accountID interface{}) {
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
		err = errors.GetNotFoundError(request)
		return
	}
	for _, key := range keys {
		deleteTokenByKey(key.(string))
	}
	return
}
