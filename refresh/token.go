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
	Value   string
	Exp     time.Duration
	Key     string
	KeyType base.KeyType
}

func getKey(token string) (key string) {
	return fmt.Sprintf("refresh:%s", token)
}

func New(key string, keyType base.KeyType, exp time.Duration) (token *Token, err error) {
	b := make([]byte, 32)
	_, err = rand.Read(b)
	if err != nil {
		return
	}
	token = &Token{
		Value:   fmt.Sprintf("%x", b),
		Exp:     exp,
		Key:     key,
		KeyType: keyType,
	}
	err = base.RedisHandler.Set(getKey(token.Value), token, exp)
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
	val := client.Get(getKey(value)).Val()
	if val != "" {
		token = new(Token)
		err = json.Unmarshal([]byte(val), &token)
		if err != nil {
			token = nil
			return
		}
		deleted := deleteToken(token.Value)
		if !deleted {
			err = errors.GetInternalServiceError("could not delete old refresh token")
			return
		}
	}
	return
}

func deleteToken(value string) (deleted bool) {
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
	count := client.Del(getKey(value)).Val()
	deleted = count > 0
	return
}
