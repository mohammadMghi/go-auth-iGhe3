package password

import (
	"fmt"
	"github.com/go-ginger/models/errors"
	"github.com/go-m/auth/base"
	"log"
)

type retries struct {
	Key                   string
	RetriesRemainingCount int
}

func getRetries(keyType base.KeyType, key string) (err error, result *retries) {
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
	redisKey := fmt.Sprintf("retries:%s:%s", keyType, key)
	result = &retries{
		Key:                   redisKey,
		RetriesRemainingCount: CurrentConfig.MaxRetries,
	}
	err = base.RedisHandler.Get(redisKey, result)
	if err != nil {
		return
	}
	return
}

func (r *retries) Save() (err error) {
	err = base.RedisHandler.Set(r.Key, r, CurrentConfig.MaxRetriesExpiration)
	if err != nil {
		return
	}
	return
}

func (r *retries) Validate() (err error) {
	if r.RetriesRemainingCount <= 0 {
		err = errors.GetValidationError("Maximum retries limit exceeded. try again later")
		return
	}
	return
}

func (r *retries) TryMore() (err error) {
	err = r.Validate()
	if err != nil {
		return
	}
	r.RetriesRemainingCount--
	err = r.Save()
	return
}
