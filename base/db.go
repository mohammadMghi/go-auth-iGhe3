package base

import (
	"encoding/json"
	"github.com/go-redis/redis"
	"time"
)

type redisHandler struct {
	Config *Config
}

var RedisHandler *redisHandler

func (h *redisHandler) GetClient() (client *redis.Client, err error) {
	client = redis.NewClient(&redis.Options{
		Addr:     h.Config.RedisAddr,
		Password: h.Config.RedisPwd,
		DB:       h.Config.RedisDb,
	})
	return
}

func (h *redisHandler) Set(key string, value interface{}, expiration time.Duration) error {
	client, err := RedisHandler.GetClient()
	defer func() {
		e := client.Close()
		if e != nil {
			err = e
			return
		}
	}()
	p, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return client.Set(key, p, expiration).Err()
}

func (h *redisHandler) Get(key string, dest interface{}) error {
	client, err := RedisHandler.GetClient()
	defer func() {
		e := client.Close()
		if e != nil {
			err = e
			return
		}
	}()
	p := client.Get(key).Val()
	if p != "" {
		return json.Unmarshal([]byte(p), dest)
	}
	return nil
}
