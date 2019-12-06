package base

import (
	"github.com/go-ginger/helpers"
	m "github.com/go-ginger/models"
	"net/http"
	"reflect"
	"strconv"
	"time"
)

type Config struct {
	m.IConfig

	LoginHandler ILoginHandler

	Debug bool

	RedisAddr string
	RedisPwd  string
	RedisDb   int

	TokenExp        time.Duration
	RefreshTokenExp time.Duration

	// if true, checks authentication before any request
	OptionalAuthOnAnyRequest bool
	// if true, authentication response will be available in header.
	// useful when using OptionalAuthOnAnyRequest=true, which makes check
	// authentication on any request and response in header of response
	AllowAuthResponseHeaders bool

	CookieEnabled bool
	CookiePattern *http.Cookie
}

var CurrentConfig *Config

func (c *Config) InitializeConfig(input interface{}) {
	CurrentConfig = c
	var redisAddr string
	var redisPw string
	var redisDb int64

	if input != nil {
		v := reflect.Indirect(reflect.ValueOf(input))
		debugAddrField := v.FieldByName("Debug")
		if debugAddrField.CanAddr() {
			c.Debug = debugAddrField.Bool()
		}
		redisAddrField := v.FieldByName("RedisAddr")
		if redisAddrField.CanAddr() {
			redisAddr = redisAddrField.String()
		}
		redisPwField := v.FieldByName("RedisPw")
		if redisPwField.CanAddr() {
			redisPw = redisPwField.String()
		}
		redisDbField := v.FieldByName("RedisDb")
		if redisDbField.CanAddr() {
			redisDb = redisDbField.Int()
		}
	}

	if redisAddr == "" {
		redisAddr = helpers.GetEnv("REDIS_ADDR", "localhost:6379")
	}
	if redisPw == "" {
		redisPw = helpers.GetEnv("REDIS_PW", "")
	}
	if redisDb == 0 {
		redisDb, _ = strconv.ParseInt(helpers.GetEnv("REDIS_DB", "0"), 10, 64)
	}

	c.RedisAddr = redisAddr
	c.RedisPwd = redisPw
	c.RedisDb = int(redisDb)
}
