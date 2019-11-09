package base

func Initialize(config *Config) {
	RedisHandler = &redisHandler{
		Config: config,
	}
}
