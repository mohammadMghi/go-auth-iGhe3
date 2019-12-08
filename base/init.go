package base

func Initialize(config *Config) {
	RedisHandler = &redisHandler{
		Config: config,
	}
	if config.RefreshTokenHeaderKey == "" {
		config.RefreshTokenHeaderKey = "X-Refresh-Token"
	}
}
