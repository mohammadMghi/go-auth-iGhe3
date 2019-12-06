package base

func Initialize(config *Config) {
	RedisHandler = &redisHandler{
		Config: config,
	}
	if CurrentConfig.OptionalAuthOnAnyRequest {
		// TODO: handle refresh token if present on request header
	}
}
