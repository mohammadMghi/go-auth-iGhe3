package base

import "time"

type refreshToken struct {
	Token   string
	Exp     time.Duration
	Key     string
	KeyType KeyType
}
