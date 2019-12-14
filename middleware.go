package auth

import (
	gm "github.com/go-ginger/models"
	"github.com/go-m/auth/base"
	"github.com/go-m/auth/refresh"
)

func middleware(request gm.IRequest) (result interface{}) {
	req := request.GetBaseRequest()
	ctx := req.GetContext()
	refreshToken := ctx.GetHeader(base.CurrentConfig.RefreshTokenHeaderKey)
	if refreshToken == "" {
		return
	}
	token, err := refresh.GetAndDeleteToken(refreshToken)
	if err != nil || token == nil {
		return
	}
	err = base.HandleLoginResponse(request, token.Key, token.KeyType, true)
	return
}
