package auth

import (
	gm "github.com/go-ginger/models"
	"github.com/mohammadMghi/go-auth-iGhe3/base"
	"github.com/mohammadMghi/go-auth-iGhe3/refresh"
)

func (h *Handler) middleware(request gm.IRequest) (result interface{}) {
	req := request.GetBaseRequest()
	ctx := req.GetContext()
	refreshToken := ctx.GetHeader(base.CurrentConfig.RefreshTokenHeaderKey)
	if refreshToken != "" {
		token, err := refresh.GetAndDeleteToken(request, refreshToken)
		if err != nil {
			return
		}
		if token != nil {
			err = base.HandleLoginResponse(request, token.Key, token.KeyType, true)
			return
		}
	}
	if h.config.OptionalAuthOnAnyRequest {
		_ = h.config.LoginHandler.Authenticate(request)
	}
	return
}
