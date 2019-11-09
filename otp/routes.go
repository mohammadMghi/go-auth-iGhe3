package otp

import (
	g "github.com/go-ginger/ginger"
)

var request = new(requestOtpController)
var verify = new(verifyOtpController)

func RegisterRoutes(router *g.RouterGroup) {
	request.AddRoute("Post")
	verify.AddRoute("Post")

	request.RegisterRoutes(request, "/otp", router)
	verify.RegisterRoutes(verify, "/otp/verify", router)
}
