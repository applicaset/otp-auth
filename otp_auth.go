package otp_auth

import (
	"context"
	"github.com/applicaset/otp-svc"
	"github.com/applicaset/user-svc"
	"github.com/pkg/errors"
)

const Name = "otp"

type otpAuth struct {
	otpSvc otp_svc.Service
}

type response struct {
	id string
}

func (rsp response) Validated() bool {
	return rsp.id != ""
}

func (rsp response) ID() string {
	return rsp.id
}

func (oa *otpAuth) Validate(ctx context.Context, args map[string]interface{}) (user.ValidateResponse, error) {
	rsp := new(response)
	iOTPID, ok := args["otp_id"]
	if !ok {
		return rsp, nil
	}

	otpID, ok := iOTPID.(string)
	if !ok {
		return rsp, nil
	}

	iPinCode, ok := args["pin_code"]
	if !ok {
		return rsp, nil
	}

	pinCode, ok := iPinCode.(string)
	if !ok {
		return rsp, nil
	}

	res, err := oa.otpSvc.VerifyOTP(ctx, otp_svc.VerifyOTPRequest{
		OTPUUID: otpID,
		PinCode: pinCode,
	})
	if err != nil {
		return nil, errors.Wrap(err, "error on verify otp")
	}

	rsp.id = res.PhoneNumber

	return rsp, nil
}

func NewAuthProvider(otpSvc otp_svc.Service) user.AuthProvider {
	oa := otpAuth{
		otpSvc: otpSvc,
	}

	return &oa
}

func New(otpSvc otp_svc.Service) user.Option {
	return user.WithAuthProvider(Name, NewAuthProvider(otpSvc))
}
