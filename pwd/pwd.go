package pwd

import (
	"encoding/base64"
	"github.com/wumansgy/goEncrypt"
	"log"
)

const (
	VerifyPwdNone = iota + 1
	VerifyPwdWithRunes
)

type VerifyPwd interface {
	Verify() bool
	WithRunes(string) VerifyPwd
}
type DefaultVerifyPwd struct {
	OldPwd        string
	NewPwd        string
	Runes         string
	VerifyType    int
	pwdCodingFunc func(string string) string
}

func NewVerifyPwd(oldPwd, newPwd string, pwdCodingFunc func(pwd string) string) VerifyPwd {
	return &DefaultVerifyPwd{
		OldPwd:        oldPwd,
		NewPwd:        newPwd,
		VerifyType:    VerifyPwdNone,
		pwdCodingFunc: pwdCodingFunc,
	}
}

func (v *DefaultVerifyPwd) WithRunes(runes string) VerifyPwd {
	v.Runes = runes
	v.VerifyType = VerifyPwdWithRunes
	return v
}
func (v *DefaultVerifyPwd) Verify() bool {
	switch v.VerifyType {
	case VerifyPwdNone:
		return v.VerifyNoneFunc()
	case VerifyPwdWithRunes:
		return v.VerifyPwdWithRunesFunc()
	}
	return false
}
func (v *DefaultVerifyPwd) VerifyNoneFunc() bool {
	if v.pwdCodingFunc != nil {
		return v.OldPwd == v.pwdCodingFunc(v.NewPwd)
	}
	return v.OldPwd == v.NewPwd
}
func (v *DefaultVerifyPwd) VerifyPwdWithRunesFunc() bool {
	bs, err := base64.StdEncoding.DecodeString(v.NewPwd)
	if err != nil {
		log.Fatal(err.Error())
		return false
	}
	result, err := goEncrypt.AesCtrDecrypt(bs, []byte(v.Runes), []byte("0000000000000000"))
	if err != nil {
		log.Fatal(err.Error())
		return false
	}
	v.NewPwd = string(result)
	return v.VerifyNoneFunc()
}
