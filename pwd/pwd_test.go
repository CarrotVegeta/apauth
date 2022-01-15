package pwd

import (
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestPwd(t *testing.T) {
	a := &A{}
	a.Verify(func(pwd string) string {
		return MD5String([]byte(Hash("#" + pwd + "!")))
	})

}

type PasswordCodingFunc func(pwd string) string
type A struct {
	pa PasswordCodingFunc
}

func (a *A) Verify(interface{}) {
	flag := NewVerifyPwd("123", "123", a.pa).Verify()
	fmt.Println(flag)
	flag = NewVerifyPwd("123", "123", func(pwd string) string {
		return MD5String([]byte(Hash("#" + pwd + "!")))
	}).Verify()
	fmt.Println(flag)
	flag = NewVerifyPwd("89c766f8cf1624a178f4c8cf599d978b", "s8STrcm2", func(pwd string) string {
		return MD5String([]byte(Hash("#" + pwd + "!")))
	}).WithRunes("pLnfgDsc3WD9F3qN").Verify()
	fmt.Println(flag)
}
func MD5(data []byte) []byte {
	md5Ctx := md5.New()
	md5Ctx.Write(data)
	return md5Ctx.Sum(nil)
}

func MD5String(data []byte) string {
	return hex.EncodeToString(MD5(data))
}
func Hash(v string) string {
	h := sha1.New()
	h.Write([]byte(v))
	return fmt.Sprintf("%x", h.Sum(nil))
}
