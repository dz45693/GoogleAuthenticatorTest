package main

import (
	"fmt"
	"gotest/googleAuthenticator"
)

func createSecret(ga *googleAuthenticator.GAuth) string {
	secret, err := ga.CreateSecret(16)
	if err != nil {
		return ""
	}
	return secret
}

func getCode(ga *googleAuthenticator.GAuth, secret string) string {
	code, err := ga.GetCode(secret)
	if err != nil {
		return "*"
	}
	return code
}

func verifyCode(ga *googleAuthenticator.GAuth, secret, code string) bool {
	// 1:30sec
	ret, err := ga.VerifyCode(secret, code, 1)
	if err != nil {
		return false
	}
	return ret
}

func main() {
	/*
		if len(os.Args) != 2 {
			return
		}
	*/
	// 用草料二维码 https://cli.im/ 生成 以下地址：
	//otpauth://totp/gitlab.com:410534805@qq.com?secret=LC42VPXL3VUMBCAN&issuer=gitlab.com
	secret := "LC42VPXL3VUMBCAN"
	//secret := os.Args[1]
	//secret := "IU7B5Q3VBL55Q645"
	ga := googleAuthenticator.NewGAuth()
	code := getCode(ga, secret)
	//code := "027093"
	ret := verifyCode(ga, secret, code)
	fmt.Println(ret)

}
