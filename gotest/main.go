package main

import (
	"fmt"
	"gotest/googleAuthenticator"
)

func main() {

	// 用草料二维码 https://cli.im/ 生成 以下地址：
	//otpauth://totp/Google:Gavin@gamil.com?secret=LC42VPXL3VUMBCAN&issuer=Google
	ga := googleAuthenticator.NewGAuth()
	secret, err := ga.CreateSecret(16)
	if err != nil {
		fmt.Println(err)
	}
	secret = "LC42VPXL3VUMBCAN"

	auth, err := ga.GetOtpAuth("Google", "Gavin@gamil.com", secret)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(auth)

	code, err := ga.GetCode(secret)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(code)
	//code := "027093"

	ret, err := ga.VerifyCode(secret, code, 1)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(ret)

}
