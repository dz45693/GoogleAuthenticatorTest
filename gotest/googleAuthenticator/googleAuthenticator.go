package googleAuthenticator

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"strconv"
	"strings"
	"time"
)

type GAuth struct {
	codeLen float64
	table   map[string]int
}

var (
	ErrSecretLengthLss     = errors.New("secret length lss 6 error")
	ErrSecretLength        = errors.New("secret length error")
	ErrPaddingCharCount    = errors.New("padding char count error")
	ErrPaddingCharLocation = errors.New("padding char Location error")
	ErrParam               = errors.New("param error")
)

var (
	Table = []string{
		"A", "B", "C", "D", "E", "F", "G", "H", // 7
		"I", "J", "K", "L", "M", "N", "O", "P", // 15
		"Q", "R", "S", "T", "U", "V", "W", "X", // 23
		"Y", "Z", "2", "3", "4", "5", "6", "7", // 31
		"=", // padding char
	}

	allowedValues = map[int]string{
		6: "======",
		4: "====",
		3: "===",
		1: "=",
		0: "",
	}
)

func NewGAuth() *GAuth {
	return &GAuth{
		codeLen: 6,
		table:   arrayFlip(Table),
	}
}

// SetCodeLength Set the code length, should be >=6
func (this *GAuth) SetCodeLength(length float64) error {
	if length < 6 {
		return ErrSecretLengthLss
	}
	this.codeLen = length
	return nil
}

// CreateSecret create new secret
// 16 characters, randomly chosen from the allowed base32 characters.
func (this *GAuth) CreateSecret(lens ...int) (string, error) {
	var (
		length int
		secret []string
	)
	// init length
	switch len(lens) {
	case 0:
		length = 16
	case 1:
		length = lens[0]
	default:
		return "", ErrParam
	}
	for i := 0; i < length; i++ {
		secret = append(secret, Table[rand.Intn(len(Table))])
	}
	return strings.Join(secret, ""), nil
}

// VerifyCode Check if the code is correct. This will accept codes starting from $discrepancy*30sec ago to $discrepancy*30sec from now
func (this *GAuth) VerifyCode(secret, code string, discrepancy int64) (bool, error) {
	// now time
	curTimeSlice := time.Now().Unix() / 30
	for i := -discrepancy; i <= discrepancy; i++ {
		calculatedCode, err := this.GetCode(secret, curTimeSlice+i)
		if err != nil {
			return false, err
		}
		if calculatedCode == code {
			return true, nil
		}
	}
	return false, nil
}

// GetCode Calculate the code, with given secret and point in time
func (this *GAuth) GetCode(secret string, timeSlices ...int64) (string, error) {
	var timeSlice int64
	switch len(timeSlices) {
	case 0:
		timeSlice = time.Now().Unix() / 30
	case 1:
		timeSlice = timeSlices[0]
	default:
		return "", ErrParam
	}
	secret = strings.ToUpper(secret)
	secretKey, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return "", err
	}
	tim, err := hex.DecodeString(fmt.Sprintf("%016x", timeSlice))
	if err != nil {
		return "", err
	}
	hm := HmacSha1(secretKey, tim)
	offset := hm[len(hm)-1] & 0x0F
	hashpart := hm[offset : offset+4]
	value, err := strconv.ParseInt(hex.EncodeToString(hashpart), 16, 0)
	if err != nil {
		return "", err
	}
	value = value & 0x7FFFFFFF
	modulo := int64(math.Pow(10, this.codeLen))
	format := fmt.Sprintf("%%0%dd", int(this.codeLen))
	return fmt.Sprintf(format, value%modulo), nil
}

func arrayFlip(oldArr []string) map[string]int {
	newArr := make(map[string]int, len(oldArr))
	for key, value := range oldArr {
		newArr[value] = key
	}
	return newArr
}

func HmacSha1(key, data []byte) []byte {
	mac := hmac.New(sha1.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func (this *GAuth) GetOtpAuth(issuer, accountTitleNoSpaces, secret string) (string, error) {
	secretbyte, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return "", err
	}

	secret = base32.StdEncoding.EncodeToString(secretbyte)
	auth := fmt.Sprintf("otpauth://totp/%v:%v?secret=%v&issuer=%v", issuer, accountTitleNoSpaces, secret, issuer)

	return auth, nil
}
