package wndclient

import (
	"crypto/md5"
	"encoding/hex"
	"strconv"
	"time"
)

func MakeAuthHash(secret string) (string, int64) {
	iTime := time.Now().Unix()
	sTime := strconv.FormatInt(iTime, 10)
	h := md5.Sum([]byte(secret + sTime))
	return hex.EncodeToString(h[:]), iTime
}
