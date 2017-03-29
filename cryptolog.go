// Cryptolog is a tool for anonymizing webserver logs.
package cryptolog

import (
	// "fmt"
	// "os"
	"crypto/hmac"
	"crypto/md5"
	"encoding/base64"
)

func main() {
}

func hashIp(ip, salt string) string {
	mac := hmac.New(md5.New, []byte(salt))
	mac.Write([]byte(ip))
	hashedIp := mac.Sum(nil)
	return base64.StdEncoding.EncodeToString(hashedIp)[:6]
	// return string(hashedIp)
}
