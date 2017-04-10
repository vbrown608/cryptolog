// Cryptolog is a tool for anonymizing webserver logs.
package main

import (
  "fmt"
  "os"
  "crypto/hmac"
  "crypto/md5"
  "crypto/rand"
  "encoding/base64"
  "flag"
  "regexp"
  "time"
  "bufio"
)

const (
  ipv4_exp = `(\d\d?\d?\.\d\d?\d?\.\d\d?\d?\.\d\d?\d?)`
  ipv6_exp = `(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))`
)

var (
  salt = make([]byte, 10)
)

func main() {
  saltLifetime := flag.Duration("salt-lifetime", time.Hour*24,
`Set the lifetime of the hash salt.
This is the duration during which the hashes of a given ip will be identical.
See https://golang.org/pkg/time/#ParseDuration for format.` )
  flag.Parse()
  go generateSalt(*saltLifetime)

  scanner := bufio.NewScanner(os.Stdin)
  for scanner.Scan() {
    entry := processSingleLogEntry(scanner.Text())
    fmt.Println(entry)
  }
}

func generateSalt(delay time.Duration) {
  for {
    rand.Read(salt)
    time.Sleep(delay)
  }
}

func processSingleLogEntry(log_entry string) string {
  r, _ := regexp.Compile(ipv4_exp + "|" + ipv6_exp)
  hashed_entry := r.ReplaceAllStringFunc(log_entry, hashIp)
  return hashed_entry
}

func hashIp(ip string) string {
  mac := hmac.New(md5.New, []byte(salt))
  mac.Write([]byte(ip))
  hashedIp := mac.Sum(nil)
  return base64.StdEncoding.EncodeToString(hashedIp)[:6]
}
