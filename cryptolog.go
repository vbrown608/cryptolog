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
  ipv4_exp := `^(\d\d?\d?\.\d\d?\d?\.\d\d?\d?\.\d\d?\d?).*`
  r, _ := regexp.Compile(ipv4_exp)
  indexes := r.FindStringSubmatchIndex(log_entry)
  hashedIP := hashIp(log_entry[indexes[2]:indexes[3]])
  return log_entry[:indexes[2]] + hashedIP + log_entry[indexes[3]:]
}

func hashIp(ip string) string {
  mac := hmac.New(md5.New, []byte(salt))
  mac.Write([]byte(ip))
  hashedIp := mac.Sum(nil)
  return base64.StdEncoding.EncodeToString(hashedIp)[:6]
}
