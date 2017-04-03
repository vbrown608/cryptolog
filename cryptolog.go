// Cryptolog is a tool for anonymizing webserver logs.
package main

import (
  "fmt"
  "os"
  "crypto/hmac"
  "crypto/md5"
  "crypto/rand"
  "encoding/base64"
  // "flag"
  "regexp"
  "time"
  "bufio"
)

var (
  salt = make([]byte, 10)
)

func main() {
  // var _delay = flag.Duration("", 1234, "help message for flagname")
  go generateSalt(time.Minute)
  scanner := bufio.NewScanner(os.Stdin)
  for scanner.Scan() {
    entry := processSingleLogEntry(scanner.Text())
    fmt.Println(entry)
  }
}

func generateSalt(delay time.Duration) {
  rand.Read(salt)
  time.Sleep(delay)
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
