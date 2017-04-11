package main

import (
	"regexp"
	"testing"
)

func TestHashIp(t *testing.T) {
	salt = []byte("ueErQYkQp5A9LrNbRQ1+XQ==")

	ip := "172.17.0.1"
	want := "JKx+3b"
	if got := hashIP(ip); got != want {
		t.Errorf("want %s, got %s", want, got)
	}
}

func TestProcessSingleLogEntry(t *testing.T) {
	salt = []byte("ueErQYkQp5A9LrNbRQ1+XQ==")

	replaceAllRegexp := compileRegexp(true)
	replaceOneRegexp := compileRegexp(false)

	var tests = []struct {
		input string
		want  string
		r     *regexp.Regexp
	}{
		{`172.17.0.1 - - [29/Mar/2017:20:09:52 +0000] "GET / HTTP/1.1" 304 -`,
			`JKx+3b - - [29/Mar/2017:20:09:52 +0000] "GET / HTTP/1.1" 304 -`,
			replaceAllRegexp},
		{`172.17.0.1 - - 172.17.0.1 - - [29/Mar/2017:20:09:52 +0000] "GET / HTTP/1.1" 304 -`,
			`JKx+3b - - JKx+3b - - [29/Mar/2017:20:09:52 +0000] "GET / HTTP/1.1" 304 -`,
			replaceAllRegexp},
		{`172.17.0.1 - - [29/Mar/2017:20:09:52 +0000] "GET / HTTP/1.1" 304 -`,
			`JKx+3b - - [29/Mar/2017:20:09:52 +0000] "GET / HTTP/1.1" 304 -`,
			replaceOneRegexp},
		{`172.17.0.1 - - 172.17.0.1 - - [29/Mar/2017:20:09:52 +0000] "GET / HTTP/1.1" 304 -`,
			`JKx+3b - - 172.17.0.1 - - [29/Mar/2017:20:09:52 +0000] "GET / HTTP/1.1" 304 -`,
			replaceOneRegexp},
	}

	for _, test := range tests {
		if got := processSingleLogEntry(test.input, test.r); got != test.want {
			t.Errorf("want %s, got %s", test.want, got)
		}
	}
}
