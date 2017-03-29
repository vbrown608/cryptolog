package cryptolog

import "testing"

func TestHashIp(t *testing.T) {
	salt = []byte("ueErQYkQp5A9LrNbRQ1+XQ==")

	ip := "172.17.0.1"
	expected := "JKx+3b"
	if got := hashIp(ip); got != expected {
		t.Errorf("Expected %s, got %s", expected, got)
	}
}

func TestProcessSingleLogEntry(t *testing.T) {
	salt = []byte("ueErQYkQp5A9LrNbRQ1+XQ==")

	log_entry := `172.17.0.1 - - [29/Mar/2017:20:09:52 +0000] "GET / HTTP/1.1" 304 -`
	expected := `JKx+3b - - [29/Mar/2017:20:09:52 +0000] "GET / HTTP/1.1" 304 -`
	if got := processSingleLogEntry(log_entry); got != expected {
		t.Errorf("Expected %s, got %s", expected, got)
	}
}
