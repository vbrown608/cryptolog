package cryptolog

import "testing"

func TestHashIp(t *testing.T) {
	ip := "172.17.0.1"
	salt := "ueErQYkQp5A9LrNbRQ1+XQ=="
	expected := "JKx+3b"
	if got := hashIp(ip, salt); got != expected {
		t.Errorf("Expected %s, got %s", expected, got)
	}
}
