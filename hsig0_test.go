package hsig0

import (
	"encoding/hex"
	"github.com/miekg/dns"
	"testing"
)

func TestVerify(t *testing.T) {
	key, err := ParsePublicKey("aj7bjss4ae6hd3kdxzl4f6klirzla377uifxu5mnzczzk2v7p76ek")
	if err != nil {
		t.Fatal(err)
	}

	// msg signed using hsd
	valid := "3b9d8080000100000001000206676f6f676c6503636f6d0000300001c00c000600010000003c0026036e7331c00c09646e732d61646d696ec00c13e862850000038400000384000007080000003c000029100000000000000000001800ff0000000000530000fd00000000005f727e8a5f71d5ca65de008e51424eaf4593c1331d7a60294f0a08f3f686a8f9401bc9aa5768bd045c5dd4452ed6b9959c6b96e4e970e9b79b62ece84152bd8209048d77546d540f7d2c22"
	msg := new(dns.Msg)
	data, _ := hex.DecodeString(valid)
	if err := msg.Unpack(data) ; err != nil {
		t.Fatal(err)
	}

	// verify msg
	if err := Verify(msg, key) ; err != nil {
		t.Fatal(err)
	}

	// Verify should compress before checking since hsd signs messages compressed
	msg.Compress = false
	if err := Verify(msg, key) ; err != nil {
		t.Fatal(err)
	}

	// change msg
	msg.Rcode = dns.RcodeNameError
	if err := Verify(msg, key) ; err == nil {
		t.Fatal("want error bad sig")
	}

	// no sig 0
	msg.Rcode = dns.RcodeSuccess
	msg.Extra = nil

	if err := Verify(msg, key) ; err == nil {
		t.Fatal("want error no sig0")
	}
}