package hsig0

// this is based on miekg dns sig0 but supports non standard BLAKE2bSECP256K1 with PRIVATEEDNS (algo code 253)
// checkout https://github.com/miekg/dns/blob/master/sig0.go
// for standard algorithm types

import (
	"crypto"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/decred/dcrd/dcrec/secp256k1/v3"
	"github.com/decred/dcrd/dcrec/secp256k1/v3/ecdsa"
	"github.com/miekg/dns"
	_ "golang.org/x/crypto/blake2b"
	"strings"
	"time"
)

// handshake sig0 algorithm
const BLAKE2bSECP256K1 = dns.PRIVATEDNS

const (
	headerSize = 12
)

type PublicKey struct {
	pub *secp256k1.PublicKey
}

// ParsePublicKey parses the node public key
func ParsePublicKey(key string) (*PublicKey, error) {
	b, err := base32.StdEncoding.DecodeString(strings.ToUpper(key + "==="))
	if err != nil {
		return nil, fmt.Errorf("hsig0: invalid base32 encoded string: %v", err)
	}

	pub, err := secp256k1.ParsePubKey(b)
	if err != nil {
		return nil, fmt.Errorf("hsig0: parse key failed:  %v", err)
	}

	return &PublicKey{pub: pub}, nil
}

// Verify validates the message using the key k.
func Verify(msg *dns.Msg, k *PublicKey) error {
	// hsd signs messages compressed
	// compress before packing
	c := msg.Compress
	msg.Compress = true
	buf, err := msg.Pack()
	msg.Compress = c

	if err != nil {
		return err
	}

	var sig *dns.SIG
L:
	for _, r := range msg.Extra {
		switch t := r.(type) {
		case *dns.SIG:
			sig = t
			break L
		}
	}

	if sig == nil {
		return errors.New("no sig rr found")
	}

	return verifySig(buf, k, sig)
}

func verifySig(buf []byte, k *PublicKey, rr *dns.SIG) error {
	if k == nil {
		return dns.ErrKey
	}
	if rr.KeyTag == 0 || len(rr.SignerName) == 0 || rr.Algorithm == 0 {
		return dns.ErrKey
	}

	var hash crypto.Hash
	switch rr.Algorithm {
	case BLAKE2bSECP256K1:
		hash = crypto.BLAKE2b_256
	default:
		return dns.ErrAlg
	}
	hasher := hash.New()

	buflen := len(buf)
	qdc := binary.BigEndian.Uint16(buf[4:])
	anc := binary.BigEndian.Uint16(buf[6:])
	auc := binary.BigEndian.Uint16(buf[8:])
	adc := binary.BigEndian.Uint16(buf[10:])
	offset := headerSize
	var err error
	for i := uint16(0); i < qdc && offset < buflen; i++ {
		_, offset, err = dns.UnpackDomainName(buf, offset)
		if err != nil {
			return err
		}
		// Skip past Type and Class
		offset += 2 + 2
	}
	for i := uint16(1); i < anc+auc+adc && offset < buflen; i++ {
		_, offset, err = dns.UnpackDomainName(buf, offset)
		if err != nil {
			return err
		}
		// Skip past Type, Class and TTL
		offset += 2 + 2 + 4
		if offset+1 >= buflen {
			continue
		}
		rdlen := binary.BigEndian.Uint16(buf[offset:])
		offset += 2
		offset += int(rdlen)
	}
	if offset >= buflen {
		return errors.New("overflowing unpacking signed message offset")
	}

	// offset should be just prior to SIG
	bodyend := offset
	// owner name SHOULD be root
	_, offset, err = dns.UnpackDomainName(buf, offset)
	if err != nil {
		return err
	}
	// Skip Type, Class, TTL, RDLen
	offset += 2 + 2 + 4 + 2
	sigstart := offset
	// Skip Type Covered, Algorithm, Labels, Original TTL
	offset += 2 + 1 + 1 + 4
	if offset+4+4 >= buflen {
		return errors.New("overflowing unpacking signed message offset")
	}
	expire := binary.BigEndian.Uint32(buf[offset:])
	offset += 4
	incept := binary.BigEndian.Uint32(buf[offset:])
	offset += 4
	now := uint32(time.Now().Unix())
	if now < incept || now > expire {
		return dns.ErrTime
	}
	// Skip key tag
	offset += 2
	var signername string
	signername, offset, err = dns.UnpackDomainName(buf, offset)
	if err != nil {
		return err
	}
	// If key has come from the DNS name compression might
	// have mangled the case of the name
	if !strings.EqualFold(signername, ".") {
		return errors.New("signer name doesn't match key name")
	}
	sigend := offset
	hasher.Write(buf[sigstart:sigend])
	hasher.Write(buf[:10])
	hasher.Write([]byte{
		byte((adc - 1) << 8),
		byte(adc - 1),
	})
	hasher.Write(buf[12:bodyend])

	hashed := hasher.Sum(nil)
	sig := buf[sigend:]

	var rModBytes [32]byte
	copy(rModBytes[:], sig[:len(sig)/2])

	var sModBytes [32]byte
	copy(sModBytes[:], sig[len(sig)/2:])

	ecdsaRModNScalar := &secp256k1.ModNScalar{}
	ecdsaRModNScalar.SetBytes(&rModBytes)

	ecdsaSModNScalar := &secp256k1.ModNScalar{}
	ecdsaSModNScalar.SetBytes(&sModBytes)

	signature := ecdsa.NewSignature(ecdsaRModNScalar, ecdsaSModNScalar)
	if signature.Verify(hashed, k.pub) {
		return nil
	}

	return dns.ErrSig
}
