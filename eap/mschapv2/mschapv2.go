package mschapv2

import (
	"crypto/des"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

// https://tools.ietf.org/html/rfc2759#section-8.1
func GenerateNTResponse(authenticatorChallenge, peerChallenge, userName []byte, password string) []byte {
	challenge := ChallengeHash(peerChallenge, authenticatorChallenge, userName)
	passwordHash := NtPasswordHash(password)
	return ChallengeResponse(challenge, passwordHash)
}

// https://tools.ietf.org/html/rfc2759#section-8.2
func ChallengeHash(peerChallenge, authenticatorChallenge, userName []byte) []byte {
	h := sha1.New()
	h.Write(peerChallenge)
	h.Write(authenticatorChallenge)
	h.Write(userName)
	return h.Sum(nil)[:8]
}

// https://tools.ietf.org/html/rfc2759#section-8.3
func NtPasswordHash(password string) []byte {
	encoded := utf16.Encode([]rune(password))
	passwordBuf := make([]byte, len(password)*2)
	for i := 0; i < len(encoded); i++ {
		binary.LittleEndian.PutUint16(passwordBuf[i*2:], encoded[i])
	}

	h := md4.New()
	h.Write(passwordBuf)
	return h.Sum(nil)
}

// https://tools.ietf.org/html/rfc2759#section-8.4
func HashNtPasswordHash(passwordHash []byte) []byte {
	h := md4.New()
	h.Write(passwordHash)
	return h.Sum(nil)
}

// https://tools.ietf.org/html/rfc2759#section-8.5
func ChallengeResponse(challenge, passwordHash []byte) []byte {
	zPasswordHash := make([]byte, 21)
	copy(zPasswordHash, passwordHash)
	response := make([]byte, 24)
	copy(response, DesEncrypt(challenge, zPasswordHash[0:7]))
	copy(response[8:], DesEncrypt(challenge, zPasswordHash[7:14]))
	copy(response[16:], DesEncrypt(challenge, zPasswordHash[14:]))
	return response
}

// https://tools.ietf.org/html/rfc2759#section-8.6
func DesEncrypt(clear, key []byte) []byte {
	keyWithParity := make([]byte, 8)

	next := byte(0)
	for i := 0; i < 7; i++ {
		keyWithParity[i] = (key[i] >> uint(i)) | next
		next = key[i] << uint(7-i)
	}
	keyWithParity[7] = next

	c, err := des.NewCipher(keyWithParity)
	if err != nil {
		panic(err)
	}
	ret := make([]byte, 8)
	c.Encrypt(ret, clear)
	return ret
}

// https://tools.ietf.org/html/rfc2759#section-8.7
func GenerateAuthenticatorResponse(password string, ntResponse, peerChallenge, authenticatorChallenge, userName []byte) string {
	passwordHash := NtPasswordHash(password)
	passwordHashHash := HashNtPasswordHash(passwordHash)

	h := sha1.New()
	h.Write(passwordHashHash)
	h.Write(ntResponse)
	h.Write([]byte{
		0x4d, 0x61, 0x67, 0x69, 0x63, 0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x74, 0x6f,
		0x20, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x20, 0x73, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67,
		0x20, 0x63, 0x6f, 0x6e, 0x73, 0x74, 0x61, 0x6e, 0x74,
	})
	digest := h.Sum(nil)

	challenge := ChallengeHash(peerChallenge, authenticatorChallenge, userName)

	h = sha1.New()
	h.Write(digest)
	h.Write(challenge)
	h.Write([]byte{
		0x50, 0x61, 0x64, 0x20, 0x74, 0x6f, 0x20, 0x6d, 0x61, 0x6b, 0x65, 0x20, 0x69, 0x74, 0x20,
		0x64, 0x6f, 0x20, 0x6d, 0x6f, 0x72, 0x65, 0x20, 0x74, 0x68, 0x61, 0x6e, 0x20, 0x6f, 0x6e,
		0x65, 0x20, 0x69, 0x74, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	})
	digest = h.Sum(nil)

	return fmt.Sprintf("S=%X", digest)
}
