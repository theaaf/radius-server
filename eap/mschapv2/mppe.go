package mschapv2

import (
	"crypto/md5"
	"crypto/sha1"
	"math/rand"
	"time"
)

func GetMasterKey(passwordHashHash, ntResponse []byte) []byte {
	hash := sha1.New()
	hash.Write(passwordHashHash)
	hash.Write(ntResponse)
	hash.Write([]byte("This is the MPPE Master Key"))
	return hash.Sum(nil)[:16]
}

func GetAsymmetricStartKey(masterKey []byte, sessionKeyLength int, isSend, isServer bool) []byte {
	magic := "On the client side, this is the send key; on the server side, it is the receive key."
	if isSend == isServer {
		magic = "On the client side, this is the receive key; on the server side, it is the send key."
	}

	hash := sha1.New()
	hash.Write(masterKey)
	hash.Write([]byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	})
	hash.Write([]byte(magic))
	hash.Write([]byte{
		0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2,
		0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2,
		0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2,
		0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2,
	})
	return hash.Sum(nil)[:sessionKeyLength]
}

func GetMasterKeys(password string, ntResponse []byte) ([]byte, []byte) {
	hashHash := HashNtPasswordHash(NtPasswordHash(password))
	masterKey := GetMasterKey(hashHash, ntResponse)

	sendKey := GetAsymmetricStartKey(masterKey, 16, true, true)
	recvKey := GetAsymmetricStartKey(masterKey, 16, false, true)
	return sendKey, recvKey
}

func xor(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("mismatched lengths")
	}
	ret := append([]byte(nil), a...)
	for i, b := range b {
		ret[i] ^= b
	}
	return ret
}

func plaintext(key []byte) []byte {
	p := append([]byte{byte(len(key))}, key...)
	for len(p)%16 != 0 {
		p = append(p, 0)
	}
	return p
}

func ciphertext(secret, key, requestAuthenticator, salt []byte) []byte {
	P := plaintext(key)

	var c [][]byte
	var C []byte

	for i := 0; i < len(P)/16; i++ {
		p := P[i*16 : (i+1)*16]
		h := md5.New()
		if i == 0 {
			h.Write(secret)
			h.Write(requestAuthenticator)
			h.Write(salt)
		} else {
			h.Write(secret)
			h.Write(c[i-1])
		}
		c = append(c, xor(p, h.Sum(nil)))
		C = append(C, c[i]...)
	}

	salted := make([]byte, 2+len(C))
	salted[0] = salt[0]
	salted[1] = salt[1]
	copy(salted[2:], C)
	return salted
}

func salt(offset uint8) []byte {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	salt := uint8(r.Uint32())

	pfx := make([]byte, 2)
	pfx[0] = byte(0x80 | ((offset & 0x0f) << 3) | (salt & 0x07))
	pfx[1] = byte(salt)
	return pfx
}

func MPPEv2(secret []byte, password string, requestAuthenticator, ntResponse []byte) ([]byte, []byte) {
	send, recv := GetMasterKeys(password, ntResponse)
	sendEnc := ciphertext(secret, send, requestAuthenticator, salt(0))
	recvEnc := ciphertext(secret, recv, requestAuthenticator, salt(1))

	return sendEnc, recvEnc
}
