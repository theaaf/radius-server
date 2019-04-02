package eap

import (
	"crypto/md5"
	"crypto/subtle"
	"fmt"
)

const (
	TypeIdentity         = 1
	TypeNotification     = 2
	TypeNak              = 3
	TypeMD5Challenge     = 4
	TypeOneTimePassword  = 5
	TypeGenericTokenCard = 6
	TypeMSCHAPv2         = 26
	TypeExpendedNak      = 254
)

type UnsupportedTypeError struct {
	Type int
}

func (e UnsupportedTypeError) Error() string {
	return fmt.Sprintf("unsupported type: %d", e.Type)
}

type Identity struct {
	Identity string
}

func (d *Identity) UnmarshalBinary(b []byte) error {
	if b[0] != TypeIdentity {
		return fmt.Errorf("wrong type byte")
	}
	d.Identity = string(b[1:])
	return nil
}

type Nak struct {
	DesiredAuthenticationTypes []int
}

func (d *Nak) UnmarshalBinary(b []byte) error {
	if b[0] != TypeNak {
		return fmt.Errorf("wrong type byte")
	}
	d.DesiredAuthenticationTypes = make([]int, len(b))
	for i, b := range b[1:] {
		d.DesiredAuthenticationTypes[i] = int(b)
	}
	return nil
}

type MD5Challenge struct {
	Value []byte
	Name  []byte
}

func (d *MD5Challenge) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 2+len(d.Value)+len(d.Name))
	buf[0] = TypeMD5Challenge
	buf[1] = byte(len(d.Value))
	copy(buf[2:], d.Value)
	copy(buf[2+len(d.Value):], d.Name)
	return buf, nil
}

func (d *MD5Challenge) UnmarshalBinary(b []byte) error {
	if b[0] != TypeMD5Challenge {
		return fmt.Errorf("wrong type byte")
	} else if len(b) < 2 {
		return fmt.Errorf("buffer too short")
	}
	valueSize := int(b[1])
	if len(b)-2 < valueSize {
		return fmt.Errorf("buffer too short for value size")
	}

	b = append([]byte(nil), b[2:]...)

	d.Value = b[:valueSize]
	d.Name = b[valueSize:]
	return nil
}

func (d *MD5Challenge) Verify(identifier int, password, requestChallenge []byte) bool {
	h := md5.New()
	h.Write([]byte{byte(identifier)})
	h.Write(password)
	h.Write(requestChallenge)
	return subtle.ConstantTimeCompare(h.Sum(nil), d.Value) == 1
}
