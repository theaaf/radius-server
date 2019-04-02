package eap

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding"
	"encoding/binary"
	"fmt"

	"github.com/theaaf/radius-server/eap/mschapv2"
)

type MSCHAPv2 struct {
	OpCode int
	Id     int
	Data   []byte
}

func NewMSCHAPv2(Id int, op interface{}) (*MSCHAPv2, error) {
	ret := &MSCHAPv2{
		Id: Id,
	}

	var err error
	switch v := op.(type) {
	case *MSCHAPv2Challenge:
		ret.OpCode = MSCHAPv2OpCodeChallenge
		ret.Data, err = v.MarshalBinary()
	case *MSCHAPv2SuccessRequest:
		ret.OpCode = MSCHAPv2OpCodeSuccess
		ret.Data, err = v.MarshalBinary()
	default:
		return nil, fmt.Errorf("unsupported op type %T", op)
	}

	if err != nil {
		return nil, err
	}
	return ret, nil
}

const (
	MSCHAPv2OpCodeChallenge = 1
	MSCHAPv2OpCodeResponse  = 2
	MSCHAPv2OpCodeSuccess   = 3
)

type UnsupportedMSCHAPv2OpCodeError struct {
	OpCode int
}

func (e UnsupportedMSCHAPv2OpCodeError) Error() string {
	return fmt.Sprintf("unsupported mschapv2 opcode: %d", e.OpCode)
}

func (d *MSCHAPv2) UnmarshalBinary(b []byte) error {
	if b[0] != TypeMSCHAPv2 {
		return fmt.Errorf("wrong type byte")
	} else if len(b) < 2 {
		return fmt.Errorf("buffer too short")
	}
	d.OpCode = int(b[1])
	if len(b) == 2 {
		return nil
	} else if len(b) < 5 {
		return fmt.Errorf("buffer too short")
	}
	if int(binary.BigEndian.Uint16(b[3:])) != 4+len(b)-5 {
		return fmt.Errorf("wrong length")
	}
	d.Id = int(b[2])
	d.Data = append([]byte(nil), b[5:]...)
	return nil
}

func (d *MSCHAPv2) MarshalBinary() ([]byte, error) {
	b := make([]byte, 5+len(d.Data))
	b[0] = TypeMSCHAPv2
	b[1] = byte(d.OpCode)
	b[2] = byte(d.Id)
	binary.BigEndian.PutUint16(b[3:], uint16(4+len(d.Data)))
	copy(b[5:], d.Data)
	return b, nil
}

func (d *MSCHAPv2) DecodeData() (interface{}, error) {
	if len(d.Data) == 0 {
		return nil, nil
	}

	var v encoding.BinaryUnmarshaler

	switch op := d.OpCode; op {
	case MSCHAPv2OpCodeResponse:
		v = &MSCHAPv2Response{}
	default:
		return nil, UnsupportedMSCHAPv2OpCodeError{op}
	}

	if err := v.UnmarshalBinary(d.Data); err != nil {
		return nil, err
	}

	return v, nil
}

type MSCHAPv2Challenge struct {
	Challenge []byte
	Name      []byte
}

func NewMSCHAPv2Challenge(name string) (*MSCHAPv2Challenge, error) {
	ret := &MSCHAPv2Challenge{
		Challenge: make([]byte, 16),
		Name:      []byte(name),
	}
	if _, err := rand.Read(ret.Challenge); err != nil {
		return nil, err
	}
	return ret, nil
}

func (d *MSCHAPv2Challenge) MarshalBinary() ([]byte, error) {
	if len(d.Challenge) != 16 {
		return nil, fmt.Errorf("challenge must be 16 bytes")
	}
	b := make([]byte, 1+len(d.Challenge)+len(d.Name))
	b[0] = 16
	copy(b[1:], d.Challenge)
	copy(b[1+len(d.Challenge):], d.Name)
	return b, nil
}

type MSCHAPv2Response struct {
	PeerChallenge []byte
	NTResponse    []byte
	Name          []byte
}

func (d *MSCHAPv2Response) GenerateNTResponse(password string, authenticatorChallenge []byte) []byte {
	return mschapv2.GenerateNTResponse(authenticatorChallenge, d.PeerChallenge, d.Name, password)
}

func (d *MSCHAPv2Response) Verify(password string, authenticatorChallenge []byte) bool {
	return subtle.ConstantTimeCompare(d.NTResponse, d.GenerateNTResponse(password, authenticatorChallenge)) == 1
}

func (d *MSCHAPv2Response) GenerateAuthenticatorResponse(password string, authenticatorChallenge []byte) string {
	return mschapv2.GenerateAuthenticatorResponse(password, d.NTResponse, d.PeerChallenge, authenticatorChallenge, d.Name)
}

func (d *MSCHAPv2Response) UnmarshalBinary(b []byte) error {
	if len(b) < 50 {
		return fmt.Errorf("buffer too short")
	} else if b[0] != 49 {
		return fmt.Errorf("wrong value size")
	}
	response := b[1:50]
	for _, zero := range response[16:24] {
		if zero != 0 {
			return fmt.Errorf("non-zero reserved byte")
		}
	}
	d.PeerChallenge = append([]byte(nil), response[:16]...)
	d.NTResponse = append([]byte(nil), response[24:48]...)
	if response[48] != 0 {
		return fmt.Errorf("non-zero flags")
	}
	d.Name = append([]byte(nil), b[50:]...)
	return nil
}

type MSCHAPv2SuccessRequest struct {
	AuthenticatorResponse string
}

func (d *MSCHAPv2SuccessRequest) MarshalBinary() ([]byte, error) {
	return []byte(d.AuthenticatorResponse), nil
}
