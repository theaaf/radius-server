package eap

import (
	"encoding"
	"encoding/binary"
	"fmt"
)

type Packet struct {
	Code       int
	Identifier int
	Data       []byte
}

func (p *Packet) UnmarshalBinary(b []byte) error {
	if len(b) < 4 {
		return fmt.Errorf("buffer too short (%d bytes)", len(b))
	}
	length := int(binary.BigEndian.Uint16(b[2:]))
	if len(b) < length {
		return fmt.Errorf("buffer too short (%d bytes) for packet length (%d bytes)", len(b), length)
	}

	b = append([]byte(nil), b...)

	p.Code = int(b[0])
	p.Identifier = int(b[1])
	p.Data = b[4:length]
	return nil
}

func (p *Packet) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 4+len(p.Data))
	buf[0] = byte(p.Code)
	buf[1] = byte(p.Identifier)
	binary.BigEndian.PutUint16(buf[2:], uint16(4+len(p.Data)))
	copy(buf[4:], p.Data)
	return buf, nil
}

func (p *Packet) DecodeData() (interface{}, error) {
	if len(p.Data) == 0 {
		return nil, nil
	}

	var v encoding.BinaryUnmarshaler

	switch t := int(p.Data[0]); t {
	case TypeIdentity:
		v = &Identity{}
	case TypeNak:
		v = &Nak{}
	case TypeMD5Challenge:
		v = &MD5Challenge{}
	case TypeMSCHAPv2:
		v = &MSCHAPv2{}
	default:
		return nil, UnsupportedTypeError{t}
	}

	if err := v.UnmarshalBinary(p.Data); err != nil {
		return nil, err
	}

	return v, nil
}
