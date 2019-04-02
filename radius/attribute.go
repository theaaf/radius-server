package radius

import (
	"encoding/binary"
	"fmt"
	"net"
)

type Attribute struct {
	Type  int
	Value []byte
}

func MustAttribute(a *Attribute, err error) *Attribute {
	if err != nil {
		panic(err)
	}
	return a
}

// StringAttribute returns an attribute whose value is a "string" as defined by RFC-2865. This is used
// for binary data, not UTF-8 strings. UTF-8 strings are encoded as "text" values.
func NewStringAttribute(attributeType int, value []byte) (*Attribute, error) {
	if len(value) == 0 || len(value) > 253 {
		return nil, fmt.Errorf("invalid length for string attribute")
	}
	return &Attribute{
		Type:  attributeType,
		Value: value,
	}, nil
}

func NewAddressAttribute(attributeType int, value net.IP) (*Attribute, error) {
	ipv4 := value.To4()
	if ipv4 == nil {
		return nil, fmt.Errorf("invalid address")
	}
	return &Attribute{
		Type:  attributeType,
		Value: ipv4,
	}, nil
}

func NewIntAttribute(attributeType int, value uint32) (*Attribute, error) {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, value)
	return &Attribute{
		Type:  attributeType,
		Value: b,
	}, nil
}

func (a *Attribute) MarshalBinary() ([]byte, error) {
	b := make([]byte, 1+len(a.Value))
	b[0] = byte(a.Type)
	return b, nil
}

type VendorData struct {
	Type int
	Data []byte
}

func NewVendorAttribute(vendorId int, data []*VendorData) (*Attribute, error) {
	size := 4
	for _, d := range data {
		size += 2 + len(d.Data)
	}
	v := make([]byte, size)
	binary.BigEndian.PutUint32(v, uint32(vendorId))
	dest := v[4:]
	for _, d := range data {
		dest[0] = uint8(d.Type)
		dest[1] = uint8(2 + len(d.Data))
		copy(dest[2:], d.Data)
		dest = dest[2+len(d.Data):]
	}
	return &Attribute{
		Type:  AttributeTypeVendorSpecific,
		Value: v,
	}, nil
}
