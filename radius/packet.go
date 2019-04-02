package radius

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"fmt"

	"github.com/theaaf/radius-server/eap"
)

type Packet struct {
	Code          int
	Identifier    int
	Authenticator []byte
	Attributes    []*Attribute
}

var ErrInvalidAttributeLength = fmt.Errorf("invalid attribute length")

// UnmarshalBinary decodes a packet. Note that it may partially unmarshal a packet and return
// ErrInvalidAttributeLength, and the caller should handle that case according to RFC-2865, section
// 5:
//
// "If an Attribute is received in an Access-Request but with an invalid Length, an Access-Reject
// SHOULD be transmitted.  If an Attribute is received in an Access-Accept, Access-Reject or
// Access-Challenge packet with an invalid length, the packet MUST either be treated as an
// Access-Reject or else silently discarded."
func (p *Packet) UnmarshalBinary(b []byte) error {
	if len(b) < 20 {
		return fmt.Errorf("buffer too short (%d bytes)", len(b))
	}
	length := int(binary.BigEndian.Uint16(b[2:]))
	if length < 20 || length > 4096 {
		return fmt.Errorf("packet length (%d bytes) outside valid range (20-4096)", length)
	} else if len(b) < length {
		return fmt.Errorf("buffer too short (%d bytes) for packet length (%d bytes)", len(b), length)
	}

	b = append([]byte(nil), b...)

	p.Code = int(b[0])
	p.Identifier = int(b[1])
	p.Authenticator = b[4:20]
	b = b[20:length]
	for len(b) > 0 {
		if len(b) < 2 {
			return ErrInvalidAttributeLength
		}
		length := int(b[1])
		if len(b) < length {
			return ErrInvalidAttributeLength
		}
		a := &Attribute{
			Type:  int(b[0]),
			Value: b[2:length],
		}
		p.Attributes = append(p.Attributes, a)
		b = b[length:]
	}
	return nil
}

// EAPPacket decodes an EAP packet from the EAP-Message attributes of the RADIUS packet or returns nil.
func (p *Packet) EAPPacket() (*eap.Packet, error) {
	// RFC-3579, section 3.1: Where more than one EAP-Message attribute is included, it is assumed
	// that the attributes are to be concatenated to form a single EAP packet. Multiple EAP packets
	// MUST NOT be encoded within EAP-Message attributes contained within a single Access-Challenge,
	// Access-Accept, Access-Reject or Access-Request packet.

	var buf []byte
	isReadingMessage := false
	for _, attr := range p.Attributes {
		if attr.Type == AttributeTypeEAPMessage {
			if !isReadingMessage && buf != nil {
				return nil, fmt.Errorf("multiple eap packets found")
			}
			buf = append(buf, attr.Value...)
			isReadingMessage = true
		} else {
			isReadingMessage = false
		}
	}

	if buf == nil {
		return nil, nil
	}

	var ret eap.Packet
	if err := ret.UnmarshalBinary(buf); err != nil {
		return nil, err
	}
	return &ret, nil
}

var messageAuthenticatorPlaceholder = MustAttribute(NewStringAttribute(AttributeTypeMessageAuthenticator, make([]byte, 16)))

// CalculateMessageAuthenticator calculates the message authenticator for a packet. If the packet
// contains no Message-Authenticator attributes, nil is returned.
func (p *Packet) CalculateMessageAuthenticator(secret []byte) ([]byte, error) {
	var pCopy *Packet
	for i, attr := range p.Attributes {
		if attr.Type == AttributeTypeMessageAuthenticator {
			if pCopy == nil {
				pCopy = new(Packet)
				*pCopy = *p
				pCopy.Attributes = append([]*Attribute(nil), pCopy.Attributes...)
			}
			pCopy.Attributes[i] = messageAuthenticatorPlaceholder
		}
	}
	if pCopy == nil {
		return nil, nil
	}
	b, err := pCopy.MarshalBinary()
	if err != nil {
		return nil, err
	}
	mac := hmac.New(md5.New, secret)
	mac.Write(b)
	return mac.Sum(nil), nil
}

func (p *Packet) HasAttributeType(attributeType int) bool {
	for _, attr := range p.Attributes {
		if attr.Type == attributeType {
			return true
		}
	}
	return false
}

// VerifyMessageAuthenticator verifies Message-Authenticator attributes if present.
func (p *Packet) VerifyMessageAuthenticator(secret []byte) error {
	ma, err := p.CalculateMessageAuthenticator(secret)
	if err != nil {
		return err
	} else if ma == nil {
		return nil
	}
	for _, attr := range p.Attributes {
		if attr.Type == AttributeTypeMessageAuthenticator && !hmac.Equal(attr.Value, ma) {
			return fmt.Errorf("bad message authenticator")
		}
	}
	return nil
}

func (p *Packet) MarshalBinary() ([]byte, error) {
	l := 20
	for _, attr := range p.Attributes {
		l += 2 + len(attr.Value)
	}
	if l > 4096 {
		return nil, fmt.Errorf("packet too large (%d bytes)", l)
	}
	buf := make([]byte, l)
	buf[0] = byte(p.Code)
	buf[1] = byte(p.Identifier)
	binary.BigEndian.PutUint16(buf[2:], uint16(l))
	copy(buf[4:], p.Authenticator)
	attrBuf := buf[20:]
	for _, attr := range p.Attributes {
		attrBuf[0] = byte(attr.Type)
		attrBuf[1] = byte(2 + len(attr.Value))
		copy(attrBuf[2:], attr.Value)
		attrBuf = attrBuf[2+len(attr.Value):]
	}
	return buf, nil
}

func (p *Packet) SetMessageAuthenticator(requestAuthenticator, secret []byte) error {
	p.Authenticator = requestAuthenticator
	if !p.HasAttributeType(AttributeTypeMessageAuthenticator) {
		p.Attributes = append(p.Attributes, MustAttribute(NewStringAttribute(AttributeTypeMessageAuthenticator, make([]byte, 16))))
	} else {
		for i, attr := range p.Attributes {
			if attr.Type == AttributeTypeMessageAuthenticator {
				p.Attributes[i] = messageAuthenticatorPlaceholder
			}
		}
	}
	ma, err := p.CalculateMessageAuthenticator(secret)
	if err != nil {
		return err
	}
	for i, attr := range p.Attributes {
		if attr.Type == AttributeTypeMessageAuthenticator {
			p.Attributes[i] = MustAttribute(NewStringAttribute(AttributeTypeMessageAuthenticator, ma))
		}
	}
	return nil
}

func (p *Packet) SetResponseAuthenticator(requestAuthenticator, secret []byte) error {
	p.Authenticator = requestAuthenticator

	b, err := p.MarshalBinary()
	if err != nil {
		return err
	}

	h := md5.New()
	h.Write(b)
	h.Write(secret)

	p.Authenticator = h.Sum(nil)
	return nil
}
