package app

import (
	"crypto/rand"
	"encoding"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/pkg/errors"

	"github.com/theaaf/radius-server/eap"
	"github.com/theaaf/radius-server/eap/mschapv2"
	"github.com/theaaf/radius-server/radius"
)

type EAPCredentials interface {
	PlaintextPassword() []byte
}

type EAPCredentialProvider interface {
	CredentialsForIdentity(id string) (EAPCredentials, error)
}

// EAPAuthenticator implements a RADIUS server with minimal support for EAP authentication.
//
// EAPAuthenticator is safe for concurrent use.
type EAPAuthenticator struct {
	SharedSecret       []byte
	Send               func(b []byte, addr net.Addr) error
	CredentialProvider EAPCredentialProvider

	mutex sync.Mutex
	state map[string]*EAPConnectionState
}

type EAPConnectionState struct {
	CreationTime            time.Time
	Identity                string
	MD5ChallengeValue       []byte
	CompletedAuthentication bool

	MSCHAPv2ChallengeValues [][]byte
	MSCHAPv2SuccessSent     bool
	MSCHAPv2NTResponse      []byte

	mutex sync.Mutex
}

type EAPAuthenticatorEAPRequestResult struct {
	Identity string
}

func (auth *EAPAuthenticator) eapRequest(p *eap.Packet, data encoding.BinaryMarshaler) (*eap.Packet, []*radius.Attribute, *EAPAuthenticatorEAPRequestResult, error) {
	result := &EAPAuthenticatorEAPRequestResult{}
	dataBuf, err := data.MarshalBinary()
	if err != nil {
		return nil, nil, result, err
	}
	req := &eap.Packet{
		Code:       eap.CodeRequest,
		Identifier: p.Identifier + 1,
		Data:       dataBuf,
	}
	return req, nil, result, nil
}

type EAPAuthenticatorEAPFailureResult struct {
	Identity string
	Reason   error
}

func (auth *EAPAuthenticator) sendEAPPacket(rp *radius.Packet, ep *eap.Packet, attrs []*radius.Attribute, stateKey []byte, addr net.Addr, result interface{}) (interface{}, error) {
	eapBuf, err := ep.MarshalBinary()
	if err != nil {
		return result, err
	}
	resp := &radius.Packet{
		Identifier: rp.Identifier,
		Attributes: []*radius.Attribute{
			radius.MustAttribute(radius.NewStringAttribute(radius.AttributeTypeEAPMessage, eapBuf)),
			radius.MustAttribute(radius.NewStringAttribute(radius.AttributeTypeState, stateKey)),
		},
	}
	resp.Attributes = append(resp.Attributes, attrs...)
	if ep.Code == eap.CodeFailure {
		resp.Code = radius.CodeAccessReject
	} else if ep.Code == eap.CodeSuccess {
		resp.Code = radius.CodeAccessAccept
	} else {
		resp.Code = radius.CodeAccessChallenge
	}
	resp.SetMessageAuthenticator(rp.Authenticator, auth.SharedSecret)
	resp.SetResponseAuthenticator(rp.Authenticator, auth.SharedSecret)
	b, err := resp.MarshalBinary()
	if err != nil {
		return result, err
	}
	return result, auth.Send(b, addr)
}

func (auth *EAPAuthenticator) eapFailure(p *eap.Packet, reason error) (*eap.Packet, []*radius.Attribute, *EAPAuthenticatorEAPFailureResult, error) {
	return &eap.Packet{
			Code:       eap.CodeFailure,
			Identifier: p.Identifier,
		}, nil, &EAPAuthenticatorEAPFailureResult{
			Reason: reason,
		}, nil
}

type EAPAuthenticatorEAPSuccessResult struct {
	Identity string
}

func (auth *EAPAuthenticator) eapSuccess(p *eap.Packet) (*eap.Packet, []*radius.Attribute, *EAPAuthenticatorEAPSuccessResult, error) {
	return &eap.Packet{
		Code:       eap.CodeSuccess,
		Identifier: p.Identifier,
	}, nil, &EAPAuthenticatorEAPSuccessResult{}, nil
}

type EAPAuthenticatorRejectResult struct {
	Reason error
}

func (auth *EAPAuthenticator) reject(p *radius.Packet, addr net.Addr, reason error) (*EAPAuthenticatorRejectResult, error) {
	result := &EAPAuthenticatorRejectResult{
		Reason: reason,
	}
	resp := &radius.Packet{
		Code:       radius.CodeAccessReject,
		Identifier: p.Identifier,
	}
	resp.SetResponseAuthenticator(p.Authenticator, auth.SharedSecret)
	b, err := resp.MarshalBinary()
	if err != nil {
		return result, err
	}
	return result, auth.Send(b, addr)
}

type EAPAuthenticatorDiscardResult struct {
	Reason error
}

func (auth *EAPAuthenticator) discard(reason error) (*EAPAuthenticatorDiscardResult, error) {
	return &EAPAuthenticatorDiscardResult{
		Reason: reason,
	}, nil
}

func (auth *EAPAuthenticator) purgeConnectionStates() {
	cutoff := time.Now().Add(-time.Minute)
	for k, v := range auth.state {
		if v.CreationTime.Before(cutoff) {
			delete(auth.state, k)
		}
	}
}

// Handles a RADIUS packet. Errors are returned for internal issues such as the authenticator's Send
// function returning an error. Under normal operation, even in cases such as malformed packets, a
// non-nil result and nil error are returned.
func (auth *EAPAuthenticator) Handle(b []byte, addr net.Addr) (interface{}, error) {
	p := &radius.Packet{}
	err := p.UnmarshalBinary(b)

	if err := p.VerifyMessageAuthenticator(auth.SharedSecret); err != nil {
		// RFC-3579, section 3.2: A RADIUS server receiving an Access-Request with a
		// Message-Authenticator attribute present MUST calculate the correct value of the
		// Message-Authenticator and silently discard the packet if it does not match the value
		// sent.
		return auth.discard(errors.Wrap(err, "unable to verify message authenticator"))
	}

	if err != nil {
		if err == radius.ErrInvalidAttributeLength && p.Code == radius.CodeAccessRequest {
			// RFC-2865, section 5: If an Attribute is received in an Access-Request but with an
			// invalid Length, an Access-Reject SHOULD be transmitted.
			return auth.reject(p, addr, err)
		}
		return auth.discard(err)
	}

	if p.Code != radius.CodeAccessRequest {
		return auth.discard(fmt.Errorf("unsupported code: %d", p.Code))
	}

	eapPacket, err := p.EAPPacket()
	if err != nil {
		return auth.reject(p, addr, err)
	} else if eapPacket == nil {
		// This is strictly an EAP authenticator. Reject requests without EAP packets.
		return auth.reject(p, addr, fmt.Errorf("no eap packet present"))
	}

	if !p.HasAttributeType(radius.AttributeTypeMessageAuthenticator) {
		// RFC-3579, section 3.1: Access-Request packets including EAP-Message attribute(s) without
		// a Message-Authenticator attribute SHOULD be silently discarded by the RADIUS server.
		return auth.discard(fmt.Errorf("no message authenticator present"))
	}

	var stateKey []byte
	for _, attr := range p.Attributes {
		if attr.Type == radius.AttributeTypeState {
			if stateKey != nil {
				return auth.discard(fmt.Errorf("multiple state attributes"))
			}
			stateKey = attr.Value
		}
	}

	var state *EAPConnectionState

	if stateKey == nil {
		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err != nil {
			return auth.discard(err)
		}
		stateKey = buf
		state = &EAPConnectionState{
			CreationTime: time.Now(),
		}
		auth.mutex.Lock()
		if auth.state == nil {
			auth.state = make(map[string]*EAPConnectionState)
		}
		auth.purgeConnectionStates()
		auth.state[string(stateKey)] = state
		auth.mutex.Unlock()
	} else {
		auth.mutex.Lock()
		auth.purgeConnectionStates()
		state = auth.state[string(stateKey)]
		auth.mutex.Unlock()
	}

	if state == nil {
		return auth.discard(fmt.Errorf("invalid state"))
	}

	state.mutex.Lock()
	defer state.mutex.Unlock()

	if state.CompletedAuthentication {
		return auth.discard(fmt.Errorf("authentication already completed"))
	}

	eapOut, attrs, eapResult, eapErr := auth.handleEAP(p, eapPacket, state)
	switch r := eapResult.(type) {
	case *EAPAuthenticatorEAPRequestResult:
		r.Identity = state.Identity
	case *EAPAuthenticatorEAPSuccessResult:
		r.Identity = state.Identity
	case *EAPAuthenticatorEAPFailureResult:
		r.Identity = state.Identity
	}
	if eapErr != nil {
		return eapResult, eapErr
	}

	if eapOut.Code == eap.CodeSuccess || eapOut.Code == eap.CodeFailure {
		state.CompletedAuthentication = true
	}

	return auth.sendEAPPacket(p, eapOut, attrs, stateKey, addr, eapResult)
}

func (auth *EAPAuthenticator) handleEAP(rp *radius.Packet, p *eap.Packet, state *EAPConnectionState) (*eap.Packet, []*radius.Attribute, interface{}, error) {
	if p.Code != eap.CodeResponse {
		return auth.eapFailure(p, fmt.Errorf("unsupported eap message code: %d", p.Code))
	}

	data, err := p.DecodeData()
	if err != nil {
		return auth.eapFailure(p, err)
	}

	var credentials EAPCredentials

	if identity, ok := data.(*eap.Identity); ok {
		if state.Identity == "" {
			credentials, err = auth.CredentialProvider.CredentialsForIdentity(identity.Identity)
			if err != nil {
				return auth.eapFailure(p, errors.Wrapf(err, "unable to get credentials"))
			} else if credentials == nil {
				return auth.eapFailure(p, fmt.Errorf("invalid identity: %s", identity.Identity))
			}
			v := make([]byte, 16)
			if _, err := rand.Read(v); err != nil {
				return auth.eapFailure(p, err)
			}
			state.Identity = identity.Identity
			state.MD5ChallengeValue = v
		} else if identity.Identity != state.Identity {
			return auth.eapFailure(p, fmt.Errorf("already received identity"))
		}

		return auth.eapRequest(p, &eap.MD5Challenge{
			Value: state.MD5ChallengeValue,
		})
	} else if state.Identity == "" {
		return auth.eapFailure(p, fmt.Errorf("expected identity"))
	} else {
		credentials, err = auth.CredentialProvider.CredentialsForIdentity(state.Identity)
		if err != nil {
			return auth.eapFailure(p, errors.Wrapf(err, "unable to get credentials"))
		} else if credentials == nil {
			return auth.eapFailure(p, fmt.Errorf("identity no longer valid"))
		}
	}

	switch v := data.(type) {
	case *eap.MD5Challenge:
		if !v.Verify(p.Identifier, credentials.PlaintextPassword(), state.MD5ChallengeValue) {
			return auth.eapFailure(p, fmt.Errorf("bad md5 challenge value"))
		}
		return auth.eapSuccess(p)
	case *eap.MSCHAPv2:
		password := string(credentials.PlaintextPassword())
		if v.OpCode == eap.MSCHAPv2OpCodeSuccess {
			if state.MSCHAPv2SuccessSent {
				p, attrs, result, err := auth.eapSuccess(p)
				send, recv := mschapv2.MPPEv2(auth.SharedSecret, password, rp.Authenticator, state.MSCHAPv2NTResponse)
				attrs = append(attrs,
					radius.MustAttribute(radius.NewVendorAttribute(311, []*radius.VendorData{
						&radius.VendorData{
							Type: 16, // send key
							Data: send,
						},
					})),
					radius.MustAttribute(radius.NewVendorAttribute(311, []*radius.VendorData{
						&radius.VendorData{
							Type: 17, // recv key
							Data: recv,
						},
					})),
				)
				return p, attrs, result, err
			}
			return auth.eapFailure(p, fmt.Errorf("success response for unauthenticated connection"))
		}
		mschap, err := v.DecodeData()
		if err != nil {
			return auth.eapFailure(p, errors.Wrapf(err, "unable to decode mschapv2 data"))
		}
		switch v2 := mschap.(type) {
		case *eap.MSCHAPv2Response:
			// If anything goes wrong, take the easy way out with an EAP failure:
			//
			// draft-kamath-pppext-eap-mschapv2-02, section 2.2: If the values do not match, and
			// the error is not retryable, then a Failure-Request packet (described in Section
			// 2.5) SHOULD be sent, or alternatively, the authentication MAY be  terminated (as
			// described in Section 2.8) such as by sending an EAP Failure.
			if v.Id >= len(state.MSCHAPv2ChallengeValues) {
				return auth.eapFailure(p, fmt.Errorf("invalid mschapv2 id"))
			} else if name := string(v2.Name); name != state.Identity {
				return auth.eapFailure(p, fmt.Errorf("unexpected mschapv2 name: %v", name))
			} else if authenticatorChallenge := state.MSCHAPv2ChallengeValues[v.Id]; !v2.Verify(password, authenticatorChallenge) {
				return auth.eapFailure(p, fmt.Errorf("bad mschapv2 challenge value"))
			} else {
				state.MSCHAPv2SuccessSent = true
				state.MSCHAPv2NTResponse = v2.GenerateNTResponse(password, authenticatorChallenge)
				response, err := eap.NewMSCHAPv2(0, &eap.MSCHAPv2SuccessRequest{
					AuthenticatorResponse: v2.GenerateAuthenticatorResponse(password, authenticatorChallenge),
				})
				if err != nil {
					return auth.eapFailure(p, errors.Wrapf(err, "unable to create mschapv2 packet"))
				}
				return auth.eapRequest(p, response)
			}
		}
		return auth.eapFailure(p, fmt.Errorf("unexpected mschapv2 type: %T", mschap))
	case *eap.Nak:
		for _, authType := range v.DesiredAuthenticationTypes {
			if authType == eap.TypeMSCHAPv2 {
				if len(state.MSCHAPv2ChallengeValues) >= 3 {
					return auth.eapFailure(p, fmt.Errorf("too many naks already received"))
				}
				challenge, err := eap.NewMSCHAPv2Challenge("intranet")
				if err != nil {
					return auth.eapFailure(p, errors.Wrapf(err, "unable to generate new mschapv2 challenge"))
				}
				state.MSCHAPv2ChallengeValues = append(state.MSCHAPv2ChallengeValues, challenge.Challenge)
				response, err := eap.NewMSCHAPv2(len(state.MSCHAPv2ChallengeValues)-1, challenge)
				if err != nil {
					return auth.eapFailure(p, errors.Wrapf(err, "unable to create mschapv2 packet"))
				}
				return auth.eapRequest(p, response)
			}
		}
		return auth.eapFailure(p, fmt.Errorf("received nak with no supported authentication types: %v", v.DesiredAuthenticationTypes))
	}

	return auth.eapFailure(p, fmt.Errorf("unexpected eap type: %T", data))
}
