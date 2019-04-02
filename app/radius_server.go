package app

import (
	"net"
	"runtime/debug"
	"sync"

	"github.com/sirupsen/logrus"
)

type RADIUSServer struct {
	Logger logrus.FieldLogger

	SharedSecret       []byte
	CredentialProvider EAPCredentialProvider

	authPacketConn net.PacketConn
	authServeDone  chan struct{}
	authenticator  *EAPAuthenticator
}

func (s *RADIUSServer) Start() error {
	s.Stop()

	log := s.Logger
	if log == nil {
		log = logrus.StandardLogger()
	}

	listenAddr := ":1812"
	log = log.WithField("radius_server", listenAddr)

	pc, err := net.ListenPacket("udp", listenAddr)
	if err != nil {
		return err
	}
	log.Infof("radius server listening")

	s.authPacketConn = pc
	s.authServeDone = make(chan struct{})
	s.authenticator = &EAPAuthenticator{
		SharedSecret:       s.SharedSecret,
		CredentialProvider: s.CredentialProvider,
		Send: func(b []byte, addr net.Addr) error {
			_, err := pc.WriteTo(b, addr)
			return err
		},
	}

	go s.serveAuth(pc, log)
	return nil
}

func (s *RADIUSServer) Stop() {
	if s.authPacketConn != nil {
		s.authPacketConn.Close()
		<-s.authServeDone
		s.authPacketConn = nil
	}
}

func (s *RADIUSServer) serveAuth(pc net.PacketConn, log logrus.FieldLogger) {
	defer close(s.authServeDone)

	var wg sync.WaitGroup
	wg.Add(1)

	for {
		// The maximum RADIUS packet size is 4096, but padding is allowed, so double that to be safe.
		buf := make([]byte, 4096*2)

		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Temporary() {
				log.Warn("temporary auth listener error:", err.Error())
				continue
			}
			log.Error("auth listener error:", err.Error())
			break
		}

		wg.Add(1)
		go func() {
			defer func() {
				if v := recover(); v != nil {
					log.Error("recovered from panic in auth handler:", v, string(debug.Stack()))
				}
				wg.Done()
			}()
			log := log.WithFields(logrus.Fields{
				"addr": addr,
			})
			s.handleAuth(buf[:n], addr, pc, log)
		}()
	}

	wg.Done()
	wg.Wait()
}

func (s *RADIUSServer) handleAuth(b []byte, addr net.Addr, pc net.PacketConn, log logrus.FieldLogger) {
	result, err := s.authenticator.Handle(b, addr)
	if err != nil {
		log.Error(err.Error())
		return
	}

	switch r := result.(type) {
	case *EAPAuthenticatorDiscardResult:
		log.WithField("reason", r.Reason).Info("packet discarded")
	case *EAPAuthenticatorRejectResult:
		log.WithField("reason", r.Reason).Info("packet rejected")
	case *EAPAuthenticatorEAPFailureResult:
		log.WithField("identity", r.Identity).WithField("reason", r.Reason).Info("eap failure")
	case *EAPAuthenticatorEAPRequestResult:
		log.WithField("identity", r.Identity).Info("eap request sent")
	case *EAPAuthenticatorEAPSuccessResult:
		log.WithField("identity", r.Identity).Info("eap success")
	default:
		log.WithField("result", r).Warnf("unknown result type: %T", r)
	}
}
