package smime

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
)

// Session 与桌面界面同寿命；切换邮件不会销毁智能卡的系统授权。
type Session struct {
	lifetime context.Context
	gate     chan struct{}
	prov     provider
	closing  bool
}

type sessionKey struct{}

func NewSession(lifetime context.Context) *Session {
	s := &Session{lifetime: lifetime, gate: make(chan struct{}, 1)}
	go func() {
		<-lifetime.Done()
		s.gate <- struct{}{}
		s.closing = true
		if s.prov != nil {
			_ = s.prov.Close()
			s.prov = nil
		}
		<-s.gate
	}()
	return s
}

func (s *Session) do(ctx context.Context, fn func(provider) error) error {
	select {
	case s.gate <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	case <-s.lifetime.Done():
		return s.lifetime.Err()
	}
	defer func() { <-s.gate }()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.lifetime.Err(); err != nil || s.closing {
		if s.lifetime.Err() != nil {
			return s.lifetime.Err()
		}
		return context.Canceled
	}
	if s.prov == nil {
		s.prov = newPlatformProvider(true)
	}
	if err := fn(s.prov); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	return ctx.Err()
}

func (s *Session) Open(ctx context.Context, raw []byte) (Opened, error) {
	return Open(context.WithValue(ctx, sessionKey{}, s), raw)
}

func (s *Session) OpenCMS(ctx context.Context, fromHeader string, der []byte) (Opened, error) {
	return OpenCMS(context.WithValue(ctx, sessionKey{}, s), fromHeader, der)
}

// OpenForRead decrypts and unwraps raw for display in the reader; signature/trust failures
// populate Opened.VerifyErr instead of discarding decrypted content.
func (s *Session) OpenForRead(ctx context.Context, raw []byte) (Opened, error) {
	return OpenForRead(context.WithValue(ctx, sessionKey{}, s), raw)
}

// OpenCMSForRead unwraps and decrypts a single application/pkcs7-mime part for display in the reader;
// signature/trust failures populate Opened.VerifyErr instead of discarding decrypted content.
func (s *Session) OpenCMSForRead(ctx context.Context, fromHeader string, der []byte) (Opened, error) {
	return OpenCMSForRead(context.WithValue(ctx, sessionKey{}, s), fromHeader, der)
}

// Prepare 仅对已配置邮箱的卡做一次随机挑战，触发系统自己的 PIN 窗口。
func (s *Session) Prepare(emails []string) error {
	ctx := context.WithValue(s.lifetime, sessionKey{}, s)
	certs, err := identities(ctx)
	if err != nil {
		return err
	}
	for _, cert := range certs {
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			continue
		}
		for _, email := range emails {
			if !MatchesMailbox(cert, email) {
				continue
			}
			challenge := make([]byte, 32)
			if _, err = rand.Read(challenge); err != nil {
				return err
			}
			sealed, err := rsa.EncryptPKCS1v15(rand.Reader, pub, challenge)
			if err != nil {
				return err
			}
			if err := s.do(ctx, func(p provider) error {
				return p.Prepare(ctx, cert.Raw, sealed)
			}); err != nil {
				return err
			}
			break
		}
	}
	return nil
}

// Retry 仅在用户主动重试后才允许再次请求已取消的 PIN 授权。
func (s *Session) Retry(ctx context.Context) error {
	return s.do(ctx, func(p provider) error {
		return p.Retry(ctx)
	})
}
