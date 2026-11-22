package smime

import (
	"context"
	"crypto"

	"github.com/emmansun/gmsm/smx509"
)

// Supported 报告当前操作系统是否提供原生的 S/MIME 证书与密钥能力。
func Supported() bool {
	return platformSupported()
}

type providerKey struct{}

type allowWeakKeySizeKey struct{}

// WithAllowWeakKeySize returns a context controlling whether legacy weak key-size
// compatibility (such as 1024-bit RSA) is enabled for OS trust evaluation.
func WithAllowWeakKeySize(ctx context.Context, allow bool) context.Context {
	return context.WithValue(ctx, allowWeakKeySizeKey{}, allow)
}

// AllowWeakKeySize reports whether legacy weak key-size compatibility is enabled on ctx.
func AllowWeakKeySize(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	v, _ := ctx.Value(allowWeakKeySizeKey{}).(bool)
	return v
}

// RawIdentity describes one personal identity (cert DER + private key) in the OS store.
type RawIdentity struct {
	DER      []byte
	Hardware bool
}

type cmsVerifyResult struct {
	content   []byte
	signerDER []byte
	chainDER  [][]byte
	cryptOK   bool
	trustOK   bool
	verifyErr error
}

type chainVerifier interface {
	VerifyTrustWithChain(ctx context.Context, usage, email string, certsDER [][]byte) ([][]byte, error)
}

type provider interface {
	Identities(ctx context.Context) ([]RawIdentity, error)
	FindCertificates(ctx context.Context, email string) ([][]byte, error)
	Prepare(ctx context.Context, certDER, sealed []byte) error
	DigestAlgorithm(ctx context.Context, certDER []byte) (crypto.Hash, error)
	Sign(ctx context.Context, certDER []byte, hash crypto.Hash, digest []byte) ([]byte, error)
	Decrypt(ctx context.Context, certDER, ciphertext []byte) ([]byte, error)
	VerifyTrust(ctx context.Context, usage, email string, certsDER [][]byte) error
	VerifyCMS(ctx context.Context, email string, cmsDER, detached []byte) (cmsVerifyResult, error)
	Retry(ctx context.Context) error
	Close() error
}

// FindSystemCertificates queries the OS certificate store for certificates matching email.
func FindSystemCertificates(ctx context.Context, email string) ([]*smx509.Certificate, error) {
	if !Supported() || email == "" {
		return nil, nil
	}
	var ders [][]byte
	if err := withVerifyProvider(ctx, func(p provider) error {
		var err error
		ders, err = p.FindCertificates(ctx, email)
		return err
	}); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []*smx509.Certificate
	for _, der := range ders {
		cert, err := ParseCertificate(der)
		if err != nil || !MatchesMailbox(cert, email) {
			continue
		}
		sum := CertSHA256(cert.Raw)
		if !seen[sum] {
			seen[sum] = true
			out = append(out, cert)
		}
	}
	return out, nil
}

func withProvider(ctx context.Context, fn func(provider) error) error {
	if s, ok := ctx.Value(sessionKey{}).(*Session); ok && s != nil {
		return s.do(ctx, fn)
	}
	if p, ok := ctx.Value(providerKey{}).(provider); ok && p != nil {
		return fn(p)
	}
	p := newPlatformProvider(false)
	defer p.Close()
	return fn(p)
}

// withVerifyProvider 用于纯软件的证书信任/CMS 验签路径：无需硬件锁与 Session.gate。
func withVerifyProvider(ctx context.Context, fn func(provider) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if p, ok := ctx.Value(providerKey{}).(provider); ok && p != nil {
		return fn(p)
	}
	p := newPlatformProvider(false)
	defer p.Close()
	return fn(p)
}
