package smime

import (
	"context"
	"crypto"
)

// Supported 报告当前操作系统是否提供原生的硬件 Key S/MIME 能力。
func Supported() bool {
	return platformSupported()
}

type providerKey struct{}

type provider interface {
	Identities(ctx context.Context) ([][]byte, error)
	Prepare(ctx context.Context, certDER, sealed []byte) error
	DigestAlgorithm(ctx context.Context, certDER []byte) (crypto.Hash, error)
	Sign(ctx context.Context, certDER []byte, hash crypto.Hash, digest []byte) ([]byte, error)
	Decrypt(ctx context.Context, certDER, ciphertext []byte) ([]byte, error)
	VerifyTrust(ctx context.Context, usage, email string, certsDER [][]byte) error
	VerifyCMS(ctx context.Context, email string, cmsDER, detached []byte) ([]byte, error)
	Retry(ctx context.Context) error
	Close() error
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
