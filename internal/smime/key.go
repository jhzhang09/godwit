// Package smime 处理 S/MIME 收发；硬件私钥和系统信任通过各操作系统原生安全接口在进程内直接完成。
package smime

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/emmansun/gmsm/smx509"
)

type key struct {
	ctx  context.Context
	cert *smx509.Certificate
}

func (k key) Public() crypto.PublicKey { return k.cert.PublicKey }

func (k key) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	hash := opts.HashFunc()
	switch hash {
	case crypto.SHA1, crypto.SHA256:
	default:
		return nil, errors.New("不支持的硬件签名摘要")
	}
	var sig []byte
	err := withProvider(k.ctx, func(p provider) error {
		var err error
		sig, err = p.Sign(k.ctx, k.cert.Raw, hash, digest)
		return err
	})
	return sig, err
}

func (k key) Decrypt(_ io.Reader, data []byte, _ crypto.DecrypterOpts) ([]byte, error) {
	var plain []byte
	err := withProvider(k.ctx, func(p provider) error {
		var err error
		plain, err = p.Decrypt(k.ctx, k.cert.Raw, data)
		return err
	})
	return plain, err
}

func digestAlgorithm(ctx context.Context, certDER []byte) (crypto.Hash, error) {
	var hash crypto.Hash
	err := withProvider(ctx, func(p provider) error {
		var err error
		hash, err = p.DigestAlgorithm(ctx, certDER)
		return err
	})
	return hash, err
}

func verifyCMS(ctx context.Context, email string, der, detached []byte) ([]byte, error) {
	var content []byte
	err := withVerifyProvider(ctx, func(p provider) error {
		var err error
		content, err = p.VerifyCMS(ctx, email, der, detached)
		return err
	})
	return content, err
}

func identities(ctx context.Context) ([]*smx509.Certificate, error) {
	var ders [][]byte
	if err := withProvider(ctx, func(p provider) error {
		var err error
		ders, err = p.Identities(ctx)
		return err
	}); err != nil {
		return nil, err
	}
	var certs []*smx509.Certificate
	for _, der := range ders {
		cert, err := ParseCertificate(der)
		if err != nil {
			continue
		}
		if _, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			certs = append(certs, cert)
		}
	}
	return certs, nil
}

// MatchesMailbox 同时识别 subjectAltName 和早期证书主题中的 emailAddress。
func MatchesMailbox(cert *smx509.Certificate, email string) bool {
	for _, addr := range cert.EmailAddresses {
		if strings.EqualFold(addr, email) {
			return true
		}
	}
	for _, attr := range cert.Subject.Names {
		if attr.Type.String() == "1.2.840.113549.1.9.1" {
			if addr, ok := attr.Value.(string); ok && strings.EqualFold(addr, email) {
				return true
			}
		}
	}
	return false
}

func trust(ctx context.Context, usage, email string, cert *smx509.Certificate, chain []*smx509.Certificate) error {
	if !MatchesMailbox(cert, email) {
		return fmt.Errorf("证书邮箱与 %s 不匹配", email)
	}
	ders := [][]byte{cert.Raw}
	for _, c := range chain {
		if !bytes.Equal(c.Raw, cert.Raw) {
			ders = append(ders, c.Raw)
		}
	}
	return withVerifyProvider(ctx, func(p provider) error {
		return p.VerifyTrust(ctx, usage, email, ders)
	})
}

func ownCertificate(ctx context.Context, email, usage string) (*smx509.Certificate, error) {
	certs, err := identities(ctx)
	if err != nil {
		return nil, err
	}
	var selected *smx509.Certificate
	var lastErr error
	for _, cert := range certs {
		if !MatchesMailbox(cert, email) {
			continue
		}
		if err := trust(ctx, usage, email, cert, nil); err != nil {
			lastErr = err
			continue
		}
		if selected != nil && !bytes.Equal(selected.Raw, cert.Raw) {
			return nil, fmt.Errorf("%s 有多个匹配的硬件证书，请只连接所需的 Key", email)
		}
		selected = cert
	}
	if selected == nil {
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, fmt.Errorf("没有找到 %s 的硬件证书，请插入对应的 Key", email)
	}
	return selected, nil
}
