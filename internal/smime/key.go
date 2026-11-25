// Package smime 处理 S/MIME 收发；本地证书、安全 Key 私钥操作与系统信任通过各操作系统原生安全接口在进程内直接完成。
package smime

import (
	"bytes"
	"cmp"
	"context"
	"crypto"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

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
		return nil, errors.New("unsupported signature digest algorithm")
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

func verifyCMS(ctx context.Context, email string, der, detached []byte) (cmsVerifyResult, error) {
	var res cmsVerifyResult
	err := withVerifyProvider(ctx, func(p provider) error {
		var err error
		res, err = p.VerifyCMS(ctx, email, der, detached)
		return err
	})
	return res, err
}

// IdentityInfo describes one personal S/MIME identity available in the OS certificate store.
type IdentityInfo struct {
	SHA256        string
	Subject       string
	SubjectDN     string
	SubjectAttrs  []CertDNAttr
	Issuer        string
	IssuerDN      string
	IssuerAttrs   []CertDNAttr
	Emails        []string
	SerialNumber  string
	NotBefore     time.Time
	NotAfter      time.Time
	PublicKeyAlgo string
	SignatureAlgo string
	KeyUsages     []string
	ExtKeyUsages  []string
	SHA1          string
	Hardware      bool
	CanSign       bool
	CanEncrypt    bool
	Chain         []CertChainNode
}

type parsedIdentity struct {
	cert     *smx509.Certificate
	sha256   string
	hardware bool
}

func identities(ctx context.Context) ([]*smx509.Certificate, error) {
	items, err := parsedIdentities(ctx)
	if err != nil {
		return nil, err
	}
	certs := make([]*smx509.Certificate, len(items))
	for i, it := range items {
		certs[i] = it.cert
	}
	return certs, nil
}

func parsedIdentities(ctx context.Context) ([]parsedIdentity, error) {
	var raw []RawIdentity
	if err := withProvider(ctx, func(p provider) error {
		var err error
		raw, err = p.Identities(ctx)
		return err
	}); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []parsedIdentity
	for _, r := range raw {
		cert, err := ParseCertificate(r.DER)
		if err != nil {
			continue
		}
		if _, ok := cert.PublicKey.(*rsa.PublicKey); !ok {
			continue
		}
		sum := CertSHA256(cert.Raw)
		if seen[sum] {
			continue
		}
		seen[sum] = true
		out = append(out, parsedIdentity{cert: cert, sha256: sum, hardware: r.Hardware})
	}
	return out, nil
}

// VerifyTrust verifies cert via the OS S/MIME trust policy for usage ("sign" or "encrypt") and email.
func VerifyTrust(ctx context.Context, usage, email string, cert *smx509.Certificate) error {
	if cert == nil {
		return errors.New("invalid X.509 certificate")
	}
	return trust(ctx, usage, email, cert, nil)
}

// VerifyTrustWithChain verifies cert via the OS S/MIME trust policy and returns
// the resolved certificate chain ordered top-down from root/highest CA to leaf.
func VerifyTrustWithChain(ctx context.Context, usage, email string, cert *smx509.Certificate) ([]CertChainNode, error) {
	if cert == nil {
		return nil, errors.New("invalid X.509 certificate")
	}
	_, nodes, err := trustWithChain(ctx, usage, email, cert, nil)
	return nodes, err
}

// ListIdentities returns personal S/MIME certificates matching email (or all when email == "").
func ListIdentities(ctx context.Context, email string) ([]IdentityInfo, error) {
	items, err := parsedIdentities(ctx)
	if err != nil {
		return nil, err
	}
	var out []IdentityInfo
	for _, it := range items {
		if email != "" && !MatchesMailbox(it.cert, email) {
			continue
		}
		checkEmail := email
		if checkEmail == "" {
			if emails := CertEmails(it.cert); len(emails) > 0 {
				checkEmail = emails[0]
			}
		}
		var canSign, canEnc bool
		var chainNodes []CertChainNode
		if checkEmail != "" {
			_, signNodes, signErr := trustWithChain(ctx, "sign", checkEmail, it.cert, nil)
			canSign = signErr == nil
			_, encNodes, encErr := trustWithChain(ctx, "encrypt", checkEmail, it.cert, nil)
			canEnc = encErr == nil
			switch {
			case canSign && len(signNodes) > 0:
				chainNodes = signNodes
			case canEnc && len(encNodes) > 0:
				chainNodes = encNodes
			case len(signNodes) >= len(encNodes):
				chainNodes = signNodes
			default:
				chainNodes = encNodes
			}
		}
		if len(chainNodes) == 0 {
			chainNodes = BuildCertChainWithTrust([][]byte{it.cert.Raw}, canSign || canEnc)
		}
		meta := InspectCertificate(it.cert)
		out = append(out, IdentityInfo{
			SHA256:        it.sha256,
			Subject:       meta.Subject,
			SubjectDN:     meta.SubjectDN,
			SubjectAttrs:  meta.SubjectAttrs,
			Issuer:        meta.Issuer,
			IssuerDN:      meta.IssuerDN,
			IssuerAttrs:   meta.IssuerAttrs,
			Emails:        meta.Emails,
			SerialNumber:  meta.SerialNumber,
			NotBefore:     meta.NotBefore,
			NotAfter:      meta.NotAfter,
			PublicKeyAlgo: meta.PublicKeyAlgo,
			SignatureAlgo: meta.SignatureAlgo,
			KeyUsages:     meta.KeyUsages,
			ExtKeyUsages:  meta.ExtKeyUsages,
			SHA1:          meta.SHA1,
			Hardware:      it.hardware,
			CanSign:       canSign,
			CanEncrypt:    canEnc,
			Chain:         chainNodes,
		})
	}
	slices.SortFunc(out, func(a, b IdentityInfo) int {
		av := a.CanSign || a.CanEncrypt
		bv := b.CanSign || b.CanEncrypt
		if av != bv {
			if av {
				return -1
			}
			return 1
		}
		if c := b.NotBefore.Compare(a.NotBefore); c != 0 {
			return c
		}
		return cmp.Compare(a.SHA256, b.SHA256)
	})
	return out, nil
}

// MatchesMailbox 同时识别 subjectAltName 和早期证书主题中的 emailAddress。
func MatchesMailbox(cert *smx509.Certificate, email string) bool {
	if cert == nil || email == "" || hasControlChar(email) {
		return false
	}
	for _, addr := range cert.EmailAddresses {
		if !hasControlChar(addr) && strings.EqualFold(addr, email) {
			return true
		}
	}
	for _, attr := range cert.Subject.Names {
		if attr.Type.String() == "1.2.840.113549.1.9.1" {
			if addr, ok := attr.Value.(string); ok && !hasControlChar(addr) && strings.EqualFold(addr, email) {
				return true
			}
		}
	}
	return false
}

func trust(ctx context.Context, usage, email string, cert *smx509.Certificate, chain []*smx509.Certificate) error {
	_, _, err := trustWithChain(ctx, usage, email, cert, chain)
	return err
}

func trustWithChain(ctx context.Context, usage, email string, cert *smx509.Certificate, chain []*smx509.Certificate) ([][]byte, []CertChainNode, error) {
	if !MatchesMailbox(cert, email) {
		ders := [][]byte{cert.Raw}
		return ders, BuildCertChainWithIssues(ders, [][]string{{CertIssueEmailMismatch}}, false), fmt.Errorf("certificate email does not match %s: %w", email, &TrustError{Issues: []string{CertIssueEmailMismatch}})
	}
	ders := [][]byte{cert.Raw}
	for _, c := range chain {
		if !bytes.Equal(c.Raw, cert.Raw) {
			ders = append(ders, c.Raw)
		}
	}
	var resolved [][]byte
	var nodes []CertChainNode
	err := withVerifyProvider(ctx, func(p provider) error {
		if cv, ok := p.(chainVerifier); ok {
			var verr error
			resolved, nodes, verr = cv.VerifyTrustWithChain(ctx, usage, email, ders)
			return verr
		}
		return p.VerifyTrust(ctx, usage, email, ders)
	})
	if len(resolved) == 0 {
		resolved = [][]byte{cert.Raw}
	}
	if len(nodes) == 0 && len(resolved) > 0 {
		nodes = BuildCertChainWithTrust(resolved, err == nil)
	}
	return resolved, nodes, err
}

func ownCertificate(ctx context.Context, email, usage, preferredSHA256 string) (*smx509.Certificate, error) {
	certs, err := identities(ctx)
	if err != nil {
		return nil, err
	}
	preferredSHA256 = strings.ToLower(strings.TrimSpace(preferredSHA256))
	var selected *smx509.Certificate
	var lastErr error
	matchedPreferred := false
	for _, cert := range certs {
		if !MatchesMailbox(cert, email) {
			continue
		}
		sum := CertSHA256(cert.Raw)
		if preferredSHA256 != "" && sum != preferredSHA256 {
			continue
		}
		matchedPreferred = matchedPreferred || preferredSHA256 == "" || sum == preferredSHA256
		if err := trust(ctx, usage, email, cert, nil); err != nil {
			lastErr = err
			continue
		}
		if selected == nil || cert.NotBefore.After(selected.NotBefore) ||
			(cert.NotBefore.Equal(selected.NotBefore) && sum < CertSHA256(selected.Raw)) {
			selected = cert
		}
	}
	if selected == nil {
		if lastErr != nil {
			return nil, lastErr
		}
		if preferredSHA256 != "" && !matchedPreferred {
			return nil, fmt.Errorf("selected personal S/MIME certificate for %s not found; choose another in Account Settings", email)
		}
		return nil, fmt.Errorf("no matching personal S/MIME certificate found for %s", email)
	}
	return selected, nil
}
