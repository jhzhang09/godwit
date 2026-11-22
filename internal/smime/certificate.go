package smime

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"

	"github.com/emmansun/gmsm/pkcs7"
	"github.com/emmansun/gmsm/smx509"
)

// ErrWeakKeySize reports that a certificate uses a key length below OS minimum security requirements.
var ErrWeakKeySize = errors.New("certificate key size below system security requirement")

// WeakKeySizeError describes a certificate rejected due to an insufficient cryptographic key length.
type WeakKeySizeError struct {
	Subject string
	KeyAlgo string
	KeyBits int
	MinBits int
}

// Unwrap allows errors.Is(err, ErrWeakKeySize) matching.
func (e *WeakKeySizeError) Unwrap() error { return ErrWeakKeySize }

// Error returns a clear English summary of the insufficient key size.
func (e *WeakKeySizeError) Error() string {
	if e == nil {
		return ErrWeakKeySize.Error()
	}
	hasAlgo := e.KeyAlgo != "" && e.KeyBits > 0 && e.MinBits > 0
	switch {
	case e.Subject != "" && hasAlgo:
		return fmt.Sprintf("certificate %q uses a key length below system requirements (%s %d-bit; requires at least %d-bit)", e.Subject, e.KeyAlgo, e.KeyBits, e.MinBits)
	case e.Subject != "":
		return fmt.Sprintf("certificate %q uses a key length below system security requirements", e.Subject)
	case hasAlgo:
		return fmt.Sprintf("certificate uses a key length below system requirements (%s %d-bit; requires at least %d-bit)", e.KeyAlgo, e.KeyBits, e.MinBits)
	default:
		return ErrWeakKeySize.Error()
	}
}

func weakKeySizeErrorFromCert(cert *smx509.Certificate) *WeakKeySizeError {
	if cert == nil {
		return &WeakKeySizeError{}
	}
	wk := &WeakKeySizeError{
		Subject: CertDisplaySubject(cert),
	}
	switch k := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if k != nil && k.N != nil {
			wk.KeyAlgo = "RSA"
			wk.KeyBits = k.N.BitLen()
			wk.MinBits = 2048
		}
	case *ecdsa.PublicKey:
		if k != nil && k.Curve != nil {
			wk.KeyAlgo = "ECDSA"
			wk.KeyBits = k.Curve.Params().BitSize
			wk.MinBits = 256
		}
	}
	return wk
}

// ParseCertificate 保留旧卡使用的有符号序列号；仅提取制信所需的元数据。
// 信任判断始终将原始 DER 交给 macOS，无需放宽整个进程的 TLS 证书解析策略。
func ParseCertificate(der []byte) (*smx509.Certificate, error) {
	c, err := smx509.ParseCertificate(der)
	if err == nil || err.Error() != "x509: negative serial number" {
		return c, err
	}
	var cert struct {
		TBS struct {
			Version    int `asn1:"optional,explicit,tag:0"`
			Serial     *big.Int
			Algorithm  pkix.AlgorithmIdentifier
			Issuer     asn1.RawValue
			Validity   struct{ Start, End time.Time }
			Subject    pkix.RDNSequence
			PublicKey  asn1.RawValue
			IssuerID   asn1.BitString   `asn1:"optional,tag:1"`
			SubjectID  asn1.BitString   `asn1:"optional,tag:2"`
			Extensions []pkix.Extension `asn1:"optional,explicit,tag:3"`
		}
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}
	rest, e := asn1.Unmarshal(der, &cert)
	if e != nil || len(rest) != 0 || cert.TBS.Serial == nil || cert.TBS.Serial.Sign() >= 0 {
		return nil, err
	}
	t := cert.TBS
	pub, e := x509.ParsePKIXPublicKey(t.PublicKey.FullBytes)
	if e != nil {
		return nil, e
	}
	c = &smx509.Certificate{Raw: der, RawIssuer: t.Issuer.FullBytes, SerialNumber: t.Serial, PublicKey: pub, NotBefore: t.Validity.Start, NotAfter: t.Validity.End}
	c.Subject.FillFromRDNSequence(&t.Subject)
	var issuerRDN pkix.RDNSequence
	if _, e := asn1.Unmarshal(t.Issuer.FullBytes, &issuerRDN); e == nil {
		c.Issuer.FillFromRDNSequence(&issuerRDN)
	}
	for _, ext := range t.Extensions {
		switch ext.Id.String() {
		case "2.5.29.15":
			var ku asn1.BitString
			if _, e := asn1.Unmarshal(ext.Value, &ku); e == nil {
				var usage int
				for i := 0; i < 9; i++ {
					if ku.At(i) != 0 {
						usage |= 1 << uint(i)
					}
				}
				c.KeyUsage = smx509.KeyUsage(usage)
			}
		case "2.5.29.17":
			var names []asn1.RawValue
			if _, e := asn1.Unmarshal(ext.Value, &names); e != nil {
				return nil, e
			}
			for _, name := range names {
				if name.Class == asn1.ClassContextSpecific && name.Tag == 1 && !name.IsCompound {
					c.EmailAddresses = append(c.EmailAddresses, string(name.Bytes))
				}
			}
		case "2.5.29.14":
			if _, e := asn1.Unmarshal(ext.Value, &c.SubjectKeyId); e != nil {
				return nil, e
			}
		}
	}
	return c, nil
}

// CertDetails summarizes user-inspectable metadata extracted from an X.509 certificate.
type CertDetails struct {
	Subject       string
	SubjectDN     string
	Issuer        string
	IssuerDN      string
	Emails        []string
	SerialNumber  string
	NotBefore     time.Time
	NotAfter      time.Time
	PublicKeyAlgo string
	SignatureAlgo string
	KeyUsages     []string
	ExtKeyUsages  []string
	SHA256        string
	SHA1          string
}

// CertChainNode summarizes one certificate in a resolved X.509 trust chain,
// ordered top-down from root/highest CA to leaf.
type CertChainNode struct {
	Subject       string
	Issuer        string
	PublicKeyAlgo string
	NotBefore     time.Time
	NotAfter      time.Time
	SHA256        string
	Role          string // "root", "intermediate", or "leaf"
	SelfSigned    bool
}

// BuildCertChain converts an OS-ordered certificate chain (leaf first, root last)
// into a top-down display slice (root/highest CA first, leaf last).
func BuildCertChain(ders [][]byte) []CertChainNode {
	if len(ders) == 0 {
		return nil
	}
	parsed := make([]*smx509.Certificate, 0, len(ders))
	for _, der := range ders {
		if len(der) == 0 {
			continue
		}
		if c, err := ParseCertificate(der); err == nil {
			parsed = append(parsed, c)
		}
	}
	if len(parsed) == 0 {
		return nil
	}
	out := make([]CertChainNode, len(parsed))
	for i, c := range parsed {
		d := InspectCertificate(c)
		selfSigned := len(c.RawIssuer) > 0 && bytes.Equal(c.RawIssuer, c.RawSubject)
		role := "intermediate"
		switch {
		case i == 0:
			role = "leaf"
		case i == len(parsed)-1 && selfSigned:
			role = "root"
		}
		// Reverse order so index 0 is root / highest CA and last is leaf.
		out[len(parsed)-1-i] = CertChainNode{
			Subject:       d.Subject,
			Issuer:        d.Issuer,
			PublicKeyAlgo: d.PublicKeyAlgo,
			NotBefore:     d.NotBefore,
			NotAfter:      d.NotAfter,
			SHA256:        d.SHA256,
			Role:          role,
			SelfSigned:    selfSigned,
		}
	}
	return out
}

// InspectCertificate extracts display-friendly X.509 metadata from cert.
func InspectCertificate(cert *smx509.Certificate) CertDetails {
	if cert == nil {
		return CertDetails{}
	}
	issuer := strings.TrimSpace(cert.Issuer.CommonName)
	if issuer == "" && len(cert.Issuer.Organization) > 0 {
		issuer = strings.TrimSpace(cert.Issuer.Organization[0])
	}
	if issuer == "" {
		issuer = strings.TrimSpace(cert.Issuer.String())
	}

	var keyAlgo string
	switch k := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if k != nil && k.N != nil {
			keyAlgo = fmt.Sprintf("RSA (%d bit)", k.N.BitLen())
		}
	case *ecdsa.PublicKey:
		if k != nil && k.Curve != nil {
			name := k.Curve.Params().Name
			switch {
			case strings.EqualFold(name, "sm2p256v1"), name == "SM2":
				keyAlgo = "SM2 (256 bit)"
			case name != "":
				keyAlgo = fmt.Sprintf("ECDSA (%s)", name)
			case k.Curve.Params().BitSize > 0:
				keyAlgo = fmt.Sprintf("ECDSA (%d bit)", k.Curve.Params().BitSize)
			}
		}
	case ed25519.PublicKey:
		keyAlgo = "Ed25519"
	default:
		if cert.PublicKeyAlgorithm != 0 {
			keyAlgo = cert.PublicKeyAlgorithm.String()
		}
	}

	var sigAlgo string
	if cert.SignatureAlgorithm != smx509.UnknownSignatureAlgorithm {
		if s := cert.SignatureAlgorithm.String(); s != "" && s != "0" {
			sigAlgo = s
		}
	}

	var keyUsages []string
	if cert.KeyUsage&smx509.KeyUsageDigitalSignature != 0 {
		keyUsages = append(keyUsages, "digital_signature")
	}
	if cert.KeyUsage&smx509.KeyUsageContentCommitment != 0 {
		keyUsages = append(keyUsages, "content_commitment")
	}
	if cert.KeyUsage&smx509.KeyUsageKeyEncipherment != 0 {
		keyUsages = append(keyUsages, "key_encipherment")
	}
	if cert.KeyUsage&smx509.KeyUsageDataEncipherment != 0 {
		keyUsages = append(keyUsages, "data_encipherment")
	}
	if cert.KeyUsage&smx509.KeyUsageKeyAgreement != 0 {
		keyUsages = append(keyUsages, "key_agreement")
	}

	var extKeyUsages []string
	for _, eku := range cert.ExtKeyUsage {
		switch eku {
		case smx509.ExtKeyUsageEmailProtection:
			extKeyUsages = append(extKeyUsages, "email_protection")
		case smx509.ExtKeyUsageClientAuth:
			extKeyUsages = append(extKeyUsages, "client_auth")
		case smx509.ExtKeyUsageServerAuth:
			extKeyUsages = append(extKeyUsages, "server_auth")
		case smx509.ExtKeyUsageCodeSigning:
			extKeyUsages = append(extKeyUsages, "code_signing")
		}
	}

	var sha1Hex, sha256Hex string
	if len(cert.Raw) > 0 {
		sha256Hex = CertSHA256(cert.Raw)
		s1 := sha1.Sum(cert.Raw)
		sha1Hex = hex.EncodeToString(s1[:])
	}

	return CertDetails{
		Subject:       CertDisplaySubject(cert),
		SubjectDN:     strings.TrimSpace(cert.Subject.String()),
		Issuer:        issuer,
		IssuerDN:      strings.TrimSpace(cert.Issuer.String()),
		Emails:        CertEmails(cert),
		SerialNumber:  formatSerialHex(cert.SerialNumber),
		NotBefore:     cert.NotBefore,
		NotAfter:      cert.NotAfter,
		PublicKeyAlgo: keyAlgo,
		SignatureAlgo: sigAlgo,
		KeyUsages:     keyUsages,
		ExtKeyUsages:  extKeyUsages,
		SHA256:        sha256Hex,
		SHA1:          sha1Hex,
	}
}

// InspectCertificateDER parses DER and returns its inspectable metadata.
func InspectCertificateDER(der []byte) (CertDetails, error) {
	cert, err := ParseCertificate(der)
	if err != nil {
		return CertDetails{}, err
	}
	return InspectCertificate(cert), nil
}

// FormatHexColons formats bytes as colon-separated uppercase hexadecimal pairs.
func FormatHexColons(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.Grow(len(b)*3 - 1)
	for i, v := range b {
		if i > 0 {
			sb.WriteByte(':')
		}
		fmt.Fprintf(&sb, "%02X", v)
	}
	return sb.String()
}

func formatSerialHex(n *big.Int) string {
	if n == nil {
		return ""
	}
	if n.Sign() == 0 {
		return "00"
	}
	s := FormatHexColons(new(big.Int).Abs(n).Bytes())
	if n.Sign() < 0 {
		return "-" + s
	}
	return s
}

// CertSHA256 returns the lowercase SHA-256 hex digest of a DER-encoded certificate.
func CertSHA256(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// CertDisplaySubject returns a human-readable subject name for cert.
func CertDisplaySubject(cert *smx509.Certificate) string {
	if cert == nil {
		return ""
	}
	if cn := strings.TrimSpace(cert.Subject.CommonName); cn != "" {
		return cn
	}
	if emails := CertEmails(cert); len(emails) > 0 {
		return emails[0]
	}
	return strings.TrimSpace(cert.Subject.String())
}

// CertEmails extracts lowercase normalized mailbox addresses from cert's SAN and Subject.
func CertEmails(cert *smx509.Certificate) []string {
	if cert == nil {
		return nil
	}
	var out []string
	add := func(s string) {
		s = strings.ToLower(strings.TrimSpace(s))
		if s != "" && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	for _, a := range cert.EmailAddresses {
		add(a)
	}
	for _, attr := range cert.Subject.Names {
		if attr.Type.String() == "1.2.840.113549.1.9.1" {
			if addr, ok := attr.Value.(string); ok {
				add(addr)
			}
		}
	}
	return out
}

// ParseCertificateBundle extracts X.509 certificates from DER, PEM, or PKCS#7/CMS bundles.
func ParseCertificateBundle(data []byte) ([]*smx509.Certificate, error) {
	seen := map[string]bool{}
	var out []*smx509.Certificate
	appendDER := func(der []byte) {
		cert, err := ParseCertificate(der)
		if err != nil {
			return
		}
		key := CertSHA256(cert.Raw)
		if !seen[key] {
			seen[key] = true
			out = append(out, cert)
		}
	}

	rest := data
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		switch blk.Type {
		case "CERTIFICATE", "X509 CERTIFICATE":
			appendDER(blk.Bytes)
		case "PKCS7":
			if p7, err := pkcs7.Parse(blk.Bytes); err == nil {
				for _, c := range p7.Certificates {
					appendDER(c.Raw)
				}
			}
		}
	}
	if len(out) > 0 {
		return out, nil
	}
	if cert, err := ParseCertificate(data); err == nil {
		return []*smx509.Certificate{cert}, nil
	}
	if p7, err := pkcs7.Parse(data); err == nil {
		for _, c := range p7.Certificates {
			appendDER(c.Raw)
		}
		if len(out) > 0 {
			return out, nil
		}
	}
	// Strip leading/trailing whitespace if base64/DER had noise; otherwise fail cleanly.
	if trimmed := bytes.TrimSpace(data); len(trimmed) != len(data) {
		if certs, err := ParseCertificateBundle(trimmed); err == nil && len(certs) > 0 {
			return certs, nil
		}
	}
	return nil, errors.New("no valid X.509 certificate found")
}
