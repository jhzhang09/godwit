package smime

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/mail"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/emmansun/gmsm/pkcs7"
	"github.com/emmansun/gmsm/smx509"
	"github.com/stretchr/testify/require"
)

func TestDetachedBytes(t *testing.T) {
	first := "Content-Type: text/plain\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nhello=20\r\n--not-the-boundary\r\n"
	parts, err := splitSigned([]byte("preamble\r\n--sep\r\n"+first+"\r\n--sep\r\nsignature\r\n--sep--\r\n"), "sep")
	if err != nil || len(parts) != 2 || string(parts[0]) != first || string(parts[1]) != "signature" {
		t.Fatalf("parts=%q err=%v", parts, err)
	}
}
func TestSplitOutgoing(t *testing.T) {
	outer, entity, err := splitOutgoing([]byte("To: example@example.org\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed;\r\n boundary=abc\r\nSubject: subject\r\n\r\n--abc--"))
	if err != nil || string(outer) != "To: example@example.org\r\nMIME-Version: 1.0\r\nSubject: subject\r\n" || string(entity) != "Content-Type: multipart/mixed;\r\n boundary=abc\r\n\r\n--abc--" {
		t.Fatal(err, string(outer), string(entity))
	}
}

// 只在显式授权后本地运行，使用生成的固定文字，不访问邮箱服务器。
func TestHardwareRoundTrip(t *testing.T) {
	if os.Getenv("GODWIT_TEST_SMIME_TOKEN") != "1" {
		t.Skip("需要用户授权及硬件 Key")
	}
	ctx := t.Context()
	certs, err := identities(ctx)
	if err != nil || len(certs) != 1 {
		t.Fatalf("identities=%d err=%v", len(certs), err)
	}
	cert := certs[0]
	var email string
	if len(cert.EmailAddresses) > 0 {
		email = cert.EmailAddresses[0]
	} else {
		for _, attr := range cert.Subject.Names {
			if attr.Type.String() == "1.2.840.113549.1.9.1" {
				email, _ = attr.Value.(string)
				break
			}
		}
	}
	if email == "" {
		t.Fatal("硬件证书没有邮箱地址")
	}
	raw := []byte(fmt.Sprintf("From: %s\r\nTo: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain\r\n\r\nGodwit local S/MIME test\r\n", email, email))
	protected, err := Protect(ctx, raw, email, []string{email}, true, true, func(context.Context, []string) (map[string][]*smx509.Certificate, error) { return nil, nil })
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(ctx, protected)
	if err != nil {
		t.Fatal(err)
	}
	_, want, _ := splitOutgoing(raw)
	if !bytes.Equal(got.Entity, want) || !got.Encrypted || got.Signer != email {
		t.Fatal("解密正文或验签结果不匹配")
	}
}

func TestSignedContentTamperAndFrom(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(42), EmailAddresses: []string{"alice@example.org"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	cert, err := smx509.ParseCertificate(der)
	require.NoError(t, err)
	content := []byte("Content-Type: text/plain\r\n\r\noriginal")
	sd, err := pkcs7.NewSignedData(content)
	require.NoError(t, err)
	sd.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	require.NoError(t, sd.AddSigner(cert, priv, pkcs7.SignerInfoConfig{}))
	sd.Detach()
	sig, err := sd.Finish()
	require.NoError(t, err)
	p7, err := pkcs7.Parse(sig)
	require.NoError(t, err)
	p7.Content = content
	require.NoError(t, p7.Verify())
	raw := "From: other@example.org\r\nContent-Type: multipart/signed; protocol=\"application/pkcs7-signature\"; boundary=part\r\n\r\n--part\r\n" + string(content) + "\r\n--part\r\nContent-Type: application/pkcs7-signature\r\nContent-Transfer-Encoding: base64\r\n\r\n" + base64.StdEncoding.EncodeToString(sig) + "\r\n--part--\r\n"
	for _, tc := range []struct{ raw, reason string }{
		{raw, "does not match other@example.org"},
		{strings.Replace(raw, "From: other@example.org", "From: =?gb2312?B?suLK1A==?= <other@example.org>", 1), "does not match other@example.org"},
		{strings.Replace(raw, "original", "altered", 1), "invalid S/MIME signature"},
	} {
		result, err := Open(t.Context(), []byte(tc.raw))
		require.ErrorContains(t, err, tc.reason)
		require.Empty(t, result.Entity)
		require.Empty(t, result.Signer)
	}
}

func TestReadCMSMailBase64(t *testing.T) {
	for _, encoded := range []string{"YWJjZA==", "YWJjZA", "YWJj\r\n ZA=="} {
		m, err := mail.ReadMessage(strings.NewReader("Content-Transfer-Encoding: base64\r\n\r\n" + encoded))
		require.NoError(t, err)
		got, err := readCMS(m)
		require.NoError(t, err)
		require.Equal(t, []byte("abcd"), got)
	}
}

func TestIsCMSPart(t *testing.T) {
	require.True(t, IsCMSPart("application/pkcs7-mime", ""))
	require.True(t, IsCMSPart("application/x-pkcs7-mime", "smime.p7m"))
	require.True(t, IsCMSPart("application/octet-stream", "SMIME.P7M"))
	require.False(t, IsCMSPart("application/pkcs7-signature", "smime.p7s"))
	require.False(t, IsCMSPart("application/octet-stream", "smime.p7s"))
	require.True(t, IsPart("application/pkcs7-signature", "smime.p7s"))
	require.True(t, IsPart("application/octet-stream", "smime.p7s"))
}

func TestIsCMSSignedData(t *testing.T) {
	signedOID := []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02}
	envelopedOID := []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x03}
	require.True(t, isCMSSignedData(append([]byte{0x30, 0x20}, signedOID...)))
	require.True(t, isCMSSignedData(append([]byte{0x30, 0x82, 0x04, 0x00}, signedOID...)))
	require.True(t, isCMSSignedData(append([]byte{0x30, 0x80}, signedOID...)))
	require.False(t, isCMSSignedData(append([]byte{0x30, 0x82, 0x04, 0x00}, envelopedOID...)))
	require.False(t, isCMSSignedData([]byte{0x30, 0x82}))
	require.False(t, isCMSSignedData([]byte{0x31, 0x20}))
}

func TestOpenCMSSignedTamperAndFrom(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(42), EmailAddresses: []string{"alice@example.org"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	cert, err := smx509.ParseCertificate(der)
	require.NoError(t, err)
	content := []byte("Content-Type: text/plain\r\n\r\noriginal")
	sd, err := pkcs7.NewSignedData(content)
	require.NoError(t, err)
	sd.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	require.NoError(t, sd.AddSigner(cert, priv, pkcs7.SignerInfoConfig{}))
	cms, err := sd.Finish()
	require.NoError(t, err)

	for _, tc := range []struct {
		from   string
		der    []byte
		reason string
	}{
		{"other@example.org", cms, "does not match other@example.org"},
		{"=?gb2312?B?suLK1A==?= <other@example.org>", cms, "does not match other@example.org"},
		{"alice@example.org, bob@example.org", cms, "does not match "},
		{"alice@example.org", bytes.ReplaceAll(cms, []byte("original"), []byte("altered!")), "invalid S/MIME signature"},
	} {
		result, err := OpenCMS(t.Context(), tc.from, tc.der)
		require.ErrorContains(t, err, tc.reason)
		require.Empty(t, result.Entity)
		require.Empty(t, result.Signer)
	}
}

type stubVerifyProvider struct{}

func (stubVerifyProvider) Identities(context.Context) ([]RawIdentity, error) { return nil, nil }
func (stubVerifyProvider) FindCertificates(context.Context, string) ([][]byte, error) {
	return nil, nil
}
func (stubVerifyProvider) Prepare(context.Context, []byte, []byte) error {
	return nil
}
func (stubVerifyProvider) DigestAlgorithm(context.Context, []byte) (crypto.Hash, error) {
	return 0, nil
}
func (stubVerifyProvider) Sign(context.Context, []byte, crypto.Hash, []byte) ([]byte, error) {
	return nil, nil
}
func (stubVerifyProvider) Decrypt(context.Context, []byte, []byte) ([]byte, error) { return nil, nil }
func (stubVerifyProvider) VerifyTrust(context.Context, string, string, [][]byte) error {
	return nil
}
func (stubVerifyProvider) VerifyCMS(context.Context, string, []byte, []byte) (cmsVerifyResult, error) {
	return cmsVerifyResult{content: []byte("Content-Type: text/plain\r\n\r\nok"), signerDER: []byte{0x01, 0x02}}, nil
}
func (stubVerifyProvider) Retry(context.Context) error { return nil }
func (stubVerifyProvider) Close() error                { return nil }

func TestSessionVerifyBypassesHardwareGate(t *testing.T) {
	sess := NewSession(t.Context())
	// 模拟硬件 Key 锁正被占用。
	sess.gate <- struct{}{}
	defer func() { <-sess.gate }()

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()

	// 通过 providerKey 的纯软件验签必须无阻塞返回。
	provCtx := context.WithValue(context.WithValue(ctx, sessionKey{}, sess), providerKey{}, stubVerifyProvider{})
	res, err := verifyCMS(provCtx, "alice@example.org", []byte{0x30, 0x00}, nil)
	require.NoError(t, err)
	require.NoError(t, res.verifyErr)
	require.Equal(t, []byte("Content-Type: text/plain\r\n\r\nok"), res.content)
	require.Equal(t, []byte{0x01, 0x02}, res.signerDER)

	if !Supported() {
		return
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(77), EmailAddresses: []string{"untrusted@example.org"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	cert, err := smx509.ParseCertificate(der)
	require.NoError(t, err)
	sd, err := pkcs7.NewSignedData([]byte("Content-Type: text/plain\r\n\r\nhi"))
	require.NoError(t, err)
	sd.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	require.NoError(t, sd.AddSigner(cert, priv, pkcs7.SignerInfoConfig{}))
	cms, err := sd.Finish()
	require.NoError(t, err)

	// 真实系统 VerifyTrust / VerifyCMS 在 session.gate 被持有时也应立即返回（此处因自签名返回不信任错误，但绝不阻塞）。
	_, err = sess.OpenCMS(ctx, "untrusted@example.org", cms)
	require.Error(t, err)
}

type softwareProvider struct {
	identities []RawIdentity
	keys       map[string]*rsa.PrivateKey
	trustErr   error
}

func (p *softwareProvider) Identities(context.Context) ([]RawIdentity, error) {
	return p.identities, nil
}
func (p *softwareProvider) FindCertificates(context.Context, string) ([][]byte, error) {
	return nil, nil
}
func (p *softwareProvider) Prepare(context.Context, []byte, []byte) error { return nil }
func (p *softwareProvider) DigestAlgorithm(context.Context, []byte) (crypto.Hash, error) {
	return crypto.SHA256, nil
}
func (p *softwareProvider) Sign(_ context.Context, certDER []byte, hash crypto.Hash, digest []byte) ([]byte, error) {
	k := p.keys[CertSHA256(certDER)]
	if k == nil {
		return nil, fmt.Errorf("missing key")
	}
	return rsa.SignPKCS1v15(rand.Reader, k, hash, digest)
}
func (p *softwareProvider) Decrypt(_ context.Context, certDER, data []byte) ([]byte, error) {
	k := p.keys[CertSHA256(certDER)]
	if k == nil {
		return nil, fmt.Errorf("missing key")
	}
	return rsa.DecryptPKCS1v15(rand.Reader, k, data)
}
func (p *softwareProvider) VerifyTrust(context.Context, string, string, [][]byte) error {
	return p.trustErr
}
func (p *softwareProvider) VerifyCMS(_ context.Context, _ string, der, detached []byte) (cmsVerifyResult, error) {
	pkt, err := pkcs7.Parse(der)
	if err != nil {
		return cmsVerifyResult{}, err
	}
	if len(detached) > 0 {
		pkt.Content = detached
	}
	var signerDER []byte
	if signer := pkt.GetOnlySigner(); signer != nil {
		signerDER = signer.Raw
	}
	if err := pkt.Verify(); err != nil {
		return cmsVerifyResult{content: pkt.Content, signerDER: signerDER, verifyErr: err}, nil
	}
	if p.trustErr != nil {
		return cmsVerifyResult{content: pkt.Content, signerDER: signerDER, cryptOK: true, verifyErr: p.trustErr}, nil
	}
	return cmsVerifyResult{content: pkt.Content, signerDER: signerDER, cryptOK: true, trustOK: true}, nil
}
func (p *softwareProvider) Retry(context.Context) error { return nil }
func (p *softwareProvider) Close() error                { return nil }

func TestCertificateBundleListAndProtectWith(t *testing.T) {
	now := time.Now()
	makeCert := func(email, cn string, notBefore time.Time) (*rsa.PrivateKey, *smx509.Certificate) {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		tmpl := &x509.Certificate{
			SerialNumber:   big.NewInt(notBefore.UnixNano()),
			Subject:        pkix.Name{CommonName: cn},
			EmailAddresses: []string{email},
			NotBefore:      notBefore,
			NotAfter:       now.Add(24 * time.Hour),
			KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
		require.NoError(t, err)
		cert, err := ParseCertificate(der)
		require.NoError(t, err)
		return k, cert
	}

	aliceKeyOld, aliceCertOld := makeCert("alice@example.org", "Alice Old", now.Add(-2*time.Hour))
	aliceKeyNew, aliceCertNew := makeCert("alice@example.org", "Alice New", now.Add(-time.Hour))
	bobKeyOld, bobCertOld := makeCert("bob@example.org", "Bob Old", now.Add(-2*time.Hour))
	bobKeyNew, bobCertNew := makeCert("bob@example.org", "Bob New", now.Add(-time.Hour))

	// ParseCertificateBundle handles DER, multi-PEM, and CMS SignedData bundles.
	bundlePEM := append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: bobCertOld.Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "X509 CERTIFICATE", Bytes: bobCertNew.Raw})...,
	)
	parsedPEM, err := ParseCertificateBundle(bundlePEM)
	require.NoError(t, err)
	require.Len(t, parsedPEM, 2)

	sd, err := pkcs7.NewSignedData([]byte("bundle"))
	require.NoError(t, err)
	require.NoError(t, sd.AddSigner(bobCertOld, bobKeyOld, pkcs7.SignerInfoConfig{}))
	p7b, err := sd.Finish()
	require.NoError(t, err)
	parsedP7B, err := ParseCertificateBundle(p7b)
	require.NoError(t, err)
	require.Len(t, parsedP7B, 1)
	require.Equal(t, CertSHA256(bobCertOld.Raw), CertSHA256(parsedP7B[0].Raw))

	prov := &softwareProvider{
		identities: []RawIdentity{
			{DER: aliceCertOld.Raw, Hardware: false},
			{DER: aliceCertNew.Raw, Hardware: true},
		},
		keys: map[string]*rsa.PrivateKey{
			CertSHA256(aliceCertOld.Raw): aliceKeyOld,
			CertSHA256(aliceCertNew.Raw): aliceKeyNew,
		},
	}
	ctx := context.WithValue(t.Context(), providerKey{}, prov)

	ids, err := ListIdentities(ctx, "alice@example.org")
	require.NoError(t, err)
	require.Len(t, ids, 2)
	// Newest certificate is ordered first.
	require.Equal(t, CertSHA256(aliceCertNew.Raw), ids[0].SHA256)
	require.True(t, ids[0].Hardware)
	require.False(t, ids[1].Hardware)

	// Explicitly pin Alice's older software cert and Bob's older cert.
	raw := []byte("From: alice@example.org\r\nTo: bob@example.org\r\nSubject: Test\r\nContent-Type: text/plain\r\n\r\nhello pinned")
	protected, err := ProtectWith(ctx, raw, "alice@example.org", []string{"bob@example.org"}, ProtectOptions{
		Sign:        true,
		Encrypt:     true,
		OwnCertSHA:  CertSHA256(aliceCertOld.Raw),
		PinnedCerts: map[string]string{"bob@example.org": CertSHA256(bobCertOld.Raw)},
	}, func(context.Context, []string) (map[string][]*smx509.Certificate, error) {
		return map[string][]*smx509.Certificate{
			"bob@example.org": {bobCertNew, bobCertOld},
		}, nil
	})
	require.NoError(t, err)

	// Bob opens with Bob's older key and recovers Alice's older SignerCert.
	bobProv := &softwareProvider{
		identities: []RawIdentity{{DER: bobCertOld.Raw}},
		keys:       map[string]*rsa.PrivateKey{CertSHA256(bobCertOld.Raw): bobKeyOld},
	}
	bobCtx := context.WithValue(t.Context(), providerKey{}, bobProv)
	opened, err := Open(bobCtx, protected)
	require.NoError(t, err)
	require.True(t, opened.Encrypted)
	require.Equal(t, "alice@example.org", opened.Signer)
	require.Equal(t, CertSHA256(aliceCertOld.Raw), CertSHA256(opened.SignerCert))
	require.Contains(t, string(opened.Entity), "hello pinned")
	_ = bobKeyNew
}

func TestOpenForReadDeliversBodyOnVerifyFailure(t *testing.T) {
	now := time.Now()
	var serial int64
	makeCert := func(email string) (*rsa.PrivateKey, *smx509.Certificate) {
		serial++
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		tmpl := &x509.Certificate{
			SerialNumber:   big.NewInt(serial),
			Subject:        pkix.Name{CommonName: email},
			EmailAddresses: []string{email},
			NotBefore:      now.Add(-time.Hour),
			NotAfter:       now.Add(24 * time.Hour),
			KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
		require.NoError(t, err)
		cert, err := ParseCertificate(der)
		require.NoError(t, err)
		return k, cert
	}

	aliceKey, aliceCert := makeCert("alice@example.org")
	bobKey, bobCert := makeCert("bob@example.org")

	aliceProv := &softwareProvider{
		identities: []RawIdentity{{DER: aliceCert.Raw}},
		keys:       map[string]*rsa.PrivateKey{CertSHA256(aliceCert.Raw): aliceKey},
	}
	aliceCtx := context.WithValue(t.Context(), providerKey{}, aliceProv)

	// 1. Encrypted + Signed mail whose signer cert fails trust validation.
	raw := []byte("From: alice@example.org\r\nTo: bob@example.org\r\nSubject: Report\r\nContent-Type: text/plain\r\n\r\ndecrypted plaintext body")
	protected, err := ProtectWith(aliceCtx, raw, "alice@example.org", []string{"bob@example.org"}, ProtectOptions{
		Sign:    true,
		Encrypt: true,
	}, func(context.Context, []string) (map[string][]*smx509.Certificate, error) {
		return map[string][]*smx509.Certificate{"bob@example.org": {bobCert}}, nil
	})
	require.NoError(t, err)

	bobUntrustedProv := &softwareProvider{
		identities: []RawIdentity{{DER: bobCert.Raw}},
		keys:       map[string]*rsa.PrivateKey{CertSHA256(bobCert.Raw): bobKey},
		trustErr:   fmt.Errorf("“alice@example.org”证书使用了无效的密钥大小"),
	}
	bobUntrustedCtx := context.WithValue(t.Context(), providerKey{}, bobUntrustedProv)

	// Strict Open still rejects untrusted signed content.
	_, err = Open(bobUntrustedCtx, protected)
	require.ErrorContains(t, err, "无效的密钥大小")

	// OpenForRead delivers decrypted plaintext + Encrypted=true + VerifyErr, with empty Signer/SignerCert,
	// while preserving UnverifiedCert so the user can still inspect the sender's certificate.
	opened, err := OpenForRead(bobUntrustedCtx, protected)
	require.NoError(t, err)
	require.True(t, opened.Encrypted)
	require.Contains(t, string(opened.Entity), "decrypted plaintext body")
	require.Contains(t, opened.VerifyErr, "无效的密钥大小")
	require.ErrorIs(t, opened.VerifyErrCause, bobUntrustedProv.trustErr)
	require.Empty(t, opened.Signer)
	require.Nil(t, opened.SignerCert)
	require.Equal(t, CertSHA256(aliceCert.Raw), CertSHA256(opened.UnverifiedCert))

	// 2. Also verify Session.OpenCMSForRead delivers content on real OS untrusted/invalid CMS signature.
	if Supported() {
		sess := NewSession(t.Context())
		sd, err := pkcs7.NewSignedData([]byte("Content-Type: text/plain\r\n\r\nreadable despite bad sig"))
		require.NoError(t, err)
		sd.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
		require.NoError(t, sd.AddSigner(aliceCert, aliceKey, pkcs7.SignerInfoConfig{}))
		cms, err := sd.Finish()
		require.NoError(t, err)

		tampered := bytes.ReplaceAll(cms, []byte("despite bad sig"), []byte("despite MOD sig"))
		_, err = sess.OpenCMS(t.Context(), "alice@example.org", tampered)
		require.Error(t, err)

		readOpened, err := sess.OpenCMSForRead(t.Context(), "alice@example.org", tampered)
		require.NoError(t, err)
		require.Contains(t, string(readOpened.Entity), "despite MOD sig")
		require.NotEmpty(t, readOpened.VerifyErr)
		require.Empty(t, readOpened.Signer)
		require.Nil(t, readOpened.SignerCert)
		require.Equal(t, CertSHA256(aliceCert.Raw), CertSHA256(readOpened.UnverifiedCert))
	}
}

func TestInspectCertificate(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	now := time.Now().UTC().Truncate(time.Second)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0x1234AB),
		Subject: pkix.Name{
			CommonName:   "Alice Example",
			Organization: []string{"Example Corp"},
		},
		Issuer: pkix.Name{
			CommonName:   "Example Internal CA",
			Organization: []string{"Example Corp"},
		},
		EmailAddresses: []string{"Alice@Example.com"},
		NotBefore:      now.Add(-time.Hour),
		NotAfter:       now.Add(48 * time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
	}
	parent := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Example Internal CA",
			Organization: []string{"Example Corp"},
		},
		NotBefore:             now.Add(-2 * time.Hour),
		NotAfter:              now.Add(72 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &k.PublicKey, k)
	require.NoError(t, err)

	d, err := InspectCertificateDER(der)
	require.NoError(t, err)
	require.Equal(t, "Alice Example", d.Subject)
	require.Contains(t, d.SubjectDN, "CN=Alice Example")
	require.Equal(t, "Example Internal CA", d.Issuer)
	require.Contains(t, d.IssuerDN, "CN=Example Internal CA")
	require.Equal(t, []string{"alice@example.com"}, d.Emails)
	require.Equal(t, "12:34:AB", d.SerialNumber)
	require.Equal(t, "RSA (2048 bit)", d.PublicKeyAlgo)
	require.Contains(t, d.SignatureAlgo, "RSA")
	require.Equal(t, []string{"digital_signature", "key_encipherment"}, d.KeyUsages)
	require.Equal(t, []string{"email_protection"}, d.ExtKeyUsages)
	require.Len(t, d.SHA256, 64)
	require.Len(t, d.SHA1, 40)

	// Negative serial fallback must also extract Issuer, KeyUsage, SerialNumber, and SAN emails.
	negTmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(0x42),
		Subject:        pkix.Name{CommonName: "Legacy Card"},
		EmailAddresses: []string{"legacy@example.com"},
		NotBefore:      now.Add(-time.Hour),
		NotAfter:       now.Add(24 * time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	negParent := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Legacy CA"},
	}
	posDER, err := x509.CreateCertificate(rand.Reader, negTmpl, negParent, &k.PublicKey, k)
	require.NoError(t, err)
	var rawCert struct {
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
	_, err = asn1.Unmarshal(posDER, &rawCert)
	require.NoError(t, err)
	rawCert.TBS.Serial = big.NewInt(-0x42)
	negDER, err := asn1.Marshal(rawCert)
	require.NoError(t, err)
	nd, err := InspectCertificateDER(negDER)
	require.NoError(t, err)
	require.Equal(t, "Legacy Card", nd.Subject)
	require.Equal(t, "Legacy CA", nd.Issuer)
	require.Equal(t, []string{"legacy@example.com"}, nd.Emails)
	require.Equal(t, "-42", nd.SerialNumber)
	require.Equal(t, "RSA (2048 bit)", nd.PublicKeyAlgo)
	require.Contains(t, nd.KeyUsages, "digital_signature")
	require.Contains(t, nd.KeyUsages, "key_encipherment")
}

type recordingVerifyProvider struct {
	softwareProvider
	allowFlags []bool
}

func (p *recordingVerifyProvider) VerifyTrust(ctx context.Context, usage, email string, certsDER [][]byte) error {
	p.allowFlags = append(p.allowFlags, AllowWeakKeySize(ctx))
	return p.softwareProvider.VerifyTrust(ctx, usage, email, certsDER)
}

func (p *recordingVerifyProvider) VerifyCMS(ctx context.Context, email string, der, detached []byte) (cmsVerifyResult, error) {
	p.allowFlags = append(p.allowFlags, AllowWeakKeySize(ctx))
	return p.softwareProvider.VerifyCMS(ctx, email, der, detached)
}

func TestWeakKeySizeContextAndError(t *testing.T) {
	require.False(t, AllowWeakKeySize(nil))
	require.False(t, AllowWeakKeySize(t.Context()))

	trueCtx := WithAllowWeakKeySize(t.Context(), true)
	require.True(t, AllowWeakKeySize(trueCtx))
	require.False(t, AllowWeakKeySize(WithAllowWeakKeySize(trueCtx, false)))

	cases := []struct {
		err  *WeakKeySizeError
		want string
	}{
		{
			err:  &WeakKeySizeError{Subject: "yczhang", KeyAlgo: "RSA", KeyBits: 1024, MinBits: 2048},
			want: `certificate "yczhang" uses a key length below system requirements (RSA 1024-bit; requires at least 2048-bit)`,
		},
		{
			err:  &WeakKeySizeError{Subject: "yczhang"},
			want: `certificate "yczhang" uses a key length below system security requirements`,
		},
		{
			err:  &WeakKeySizeError{KeyAlgo: "ECDSA", KeyBits: 224, MinBits: 256},
			want: `certificate uses a key length below system requirements (ECDSA 224-bit; requires at least 256-bit)`,
		},
		{
			err:  &WeakKeySizeError{},
			want: ErrWeakKeySize.Error(),
		},
	}
	for _, tc := range cases {
		require.ErrorIs(t, tc.err, ErrWeakKeySize)
		msg := tc.err.Error()
		require.Equal(t, tc.want, msg)
		require.NotContains(t, msg, "broken key size")
		require.NotContains(t, msg, "无效的密钥大小")
	}

	now := time.Now()
	makeCert := func(email string, serial int64) (*rsa.PrivateKey, *smx509.Certificate) {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		tmpl := &x509.Certificate{
			SerialNumber:   big.NewInt(serial),
			Subject:        pkix.Name{CommonName: email},
			EmailAddresses: []string{email},
			NotBefore:      now.Add(-time.Hour),
			NotAfter:       now.Add(24 * time.Hour),
			KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
		require.NoError(t, err)
		cert, err := ParseCertificate(der)
		require.NoError(t, err)
		return k, cert
	}

	aliceKey, aliceCert := makeCert("alice@example.org", 101)
	bobKey, bobCert := makeCert("bob@example.org", 102)

	recProv := &recordingVerifyProvider{
		softwareProvider: softwareProvider{
			identities: []RawIdentity{{DER: aliceCert.Raw}},
			keys:       map[string]*rsa.PrivateKey{CertSHA256(aliceCert.Raw): aliceKey},
		},
	}
	ctx := context.WithValue(t.Context(), providerKey{}, recProv)
	raw := []byte("From: alice@example.org\r\nTo: bob@example.org\r\nSubject: Compat\r\nContent-Type: text/plain\r\n\r\nhello compat")
	protected, err := ProtectWith(ctx, raw, "alice@example.org", []string{"bob@example.org"}, ProtectOptions{
		Sign:         true,
		Encrypt:      true,
		AllowWeakKey: true,
	}, func(ctx context.Context, _ []string) (map[string][]*smx509.Certificate, error) {
		require.True(t, AllowWeakKeySize(ctx))
		return map[string][]*smx509.Certificate{"bob@example.org": {bobCert}}, nil
	})
	require.NoError(t, err)
	require.NotEmpty(t, recProv.allowFlags)
	for _, f := range recProv.allowFlags {
		require.True(t, f)
	}

	wkErr := &WeakKeySizeError{Subject: "alice@example.org", KeyAlgo: "RSA", KeyBits: 1024, MinBits: 2048}
	bobProv := &softwareProvider{
		identities: []RawIdentity{{DER: bobCert.Raw}},
		keys:       map[string]*rsa.PrivateKey{CertSHA256(bobCert.Raw): bobKey},
		trustErr:   wkErr,
	}
	opened, err := OpenForRead(context.WithValue(t.Context(), providerKey{}, bobProv), protected)
	require.NoError(t, err)
	var gotWK *WeakKeySizeError
	require.ErrorAs(t, opened.VerifyErrCause, &gotWK)
	require.Equal(t, 1024, gotWK.KeyBits)
	require.True(t, errors.Is(opened.VerifyErrCause, ErrWeakKeySize))
}

func TestInspectCMSMetadata(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	makeCert := func(email, cn string, serial int64) (*rsa.PrivateKey, *smx509.Certificate) {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		tmpl := &x509.Certificate{
			SerialNumber:   big.NewInt(serial),
			Subject:        pkix.Name{CommonName: cn},
			EmailAddresses: []string{email},
			NotBefore:      now.Add(-time.Hour),
			NotAfter:       now.Add(24 * time.Hour),
			KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
		require.NoError(t, err)
		cert, err := ParseCertificate(der)
		require.NoError(t, err)
		return k, cert
	}

	aliceKey, aliceCert := makeCert("alice@example.org", "Alice", 201)
	bobKey, bobCert := makeCert("bob@example.org", "Bob", 202)

	aliceProv := &softwareProvider{
		identities: []RawIdentity{{DER: aliceCert.Raw, Hardware: false}},
		keys:       map[string]*rsa.PrivateKey{CertSHA256(aliceCert.Raw): aliceKey},
	}
	bobProv := &softwareProvider{
		identities: []RawIdentity{{DER: bobCert.Raw, Hardware: true}},
		keys:       map[string]*rsa.PrivateKey{CertSHA256(bobCert.Raw): bobKey},
	}

	raw := []byte("From: alice@example.org\r\nTo: bob@example.org\r\nSubject: Metadata\r\nContent-Type: text/plain\r\n\r\nsecret payload")
	protected, err := ProtectWith(context.WithValue(t.Context(), providerKey{}, aliceProv), raw, "alice@example.org", []string{"bob@example.org"}, ProtectOptions{
		Sign:    true,
		Encrypt: true,
	}, func(_ context.Context, _ []string) (map[string][]*smx509.Certificate, error) {
		return map[string][]*smx509.Certificate{"bob@example.org": {bobCert}}, nil
	})
	require.NoError(t, err)

	opened, err := Open(context.WithValue(t.Context(), providerKey{}, bobProv), protected)
	require.NoError(t, err)
	require.True(t, opened.Encrypted)
	require.NotNil(t, opened.Encryption)
	require.Equal(t, 2, opened.Encryption.RecipientCount) // sender + recipient
	require.NotEmpty(t, opened.Encryption.ContentCipher)
	require.Equal(t, "RSA (PKCS#1 v1.5)", opened.Encryption.KeyEncryptionAlgo)
	require.True(t, opened.Encryption.DecryptHardware)
	require.Equal(t, CertSHA256(bobCert.Raw), CertSHA256(opened.Encryption.DecryptCert))

	require.NotNil(t, opened.Signature)
	require.Equal(t, "enveloped", opened.Signature.Format)
	require.Equal(t, "SHA-256", opened.Signature.DigestAlgo)
	require.NotEmpty(t, opened.Signature.SignatureAlgo)
	require.False(t, opened.Signature.SigningTime.IsZero())
	require.Equal(t, "alice@example.org", opened.Signature.ClaimedFrom)
	require.True(t, opened.Signature.CryptOK)
	require.True(t, opened.Signature.TrustOK)
	require.True(t, opened.Signature.SenderMatched)
	require.False(t, opened.Signature.WeakKeyCompat)

	// Untrusted verification must preserve CryptOK=true, TrustOK=false, SenderMatched=true.
	untrustedProv := &softwareProvider{
		identities: bobProv.identities,
		keys:       bobProv.keys,
		trustErr:   errors.New("untrusted root"),
	}
	unverified, err := OpenForRead(WithAllowWeakKeySize(context.WithValue(t.Context(), providerKey{}, untrustedProv), true), protected)
	require.NoError(t, err)
	require.NotEmpty(t, unverified.VerifyErr)
	require.NotNil(t, unverified.Signature)
	require.True(t, unverified.Signature.CryptOK)
	require.False(t, unverified.Signature.TrustOK)
	require.True(t, unverified.Signature.SenderMatched)
	require.True(t, unverified.Signature.WeakKeyCompat)

	// Signed-only (opaque) message + indefinite-length BER normalization.
	signedOnly, err := ProtectWith(context.WithValue(t.Context(), providerKey{}, aliceProv), raw, "alice@example.org", nil, ProtectOptions{
		Sign: true,
	}, nil)
	require.NoError(t, err)
	openedOpaque, err := Open(context.WithValue(t.Context(), providerKey{}, aliceProv), signedOnly)
	require.NoError(t, err)
	require.NotNil(t, openedOpaque.Signature)
	require.Equal(t, "opaque", openedOpaque.Signature.Format)

	msgOpaque, err := mail.ReadMessage(bytes.NewReader(signedOnly))
	require.NoError(t, err)
	cmsDER, err := readCMS(msgOpaque)
	require.NoError(t, err)
	var ci cmsContentInfo
	_, err = asn1.Unmarshal(cmsDER, &ci)
	require.NoError(t, err)
	berCI := []byte{0x30, 0x80, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02, 0xa0, 0x80}
	berCI = append(berCI, ci.Content.Bytes...)
	berCI = append(berCI, 0x00, 0x00, 0x00, 0x00)
	dAlg, sAlg, sigTime := inspectSignedDER(berCI)
	require.Equal(t, "SHA-256", dAlg)
	require.NotEmpty(t, sAlg)
	require.False(t, sigTime.IsZero())

	// Detached multipart/signed message must report Format == "detached".
	detEntity := []byte("Content-Type: text/plain\r\n\r\ndetached body")
	detSD, err := pkcs7.NewSignedData(detEntity)
	require.NoError(t, err)
	detSD.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	require.NoError(t, detSD.AddSigner(aliceCert, aliceKey, pkcs7.SignerInfoConfig{}))
	detSD.Detach()
	detSig, err := detSD.Finish()
	require.NoError(t, err)
	detRaw := "From: alice@example.org\r\nContent-Type: multipart/signed; protocol=\"application/pkcs7-signature\"; boundary=part\r\n\r\n--part\r\n" +
		string(detEntity) + "\r\n--part\r\nContent-Type: application/pkcs7-signature\r\nContent-Transfer-Encoding: base64\r\n\r\n" +
		base64.StdEncoding.EncodeToString(detSig) + "\r\n--part--\r\n"
	openedDet, err := Open(context.WithValue(t.Context(), providerKey{}, aliceProv), []byte(detRaw))
	require.NoError(t, err)
	require.NotNil(t, openedDet.Signature)
	require.Equal(t, "detached", openedDet.Signature.Format)
	require.Equal(t, "SHA-256", openedDet.Signature.DigestAlgo)
	require.True(t, openedDet.Signature.CryptOK)
	require.True(t, openedDet.Signature.TrustOK)
	require.True(t, openedDet.Signature.SenderMatched)
}
