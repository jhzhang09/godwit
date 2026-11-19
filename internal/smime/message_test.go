package smime

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"github.com/emmansun/gmsm/pkcs7"
	"github.com/stretchr/testify/require"
	"math/big"
	"net/mail"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/emmansun/gmsm/smx509"
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
	for _, tc := range []struct{ raw, reason string }{{raw, "邮箱与 other@example.org"}, {strings.Replace(raw, "From: other@example.org", "From: =?gb2312?B?suLK1A==?= <other@example.org>", 1), "邮箱与 other@example.org"}, {strings.Replace(raw, "original", "altered", 1), "签名无效"}} {
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
		{"other@example.org", cms, "邮箱与 other@example.org"},
		{"=?gb2312?B?suLK1A==?= <other@example.org>", cms, "邮箱与 other@example.org"},
		{"alice@example.org, bob@example.org", cms, "证书邮箱与  不匹配"},
		{"alice@example.org", bytes.ReplaceAll(cms, []byte("original"), []byte("altered!")), "签名无效"},
	} {
		result, err := OpenCMS(t.Context(), tc.from, tc.der)
		require.ErrorContains(t, err, tc.reason)
		require.Empty(t, result.Entity)
		require.Empty(t, result.Signer)
	}
}

type stubVerifyProvider struct{}

func (stubVerifyProvider) Identities(context.Context) ([][]byte, error) { return nil, nil }
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
func (stubVerifyProvider) VerifyCMS(context.Context, string, []byte, []byte) ([]byte, error) {
	return []byte("Content-Type: text/plain\r\n\r\nok"), nil
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
	got, err := verifyCMS(provCtx, "alice@example.org", []byte{0x30, 0x00}, nil)
	require.NoError(t, err)
	require.Equal(t, []byte("Content-Type: text/plain\r\n\r\nok"), got)

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
