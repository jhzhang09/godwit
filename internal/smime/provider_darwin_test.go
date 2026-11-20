//go:build darwin

package smime

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/emmansun/gmsm/pkcs7"
	"github.com/emmansun/gmsm/smx509"
	"github.com/stretchr/testify/require"
)

func TestDarwinProviderPureGo(t *testing.T) {
	require.True(t, Supported())

	sess := NewSession(t.Context())
	p := newPlatformProvider(true)
	t.Cleanup(func() { _ = p.Close() })

	// 查询本机智能卡列表不应崩溃也不应弹出系统窗口。
	t0 := time.Now()
	ders, err := p.Identities(t.Context())
	coldDur := time.Since(t0)
	require.NoError(t, err)
	t1 := time.Now()
	warmDers, err := p.Identities(t.Context())
	warmDur := time.Since(t1)
	require.NoError(t, err)
	require.Equal(t, len(ders), len(warmDers))
	t.Logf("darwin smart-card identities found: %d (cold=%s, warm=%s)", len(ders), coldDur, warmDur)
	for i, id := range ders {
		cert, err := ParseCertificate(id.DER)
		require.NoError(t, err)
		var email string
		if len(cert.EmailAddresses) > 0 {
			email = cert.EmailAddresses[0]
		} else {
			for _, attr := range cert.Subject.Names {
				if attr.Type.String() == "1.2.840.113549.1.9.1" {
					if v, ok := attr.Value.(string); ok {
						email = v
						break
					}
				}
			}
		}
		var trustErr error
		if email != "" {
			trustErr = p.VerifyTrust(t.Context(), "sign", email, [][]byte{id.DER})
			if id.Hardware {
				require.NoError(t, trustErr, "identity[%d] %s", i, email)
			}
		}
		hash, err := p.DigestAlgorithm(t.Context(), id.DER)
		require.NoError(t, err)
		t.Logf("identity[%d] hw=%v email=%s trusted=%v digest=%v", i, id.Hardware, email, trustErr == nil, hash)
	}
	found, err := p.FindCertificates(t.Context(), "jhzhang@tendyron.com")
	require.NoError(t, err)
	t.Logf("darwin system cert lookup jhzhang@tendyron.com: %d", len(found))

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(101),
		EmailAddresses: []string{"untrusted@example.org"},
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)

	err = p.VerifyTrust(t.Context(), "sign", "untrusted@example.org", [][]byte{der})
	require.Error(t, err)

	cert, err := smx509.ParseCertificate(der)
	require.NoError(t, err)
	content := []byte("Content-Type: text/plain\r\n\r\nhello purego")
	sd, err := pkcs7.NewSignedData(content)
	require.NoError(t, err)
	sd.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	require.NoError(t, sd.AddSigner(cert, priv, pkcs7.SignerInfoConfig{}))
	cms, err := sd.Finish()
	require.NoError(t, err)

	// 自签名未受信任证书和被篡改的签名均应被拦截。
	_, err = sess.OpenCMS(t.Context(), "untrusted@example.org", cms)
	require.Error(t, err)

	tampered := make([]byte, len(cms))
	copy(tampered, cms)
	tampered[len(tampered)-1] ^= 0xff
	_, err = sess.OpenCMS(t.Context(), "untrusted@example.org", tampered)
	require.Error(t, err)
}
