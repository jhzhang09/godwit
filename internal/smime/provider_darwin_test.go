//go:build darwin

package smime

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"os/exec"
	"testing"
	"time"
	"unsafe"

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

func TestDarwinVerifyTrustWeakKeyCompat(t *testing.T) {
	d, err := loadDarwinAPI()
	require.NoError(t, err)

	evalChain := func(usage, email string, chainDER, anchorDER [][]byte, allowWeak bool) error {
		var usageKey uintptr
		switch usage {
		case "sign":
			usageKey = d.kSecPolicyKUDigitalSig
		case "encrypt":
			usageKey = d.kSecPolicyKUKeyEncipherment
		default:
			t.Fatalf("unknown usage %q", usage)
		}
		cfEmail := d.cfString(email)
		require.NotZero(t, cfEmail)
		defer d.release(cfEmail)

		certs := make([]uintptr, 0, len(chainDER))
		defer func() {
			for _, c := range certs {
				d.release(c)
			}
		}()
		for _, der := range chainDER {
			data := d.cfData(der)
			cert := d.secCertificateCreateWithData(0, data)
			d.release(data)
			require.NotZero(t, cert)
			certs = append(certs, cert)
		}
		cfCerts := d.cfArrayCreate(0, unsafe.Pointer(&certs[0]), len(certs), d.kCFTypeArrayCB)
		require.NotZero(t, cfCerts)
		defer d.release(cfCerts)

		props := d.cfDict([]uintptr{d.kSecPolicyName, usageKey}, []uintptr{cfEmail, d.kCFBooleanTrue})
		require.NotZero(t, props)
		defer d.release(props)

		policy := d.secPolicyCreateWithProperties(d.kSecPolicyAppleSMIME, props)
		require.NotZero(t, policy)
		defer d.release(policy)

		var trust uintptr
		st := d.secTrustCreateWithCertificates(cfCerts, policy, &trust)
		require.Equal(t, errSecSuccess, st)
		require.NotZero(t, trust)
		defer d.release(trust)

		anchors := make([]uintptr, 0, len(anchorDER))
		defer func() {
			for _, a := range anchors {
				d.release(a)
			}
		}()
		for _, der := range anchorDER {
			data := d.cfData(der)
			cert := d.secCertificateCreateWithData(0, data)
			d.release(data)
			require.NotZero(t, cert)
			anchors = append(anchors, cert)
		}
		var ancPtr unsafe.Pointer
		if len(anchors) > 0 {
			ancPtr = unsafe.Pointer(&anchors[0])
		}
		cfAnchors := d.cfArrayCreate(0, ancPtr, len(anchors), d.kCFTypeArrayCB)
		require.NotZero(t, cfAnchors)
		defer d.release(cfAnchors)

		require.Equal(t, errSecSuccess, d.secTrustSetAnchorCertificates(trust, cfAnchors))
		require.Equal(t, errSecSuccess, d.secTrustSetNetworkFetchAllowed(trust, false))
		_, _, evalErr := d.evaluateTrust(trust, allowWeak)
		return evalErr
	}

	now := time.Now()
	ca2kKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ca2kTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Corp CA 2048"},
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	ca2kDER, err := x509.CreateCertificate(rand.Reader, ca2kTmpl, ca2kTmpl, &ca2kKey.PublicKey, ca2kKey)
	require.NoError(t, err)
	ca2kCert, err := x509.ParseCertificate(ca2kDER)
	require.NoError(t, err)

	ca1kKey, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	ca1kTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Corp CA 1024"},
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	ca1kDER, err := x509.CreateCertificate(rand.Reader, ca1kTmpl, ca1kTmpl, &ca1kKey.PublicKey, ca1kKey)
	require.NoError(t, err)
	ca1kCert, err := x509.ParseCertificate(ca1kDER)
	require.NoError(t, err)

	key1k, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	mkLeaf := func(serial int64, cn, email string, nb, na time.Time, ku x509.KeyUsage, sigAlg x509.SignatureAlgorithm, parent *x509.Certificate, pKey any, pub any) []byte {
		tmpl := &x509.Certificate{
			SerialNumber:       big.NewInt(serial),
			Subject:            pkix.Name{CommonName: cn},
			EmailAddresses:     []string{email},
			NotBefore:          nb,
			NotAfter:           na,
			KeyUsage:           ku,
			ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
			SignatureAlgorithm: sigAlg,
		}
		if parent == nil {
			parent = tmpl
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, pKey)
		require.NoError(t, err)
		return der
	}

	validNB, validNA := now.Add(-time.Hour), now.Add(24*time.Hour)
	leafUnder2k := mkLeaf(10, "yczhang", "yczhang@tendyron.com", validNB, validNA, x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment, x509.SHA256WithRSA, ca2kCert, ca2kKey, &key1k.PublicKey)
	leafUnder1k := mkLeaf(11, "yczhang", "yczhang@tendyron.com", validNB, validNA, x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment, x509.SHA256WithRSA, ca1kCert, ca1kKey, &key1k.PublicKey)
	leafExpired := mkLeaf(12, "yczhang-exp", "yczhang@tendyron.com", now.Add(-48*time.Hour), now.Add(-time.Hour), x509.KeyUsageDigitalSignature, x509.SHA256WithRSA, ca2kCert, ca2kKey, &key1k.PublicKey)
	leafEncryptOnly := mkLeaf(13, "yczhang-enc", "yczhang@tendyron.com", validNB, validNA, x509.KeyUsageKeyEncipherment, x509.SHA256WithRSA, ca2kCert, ca2kKey, &key1k.PublicKey)
	leafSHA1 := mkLeaf(14, "yczhang-sha1", "yczhang@tendyron.com", validNB, validNA, x509.KeyUsageDigitalSignature, x509.SHA1WithRSA, ca2kCert, ca2kKey, &key1k.PublicKey)

	leaf512, err := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:512", "-nodes", "-keyout", "/dev/null",
		"-subj", "/CN=yczhang-512", "-addext", "subjectAltName=email:yczhang@tendyron.com",
		"-addext", "keyUsage=digitalSignature", "-days", "1", "-outform", "DER").Output()
	require.NoError(t, err)

	key224, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(t, err)
	leaf224 := mkLeaf(16, "yczhang-p224", "yczhang@tendyron.com", validNB, validNA, x509.KeyUsageDigitalSignature, x509.ECDSAWithSHA256, nil, key224, &key224.PublicKey)

	// 1. Anchored 1024-bit RSA leaf under 2048-bit CA.
	err = evalChain("sign", "yczhang@tendyron.com", [][]byte{leafUnder2k, ca2kDER}, [][]byte{ca2kDER}, false)
	var wk *WeakKeySizeError
	require.ErrorAs(t, err, &wk)
	require.Equal(t, "yczhang", wk.Subject)
	require.Equal(t, "RSA", wk.KeyAlgo)
	require.Equal(t, 1024, wk.KeyBits)
	require.Equal(t, 2048, wk.MinBits)
	require.NoError(t, evalChain("sign", "yczhang@tendyron.com", [][]byte{leafUnder2k, ca2kDER}, [][]byte{ca2kDER}, true))

	// 2. Anchored 1024-bit RSA leaf under 1024-bit CA.
	err = evalChain("sign", "yczhang@tendyron.com", [][]byte{leafUnder1k, ca1kDER}, [][]byte{ca1kDER}, false)
	require.ErrorAs(t, err, &wk)
	require.NoError(t, evalChain("sign", "yczhang@tendyron.com", [][]byte{leafUnder1k, ca1kDER}, [][]byte{ca1kDER}, true))

	// 3. Untrusted (no anchor) 1024-bit RSA leaf.
	err = evalChain("sign", "yczhang@tendyron.com", [][]byte{leafUnder2k, ca2kDER}, nil, false)
	require.ErrorAs(t, err, &wk)
	err = evalChain("sign", "yczhang@tendyron.com", [][]byte{leafUnder2k, ca2kDER}, nil, true)
	require.Error(t, err)
	require.False(t, errors.Is(err, ErrWeakKeySize), "untrusted 1024-bit chain must still fail trust even with compat on: %v", err)

	// 4. Expired anchored 1024-bit RSA leaf.
	err = evalChain("sign", "yczhang@tendyron.com", [][]byte{leafExpired, ca2kDER}, [][]byte{ca2kDER}, true)
	require.Error(t, err)
	require.False(t, errors.Is(err, ErrWeakKeySize))

	// 5. Wrong email anchored 1024-bit RSA leaf.
	err = evalChain("sign", "other@tendyron.com", [][]byte{leafUnder2k, ca2kDER}, [][]byte{ca2kDER}, true)
	require.Error(t, err)
	require.False(t, errors.Is(err, ErrWeakKeySize))

	// 6. Wrong KeyUsage (keyEncipherment checked as sign) anchored 1024-bit RSA leaf.
	err = evalChain("sign", "yczhang@tendyron.com", [][]byte{leafEncryptOnly, ca2kDER}, [][]byte{ca2kDER}, true)
	require.Error(t, err)
	require.False(t, errors.Is(err, ErrWeakKeySize))

	// 7. SHA-1 signed anchored 1024-bit RSA leaf.
	err = evalChain("sign", "yczhang@tendyron.com", [][]byte{leafSHA1, ca2kDER}, [][]byte{ca2kDER}, true)
	require.Error(t, err)
	require.False(t, errors.Is(err, ErrWeakKeySize))

	// 8. Anchored 512-bit RSA leaf must still fail with compat ON.
	err = evalChain("sign", "yczhang@tendyron.com", [][]byte{leaf512}, [][]byte{leaf512}, true)
	wk = nil
	require.ErrorAs(t, err, &wk)
	require.Equal(t, 512, wk.KeyBits)

	// 9. Anchored ECDSA P-224 leaf fails strict verification, then succeeds with compat ON.
	err = evalChain("sign", "yczhang@tendyron.com", [][]byte{leaf224}, [][]byte{leaf224}, false)
	wk = nil
	require.ErrorAs(t, err, &wk)
	require.Equal(t, "ECDSA", wk.KeyAlgo)
	require.Equal(t, 224, wk.KeyBits)
	require.Equal(t, 256, wk.MinBits)

	err = evalChain("sign", "yczhang@tendyron.com", [][]byte{leaf224}, [][]byte{leaf224}, true)
	require.NoError(t, err)

	// 10. Multi-failure anchored 1024-bit RSA leaf (expired + wrong email + SHA-1) with compat ON
	// reports all issues in deterministic priority order and marks only the leaf node failed.
	evalChainWithNodes := func(email string, chainDER, anchorDER [][]byte, allowWeak bool) ([]CertChainNode, error) {
		cfEmail := d.cfString(email)
		defer d.release(cfEmail)
		certs := make([]uintptr, 0, len(chainDER))
		defer func() {
			for _, c := range certs {
				d.release(c)
			}
		}()
		for _, der := range chainDER {
			data := d.cfData(der)
			cert := d.secCertificateCreateWithData(0, data)
			d.release(data)
			certs = append(certs, cert)
		}
		cfCerts := d.cfArrayCreate(0, unsafe.Pointer(&certs[0]), len(certs), d.kCFTypeArrayCB)
		defer d.release(cfCerts)
		props := d.cfDict([]uintptr{d.kSecPolicyName, d.kSecPolicyKUDigitalSig}, []uintptr{cfEmail, d.kCFBooleanTrue})
		defer d.release(props)
		policy := d.secPolicyCreateWithProperties(d.kSecPolicyAppleSMIME, props)
		defer d.release(policy)
		var trust uintptr
		require.Equal(t, errSecSuccess, d.secTrustCreateWithCertificates(cfCerts, policy, &trust))
		defer d.release(trust)
		anchors := make([]uintptr, 0, len(anchorDER))
		defer func() {
			for _, a := range anchors {
				d.release(a)
			}
		}()
		for _, der := range anchorDER {
			data := d.cfData(der)
			cert := d.secCertificateCreateWithData(0, data)
			d.release(data)
			anchors = append(anchors, cert)
		}
		var ancPtr unsafe.Pointer
		if len(anchors) > 0 {
			ancPtr = unsafe.Pointer(&anchors[0])
		}
		cfAnchors := d.cfArrayCreate(0, ancPtr, len(anchors), d.kCFTypeArrayCB)
		defer d.release(cfAnchors)
		require.Equal(t, errSecSuccess, d.secTrustSetAnchorCertificates(trust, cfAnchors))
		require.Equal(t, errSecSuccess, d.secTrustSetNetworkFetchAllowed(trust, false))
		_, nodes, evalErr := d.evaluateTrust(trust, allowWeak)
		return nodes, evalErr
	}

	leafMultiFail := mkLeaf(17, "yczhang-multi", "yczhang@tendyron.com", now.Add(-48*time.Hour), now.Add(-time.Hour), x509.KeyUsageDigitalSignature, x509.SHA1WithRSA, ca2kCert, ca2kKey, &key1k.PublicKey)
	nodes, err := evalChainWithNodes("other@tendyron.com", [][]byte{leafMultiFail, ca2kDER}, [][]byte{ca2kDER}, true)
	var te *TrustError
	require.ErrorAs(t, err, &te)
	require.Equal(t, []string{CertIssueExpired, CertIssueEmailMismatch, CertIssueWeakSignature}, te.Issues)
	require.Len(t, nodes, 2)
	require.Equal(t, CertChainStatusTrusted, nodes[0].Status)
	require.Equal(t, CertChainStatusFailed, nodes[1].Status)
	require.Equal(t, []string{CertIssueExpired, CertIssueEmailMismatch, CertIssueWeakSignature}, nodes[1].Issues)

	// 11. Untrusted root marks root failed with untrusted_root and leaf untrusted.
	nodes, err = evalChainWithNodes("yczhang@tendyron.com", [][]byte{leafUnder2k, ca2kDER}, nil, true)
	require.Error(t, err)
	require.Len(t, nodes, 2)
	require.Equal(t, CertChainStatusFailed, nodes[0].Status)
	require.Contains(t, nodes[0].Issues, CertIssueUntrustedRoot)
	require.Equal(t, CertChainStatusUntrusted, nodes[1].Status)
}
