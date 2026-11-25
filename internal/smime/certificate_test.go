package smime

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestFormatCertDisplayString(t *testing.T) {
	require.Equal(t, "brhuo@tendyron.com", formatCertDisplayString("  brhuo@tendyron.com  "))
	require.Equal(t, `brhuo@tendyron.com[\x00]`, formatCertDisplayString("brhuo@tendyron.com\x00"))
	require.Equal(t, `brhuo@tendyron.com[\x00×46]`, formatCertDisplayString("brhuo@tendyron.com"+strings.Repeat("\x00", 46)))
	require.Equal(t, `foo[\x0A]bar`, formatCertDisplayString("foo\nbar"))
}

func TestCertEmailsAndMatchesMailboxStrictNUL(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	now := time.Now().UTC()
	padded := "brhuo@tendyron.com" + strings.Repeat("\x00", 46)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: padded,
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1},
					Value: padded,
				},
			},
		},
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := ParseCertificate(der)
	require.NoError(t, err)

	require.Empty(t, CertEmails(cert))
	require.Equal(t, []string{`brhuo@tendyron.com[\x00×46]`}, CertDisplayEmails(cert))
	require.Equal(t, `brhuo@tendyron.com[\x00×46]`, CertDisplaySubject(cert))
	require.False(t, MatchesMailbox(cert, "brhuo@tendyron.com"))
	require.False(t, MatchesMailbox(cert, padded))
}

func TestBuildCertChainWithIssues(t *testing.T) {
	now := time.Now().UTC()
	genCert := func(cn string, isCA bool, parent *x509.Certificate, parentKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey, []byte) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
		require.NoError(t, err)
		tpl := &x509.Certificate{
			SerialNumber:          serial,
			Subject:               pkix.Name{CommonName: cn},
			NotBefore:             now.Add(-time.Hour),
			NotAfter:              now.Add(24 * time.Hour),
			BasicConstraintsValid: true,
			IsCA:                  isCA,
		}
		if isCA {
			tpl.KeyUsage = x509.KeyUsageCertSign
		} else {
			tpl.EmailAddresses = []string{"alice@example.com"}
			tpl.KeyUsage = x509.KeyUsageDigitalSignature
		}
		if parent == nil {
			parent = tpl
			parentKey = key
		}
		der, err := x509.CreateCertificate(rand.Reader, tpl, parent, &key.PublicKey, parentKey)
		require.NoError(t, err)
		parsed, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		return parsed, key, der
	}

	rootCert, rootKey, rootDER := genCert("Test Root CA", true, nil, nil)
	interCert, interKey, interDER := genCert("Test Inter CA", true, rootCert, rootKey)
	_, _, leafDER := genCert("Test Leaf", false, interCert, interKey)

	// 1. Trusted root + trusted intermediate + failed leaf.
	nodes := BuildCertChainWithIssues(
		[][]byte{leafDER, interDER, rootDER},
		[][]string{{CertIssueWeakSignature, CertIssueExpired, CertIssueEmailMismatch}, nil, nil},
		false,
	)
	require.Len(t, nodes, 3)
	require.Equal(t, CertChainStatusTrusted, nodes[0].Status)
	require.Empty(t, nodes[0].Issues)
	require.Equal(t, CertChainStatusTrusted, nodes[1].Status)
	require.Empty(t, nodes[1].Issues)
	require.Equal(t, CertChainStatusFailed, nodes[2].Status)
	require.Equal(t, []string{CertIssueExpired, CertIssueEmailMismatch, CertIssueWeakSignature}, nodes[2].Issues)

	// 2. Untrusted root -> root failed, intermediate and leaf untrusted.
	nodes = BuildCertChainWithIssues(
		[][]byte{leafDER, interDER, rootDER},
		[][]string{nil, nil, {CertIssueUntrustedRoot}},
		false,
	)
	require.Len(t, nodes, 3)
	require.Equal(t, CertChainStatusFailed, nodes[0].Status)
	require.Equal(t, []string{CertIssueUntrustedRoot}, nodes[0].Issues)
	require.Equal(t, CertChainStatusUntrusted, nodes[1].Status)
	require.Equal(t, CertChainStatusUntrusted, nodes[2].Status)

	// 3. Partial chain (missing root) -> intermediate failed/untrusted, leaf untrusted.
	nodes = BuildCertChainWithIssues(
		[][]byte{leafDER, interDER},
		[][]string{nil, {CertIssueMissingIssuer}},
		false,
	)
	require.Len(t, nodes, 2)
	require.Equal(t, CertChainStatusFailed, nodes[0].Status)
	require.Equal(t, []string{CertIssueMissingIssuer}, nodes[0].Issues)
	require.Equal(t, CertChainStatusUntrusted, nodes[1].Status)
}

func TestInspectCertificateDNAttrsAndOIDTranslation(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	now := time.Now().UTC()
	paddedEmail := "brhuo@tendyron.com" + strings.Repeat("\x00", 46)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(77),
		Subject: pkix.Name{
			ExtraNames: []pkix.AttributeTypeAndValue{
				{Type: asn1.ObjectIdentifier{2, 5, 4, 6}, Value: "CN"},
				{Type: asn1.ObjectIdentifier{2, 5, 4, 8}, Value: "BJ"},
				{Type: asn1.ObjectIdentifier{2, 5, 4, 7}, Value: "BEIJING"},
				{Type: asn1.ObjectIdentifier{2, 5, 4, 7}, Value: "BEIJING"},
				{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: "TENDYRON"},
				{Type: asn1.ObjectIdentifier{2, 5, 4, 11}, Value: "技术管理部"},
				{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "brhuo@tendyron.com\x00"},
				{Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}, Value: paddedEmail},
			},
		},
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := ParseCertificate(der)
	require.NoError(t, err)

	d := InspectCertificate(cert)
	require.NotContains(t, d.SubjectDN, "1.2.840.113549.1.9.1")
	require.Contains(t, d.SubjectDN, `emailAddress=brhuo@tendyron.com[\x00×46]`)
	require.Equal(t, []CertDNAttr{
		{Key: "CN", Value: `brhuo@tendyron.com[\x00]`},
		{Key: "emailAddress", Value: `brhuo@tendyron.com[\x00×46]`},
		{Key: "OU", Value: "技术管理部"},
		{Key: "O", Value: "TENDYRON"},
		{Key: "L", Value: "BEIJING"},
		{Key: "L", Value: "BEIJING"},
		{Key: "ST", Value: "BJ"},
		{Key: "C", Value: "CN"},
	}, d.SubjectAttrs)
}
