//go:build darwin

package smime

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/require"
)

func TestDarwinChainTrustPropagation(t *testing.T) {
	d, err := loadDarwinAPI()
	require.NoError(t, err)

	now := time.Now().UTC()
	genCA := func(cn string, parent *x509.Certificate, parentKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey, []byte) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
		require.NoError(t, err)
		tpl := &x509.Certificate{
			SerialNumber:          serial,
			Subject:               pkix.Name{CommonName: cn, Organization: []string{"TENDYRON"}},
			NotBefore:             now.Add(-time.Hour),
			NotAfter:              now.Add(48 * time.Hour),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
			SubjectKeyId:          serial.Bytes(),
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

	rootCert, rootKey, rootDER := genCA("Tendyron Root CA", nil, nil)
	erpCert, erpKey, erpDER := genCA("Tendyron ERP CA", rootCert, rootKey)

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	leafSerial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	require.NoError(t, err)
	leafTpl := &x509.Certificate{
		SerialNumber:          leafSerial,
		Subject:               pkix.Name{CommonName: "T0849", Organization: []string{"TENDYRON"}},
		EmailAddresses:        []string{"jhzhang@tendyron.com"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(48 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
		BasicConstraintsValid: true,
		SubjectKeyId:          leafSerial.Bytes(),
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, erpCert, &leafKey.PublicKey, erpKey)
	require.NoError(t, err)

	makeCertArray := func(ders [][]byte) uintptr {
		refs := make([]uintptr, 0, len(ders))
		for _, der := range ders {
			data := d.cfData(der)
			require.NotZero(t, data)
			ref := d.secCertificateCreateWithData(0, data)
			d.release(data)
			require.NotZero(t, ref)
			refs = append(refs, ref)
		}
		arr := d.cfArrayCreate(0, unsafe.Pointer(&refs[0]), len(refs), d.kCFTypeArrayCB)
		for _, r := range refs {
			d.release(r)
		}
		return arr
	}

	certArr := makeCertArray([][]byte{leafDER, erpDER})
	defer d.release(certArr)
	anchorArr := makeCertArray([][]byte{rootDER})
	defer d.release(anchorArr)

	emailCF := d.cfString("jhzhang@tendyron.com")
	defer d.release(emailCF)
	props := d.cfDict(
		[]uintptr{d.kSecPolicyName, d.kSecPolicyKUDigitalSig},
		[]uintptr{emailCF, d.kCFBooleanTrue},
	)
	defer d.release(props)
	policy := d.secPolicyCreateWithProperties(d.kSecPolicyAppleSMIME, props)
	require.NotZero(t, policy)
	defer d.release(policy)

	var trust uintptr
	require.Zero(t, d.secTrustCreateWithCertificates(certArr, policy, &trust))
	defer d.release(trust)
	require.Zero(t, d.secTrustSetAnchorCertificates(trust, anchorArr))
	_ = d.secTrustSetNetworkFetchAllowed(trust, false)

	require.NoError(t, d.evaluateTrust(trust, false))

	chainDER := d.copyChainDER(trust)
	require.Len(t, chainDER, 3)

	nodes := BuildCertChain(chainDER)
	require.Len(t, nodes, 3)

	require.Equal(t, "Tendyron Root CA", nodes[0].Subject)
	require.Equal(t, "root", nodes[0].Role)
	require.True(t, nodes[0].SelfSigned)

	require.Equal(t, "Tendyron ERP CA", nodes[1].Subject)
	require.Equal(t, "intermediate", nodes[1].Role)
	require.False(t, nodes[1].SelfSigned)

	require.Equal(t, "T0849", nodes[2].Subject)
	require.Equal(t, "leaf", nodes[2].Role)
	require.False(t, nodes[2].SelfSigned)

	// Without the root anchor in the slice, the intermediate CA is not mislabeled as root.
	partial := BuildCertChain([][]byte{leafDER, erpDER})
	require.Len(t, partial, 2)
	require.Equal(t, "intermediate", partial[0].Role)
	require.False(t, partial[0].SelfSigned)
	require.Equal(t, "leaf", partial[1].Role)
}
