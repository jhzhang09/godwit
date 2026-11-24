package app

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/godwit-email/godwit/internal/smime"
)

func TestReaderSMIMECertChainDialog(t *testing.T) {
	if !smime.Supported() {
		t.Skip("S/MIME not supported on this platform")
	}
	now := time.Now().UTC()
	genCert := func(cn string, email string, isCA bool, parent *x509.Certificate, parentKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey, []byte) {
		t.Helper()
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
		if err != nil {
			t.Fatal(err)
		}
		tpl := &x509.Certificate{
			SerialNumber:          serial,
			Subject:               pkix.Name{CommonName: cn, Organization: []string{"TENDYRON"}},
			NotBefore:             now.Add(-time.Hour),
			NotAfter:              now.Add(48 * time.Hour),
			BasicConstraintsValid: true,
			IsCA:                  isCA,
			SubjectKeyId:          serial.Bytes(),
		}
		if isCA {
			tpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		} else {
			tpl.EmailAddresses = []string{email}
			tpl.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
			tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}
		}
		if parent == nil {
			parent = tpl
			parentKey = key
		}
		der, err := x509.CreateCertificate(rand.Reader, tpl, parent, &key.PublicKey, parentKey)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return parsed, key, der
	}

	rootCert, rootKey, rootDER := genCert("Tendyron Root CA", "", true, nil, nil)
	erpCert, erpKey, erpDER := genCert("Tendyron ERP CA", "", true, rootCert, rootKey)
	_, _, bobDER := genCert("Bob Verified", "bob@example.com", false, erpCert, erpKey)

	h, accs := mailHarness(t, nil, "alice@example.com")
	h.app.cards = smime.NewSession(h.app.ctx)

	h.app.mail.reader.openCMSFull = func(ctx context.Context, fromHeader string, der []byte) (smime.Opened, error) {
		return smime.Opened{
			Entity:      []byte("Content-Type: text/html; charset=utf-8\r\n\r\n<p>Trusted chain content</p>"),
			Encrypted:   true,
			Signer:      "bob@example.com",
			SignerCert:  bobDER,
			SignerChain: [][]byte{bobDER, erpDER, rootDER},
		}, nil
	}

	msg := h.deliverOne(accs[0], makeRawSMIME("Bob <bob@example.com>", accs[0].Email, "chain@x", "Chain Trust", "opaque-cms"))
	h.openThread(msg.ThreadID)
	wantShow := fmt.Sprintf("ShowSecureBody %d", msg.ID)
	h.until("verified signature banner rendered", func() bool {
		return callIndex(h.plat.Calls(), wantShow) >= 0 && h.tt.HasText("签名已验证 · bob@example.com")
	})

	h.click("查看证书")
	h.until("cert dialog open", func() bool {
		return h.tt.HasText("证书详情") && h.tt.HasText("Bob Verified")
	})

	h.see("签名已验证且证书受信任")
	h.see("信任由根证书「Tendyron Root CA」经证书链传递")
	h.see("证书链")
	h.see("根证书")
	h.see("系统已信任")
	h.see("信任已传递")
	h.see("已信任")
	h.see("中间证书")
	h.see("当前证书")
	h.see("Tendyron Root CA")
	h.see("Tendyron ERP CA")
	h.see("Bob Verified")
}

func TestReaderSMIMECertChainDialogFailedLeaf(t *testing.T) {
	if !smime.Supported() {
		t.Skip("S/MIME not supported on this platform")
	}
	rootDER, erpDER, bobDER := makeTestChainDER(t)

	h, accs := mailHarness(t, nil, "alice@example.com")
	h.app.cards = smime.NewSession(h.app.ctx)
	h.app.mail.reader.openCMSFull = func(ctx context.Context, fromHeader string, der []byte) (smime.Opened, error) {
		return smime.Opened{
			Entity:           []byte("Content-Type: text/html; charset=utf-8\r\n\r\n<p>Failed leaf</p>"),
			Encrypted:        true,
			UnverifiedCert:   bobDER,
			SignerChain:      [][]byte{bobDER, erpDER, rootDER},
			SignerChainNodes: smime.BuildCertChainWithIssues([][]byte{bobDER, erpDER, rootDER}, [][]string{{smime.CertIssueExpired, smime.CertIssueEmailMismatch}, nil, nil}, false),
			VerifyErr:        "certificate has expired or is not yet valid",
			VerifyErrCause:   &smime.TrustError{Issues: []string{smime.CertIssueExpired, smime.CertIssueEmailMismatch}},
		}, nil
	}

	msg := h.deliverOne(accs[0], makeRawSMIME("Bob <bob@example.com>", accs[0].Email, "chain-fail@x", "Chain Fail", "opaque-cms"))
	h.openThread(msg.ThreadID)
	h.until("unverified banner rendered", func() bool {
		return h.tt.HasText("显示详细信息")
	})
	h.click("显示详细信息")
	h.until("detail panel open", func() bool {
		return h.tt.HasText("查看证书")
	})
	h.click("查看证书")
	h.until("cert dialog open", func() bool {
		return h.tt.HasText("证书详情") && h.tt.HasText("Bob Expired")
	})

	h.see("系统已信任")
	h.see("信任已传递")
	h.see("校验未通过")
	h.see("证书已过期或尚未生效；证书邮箱与发件人不匹配")
}

func TestReaderSMIMECertChainDialogUntrustedRoot(t *testing.T) {
	if !smime.Supported() {
		t.Skip("S/MIME not supported on this platform")
	}
	rootDER, erpDER, bobDER := makeTestChainDER(t)

	h, accs := mailHarness(t, nil, "alice2@example.com")
	h.app.cards = smime.NewSession(h.app.ctx)
	h.app.mail.reader.openCMSFull = func(ctx context.Context, fromHeader string, der []byte) (smime.Opened, error) {
		return smime.Opened{
			Entity:           []byte("Content-Type: text/html; charset=utf-8\r\n\r\n<p>Untrusted root</p>"),
			Encrypted:        true,
			UnverifiedCert:   bobDER,
			SignerChain:      [][]byte{bobDER, erpDER, rootDER},
			SignerChainNodes: smime.BuildCertChainWithIssues([][]byte{bobDER, erpDER, rootDER}, [][]string{nil, nil, {smime.CertIssueUntrustedRoot}}, false),
			VerifyErr:        "root certificate is not trusted",
			VerifyErrCause:   &smime.TrustError{Issues: []string{smime.CertIssueUntrustedRoot}},
		}, nil
	}
	msg := h.deliverOne(accs[0], makeRawSMIME("Bob <bob@example.com>", accs[0].Email, "chain-untrusted@x", "Chain Untrusted", "opaque-cms"))
	h.openThread(msg.ThreadID)
	h.until("unverified banner rendered", func() bool {
		return h.tt.HasText("显示详细信息")
	})
	h.click("显示详细信息")
	h.until("detail panel open", func() bool {
		return h.tt.HasText("查看证书")
	})
	h.click("查看证书")
	h.until("cert dialog open", func() bool {
		return h.tt.HasText("证书详情") && h.tt.HasText("Bob Expired")
	})

	h.see("根证书不受信任")
	h.see("未受信任")
	h.see("根证书未被系统信任")
}

func makeTestChainDER(t *testing.T) (rootDER, erpDER, bobDER []byte) {
	t.Helper()
	now := time.Now().UTC()
	genCert := func(cn string, email string, isCA bool, parent *x509.Certificate, parentKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey, []byte) {
		t.Helper()
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
		if err != nil {
			t.Fatal(err)
		}
		tpl := &x509.Certificate{
			SerialNumber:          serial,
			Subject:               pkix.Name{CommonName: cn, Organization: []string{"TENDYRON"}},
			NotBefore:             now.Add(-time.Hour),
			NotAfter:              now.Add(48 * time.Hour),
			BasicConstraintsValid: true,
			IsCA:                  isCA,
			SubjectKeyId:          serial.Bytes(),
		}
		if isCA {
			tpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		} else {
			tpl.EmailAddresses = []string{email}
			tpl.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
			tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}
		}
		if parent == nil {
			parent = tpl
			parentKey = key
		}
		der, err := x509.CreateCertificate(rand.Reader, tpl, parent, &key.PublicKey, parentKey)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return parsed, key, der
	}

	rootCert, rootKey, rootDER := genCert("Tendyron Root CA", "", true, nil, nil)
	erpCert, erpKey, erpDER := genCert("Tendyron ERP CA", "", true, rootCert, rootKey)
	_, _, bobDER = genCert("Bob Expired", "bob@example.com", false, erpCert, erpKey)
	return rootDER, erpDER, bobDER
}
