package smime

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"time"

	"github.com/emmansun/gmsm/smx509"
)

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
	for _, ext := range t.Extensions {
		switch ext.Id.String() {
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
