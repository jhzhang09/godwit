package smime

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"time"
)

// EncryptionInfo describes the CMS EnvelopedData parameters and local identity
// used to decrypt a protected message.
type EncryptionInfo struct {
	ContentCipher     string
	KeyEncryptionAlgo string
	RecipientCount    int
	DecryptCert       []byte
	DecryptHardware   bool
}

// SignatureInfo describes the CMS SignedData parameters and per-check outcomes
// observed when verifying a signed message.
type SignatureInfo struct {
	Format        string // "detached", "opaque", "enveloped"
	DigestAlgo    string
	SignatureAlgo string
	SigningTime   time.Time
	ClaimedFrom   string
	CryptOK       bool
	TrustOK       bool
	SenderMatched bool
	WeakKeyCompat bool
}

var (
	oidSignedData      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidEnvelopedData   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	oidAttrSigningTime = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
)

type cmsContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

type cmsEncryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
}

type cmsAttribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

func inspectEnvelopedDER(der []byte) (cipher, keyAlgo string, rcptCount int) {
	norm := normalizeBERToDER(der)
	var ci cmsContentInfo
	if _, err := asn1.Unmarshal(norm, &ci); err != nil || !ci.ContentType.Equal(oidEnvelopedData) {
		return "", "", 0
	}
	elems, err := splitSequenceElems(ci.Content.Bytes)
	if err != nil || len(elems) < 3 {
		return "", "", 0
	}
	idx := 1 // skip version
	if idx < len(elems) && elems[idx].Class == asn1.ClassContextSpecific && elems[idx].Tag == 0 {
		idx++ // skip optional originatorInfo
	}
	if idx < len(elems) {
		rcpts, err := splitContainerElems(elems[idx].FullBytes)
		if err == nil {
			rcptCount = len(rcpts)
			for _, r := range rcpts {
				if k := inspectRecipientKeyAlgo(r); k != "" {
					keyAlgo = k
					break
				}
			}
		}
		idx++
	}
	if idx < len(elems) {
		var eci cmsEncryptedContentInfo
		if _, err := asn1.Unmarshal(elems[idx].FullBytes, &eci); err == nil {
			cipher = contentCipherName(eci.ContentEncryptionAlgorithm.Algorithm)
		}
	}
	return cipher, keyAlgo, rcptCount
}

func inspectRecipientKeyAlgo(raw asn1.RawValue) string {
	switch raw.Class {
	case asn1.ClassUniversal:
		if raw.Tag != asn1.TagSequence {
			return ""
		}
		// KeyTransRecipientInfo ::= SEQUENCE { version, rid, keyEncryptionAlgorithm, encryptedKey }
		elems, err := splitContainerElems(raw.FullBytes)
		if err != nil || len(elems) < 3 {
			return ""
		}
		var alg pkix.AlgorithmIdentifier
		if _, err := asn1.Unmarshal(elems[2].FullBytes, &alg); err == nil {
			return keyEncryptionAlgoName(alg.Algorithm)
		}
	case asn1.ClassContextSpecific:
		switch raw.Tag {
		case 1: // KeyAgreeRecipientInfo
			elems, err := splitContainerElems(raw.FullBytes)
			if err == nil {
				for _, e := range elems {
					if e.Class == asn1.ClassUniversal && e.Tag == asn1.TagSequence {
						var alg pkix.AlgorithmIdentifier
						if _, err := asn1.Unmarshal(e.FullBytes, &alg); err == nil {
							if name := keyEncryptionAlgoName(alg.Algorithm); name != "" {
								return name
							}
						}
					}
				}
			}
			return "ECDH"
		case 2:
			return "KEK"
		case 3:
			return "Password"
		}
	}
	return ""
}

func inspectSignedDER(der []byte) (digestAlgo, sigAlgo string, signingTime time.Time) {
	norm := normalizeBERToDER(der)
	var ci cmsContentInfo
	if _, err := asn1.Unmarshal(norm, &ci); err != nil || !ci.ContentType.Equal(oidSignedData) {
		return "", "", time.Time{}
	}
	elems, err := splitSequenceElems(ci.Content.Bytes)
	if err != nil || len(elems) < 4 {
		return "", "", time.Time{}
	}
	// elems[1] is digestAlgorithms SET OF AlgorithmIdentifier
	if dalgs, err := splitContainerElems(elems[1].FullBytes); err == nil && len(dalgs) > 0 {
		var alg pkix.AlgorithmIdentifier
		if _, err := asn1.Unmarshal(dalgs[0].FullBytes, &alg); err == nil {
			digestAlgo = digestAlgoName(alg.Algorithm)
		}
	}
	// Last universal SET in SignedData is signerInfos.
	var signerSet *asn1.RawValue
	for i := len(elems) - 1; i >= 3; i-- {
		if elems[i].Class == asn1.ClassUniversal && elems[i].Tag == asn1.TagSet {
			signerSet = &elems[i]
			break
		}
	}
	if signerSet == nil {
		return digestAlgo, "", time.Time{}
	}
	signers, err := splitContainerElems(signerSet.FullBytes)
	if err != nil || len(signers) == 0 {
		return digestAlgo, "", time.Time{}
	}
	siElems, err := splitContainerElems(signers[0].FullBytes)
	if err != nil || len(siElems) < 5 {
		return digestAlgo, "", time.Time{}
	}
	// SignerInfo: version(0), sid(1), digestAlgorithm(2), [0] signedAttrs(opt), signatureAlgorithm, signature
	var dAlg pkix.AlgorithmIdentifier
	if _, err := asn1.Unmarshal(siElems[2].FullBytes, &dAlg); err == nil {
		if name := digestAlgoName(dAlg.Algorithm); name != "" {
			digestAlgo = name
		}
	}
	idx := 3
	if idx < len(siElems) && siElems[idx].Class == asn1.ClassContextSpecific && siElems[idx].Tag == 0 {
		signingTime = parseSigningTimeAttr(siElems[idx].Bytes)
		idx++
	}
	if idx < len(siElems) {
		var sAlg pkix.AlgorithmIdentifier
		if _, err := asn1.Unmarshal(siElems[idx].FullBytes, &sAlg); err == nil {
			sigAlgo = signatureAlgoName(sAlg.Algorithm)
		}
	}
	if digestAlgo == "" {
		digestAlgo = digestFromSigAlgo(sigAlgo)
	}
	return digestAlgo, sigAlgo, signingTime
}

func parseSigningTimeAttr(attrsBytes []byte) time.Time {
	rest := attrsBytes
	for len(rest) > 0 {
		var raw asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &raw)
		if err != nil {
			return time.Time{}
		}
		var attr cmsAttribute
		if _, err := asn1.Unmarshal(raw.FullBytes, &attr); err != nil {
			continue
		}
		if !attr.Type.Equal(oidAttrSigningTime) {
			continue
		}
		var t time.Time
		if _, err := asn1.Unmarshal(attr.Values.Bytes, &t); err == nil && !t.IsZero() {
			return t
		}
	}
	return time.Time{}
}

func splitSequenceElems(seqBytes []byte) ([]asn1.RawValue, error) {
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(seqBytes, &raw); err != nil {
		return nil, err
	}
	return splitContainerElems(raw.FullBytes)
}

func splitContainerElems(full []byte) ([]asn1.RawValue, error) {
	var outer asn1.RawValue
	if _, err := asn1.Unmarshal(full, &outer); err != nil {
		return nil, err
	}
	var out []asn1.RawValue
	rest := outer.Bytes
	for len(rest) > 0 {
		var el asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &el)
		if err != nil {
			return nil, err
		}
		out = append(out, el)
	}
	return out, nil
}

// normalizeBERToDER converts indefinite-length BER constructed TLVs into
// definite-length DER so standard Go encoding/asn1 can inspect Apple Mail CMS.
func normalizeBERToDER(in []byte) []byte {
	if len(in) == 0 {
		return in
	}
	out, rest, ok := berNodeToDER(in, 0)
	if !ok || len(rest) != 0 {
		return in
	}
	return out
}

func berNodeToDER(in []byte, depth int) (out, rest []byte, ok bool) {
	if depth > 64 || len(in) < 2 {
		return nil, nil, false
	}
	// Read identifier octets.
	i := 0
	tag0 := in[i]
	i++
	if tag0&0x1f == 0x1f {
		for {
			if i >= len(in) {
				return nil, nil, false
			}
			b := in[i]
			i++
			if b&0x80 == 0 {
				break
			}
		}
	}
	if i >= len(in) {
		return nil, nil, false
	}
	tagBytes := in[:i]
	constructed := tag0&0x20 != 0

	lenByte := in[i]
	i++
	if lenByte == 0x80 {
		if !constructed {
			return nil, nil, false
		}
		var body bytes.Buffer
		cur := in[i:]
		for {
			if len(cur) < 2 {
				return nil, nil, false
			}
			if cur[0] == 0x00 && cur[1] == 0x00 {
				cur = cur[2:]
				break
			}
			child, next, childOK := berNodeToDER(cur, depth+1)
			if !childOK {
				return nil, nil, false
			}
			body.Write(child)
			cur = next
		}
		return wrapDER(tagBytes, body.Bytes()), cur, true
	}

	var length int
	if lenByte&0x80 == 0 {
		length = int(lenByte)
	} else {
		n := int(lenByte & 0x7f)
		if n == 0 || n > 4 || i+n > len(in) {
			return nil, nil, false
		}
		for k := range n {
			length = (length << 8) | int(in[i+k])
		}
		i += n
	}
	if length < 0 || i+length > len(in) {
		return nil, nil, false
	}
	val := in[i : i+length]
	rest = in[i+length:]
	if !constructed {
		return wrapDER(tagBytes, val), rest, true
	}
	var body bytes.Buffer
	cur := val
	for len(cur) > 0 {
		child, next, childOK := berNodeToDER(cur, depth+1)
		if !childOK {
			return wrapDER(tagBytes, val), rest, true
		}
		body.Write(child)
		cur = next
	}
	return wrapDER(tagBytes, body.Bytes()), rest, true
}

func wrapDER(tagBytes, val []byte) []byte {
	n := len(val)
	var lenBuf [5]byte
	var lenSlice []byte
	switch {
	case n < 0x80:
		lenBuf[0] = byte(n)
		lenSlice = lenBuf[:1]
	case n <= 0xff:
		lenBuf[0] = 0x81
		lenBuf[1] = byte(n)
		lenSlice = lenBuf[:2]
	case n <= 0xffff:
		lenBuf[0] = 0x82
		binary.BigEndian.PutUint16(lenBuf[1:3], uint16(n))
		lenSlice = lenBuf[:3]
	case n <= 0xffffff:
		lenBuf[0] = 0x83
		lenBuf[1] = byte(n >> 16)
		lenBuf[2] = byte(n >> 8)
		lenBuf[3] = byte(n)
		lenSlice = lenBuf[:4]
	default:
		lenBuf[0] = 0x84
		binary.BigEndian.PutUint32(lenBuf[1:5], uint32(n))
		lenSlice = lenBuf[:5]
	}
	out := make([]byte, 0, len(tagBytes)+len(lenSlice)+len(val))
	out = append(out, tagBytes...)
	out = append(out, lenSlice...)
	out = append(out, val...)
	return out
}

func contentCipherName(oid asn1.ObjectIdentifier) string {
	switch oid.String() {
	case "2.16.840.1.101.3.4.1.42":
		return "AES-256-CBC"
	case "2.16.840.1.101.3.4.1.22":
		return "AES-192-CBC"
	case "2.16.840.1.101.3.4.1.2":
		return "AES-128-CBC"
	case "2.16.840.1.101.3.4.1.46":
		return "AES-256-GCM"
	case "2.16.840.1.101.3.4.1.6":
		return "AES-128-GCM"
	case "1.2.840.113549.3.7":
		return "3DES-CBC"
	case "1.3.14.3.2.7":
		return "DES-CBC"
	case "1.2.840.113549.3.2":
		return "RC2-CBC"
	case "1.2.156.10197.1.104.2":
		return "SM4-CBC"
	case "1.2.156.10197.1.104.8":
		return "SM4-GCM"
	default:
		return oid.String()
	}
}

func keyEncryptionAlgoName(oid asn1.ObjectIdentifier) string {
	switch oid.String() {
	case "1.2.840.113549.1.1.1":
		return "RSA (PKCS#1 v1.5)"
	case "1.2.840.113549.1.1.7":
		return "RSA-OAEP"
	case "1.2.840.10045.2.1", "1.2.840.113549.1.9.16.3.5", "1.3.133.16.840.63.0.2":
		return "ECDH"
	case "1.2.156.10197.1.301":
		return "SM2"
	default:
		return oid.String()
	}
}

func digestAlgoName(oid asn1.ObjectIdentifier) string {
	switch oid.String() {
	case "2.16.840.1.101.3.4.2.1":
		return "SHA-256"
	case "2.16.840.1.101.3.4.2.2":
		return "SHA-384"
	case "2.16.840.1.101.3.4.2.3":
		return "SHA-512"
	case "2.16.840.1.101.3.4.2.4":
		return "SHA-224"
	case "1.3.14.3.2.26":
		return "SHA-1"
	case "1.2.840.113549.2.5":
		return "MD5"
	case "1.2.156.10197.1.401":
		return "SM3"
	default:
		return oid.String()
	}
}

func signatureAlgoName(oid asn1.ObjectIdentifier) string {
	switch oid.String() {
	case "1.2.840.113549.1.1.1":
		return "RSA"
	case "1.2.840.113549.1.1.5":
		return "SHA1-RSA"
	case "1.2.840.113549.1.1.11":
		return "SHA256-RSA"
	case "1.2.840.113549.1.1.12":
		return "SHA384-RSA"
	case "1.2.840.113549.1.1.13":
		return "SHA512-RSA"
	case "1.2.840.113549.1.1.10":
		return "RSA-PSS"
	case "1.2.840.10045.4.1":
		return "ECDSA-SHA1"
	case "1.2.840.10045.4.3.2":
		return "ECDSA-SHA256"
	case "1.2.840.10045.4.3.3":
		return "ECDSA-SHA384"
	case "1.2.840.10045.4.3.4":
		return "ECDSA-SHA512"
	case "1.2.840.10045.2.1":
		return "ECDSA"
	case "1.2.156.10197.1.501":
		return "SM2-SM3"
	default:
		return oid.String()
	}
}

func digestFromSigAlgo(sigAlgo string) string {
	switch sigAlgo {
	case "SHA256-RSA", "ECDSA-SHA256":
		return "SHA-256"
	case "SHA384-RSA", "ECDSA-SHA384":
		return "SHA-384"
	case "SHA512-RSA", "ECDSA-SHA512":
		return "SHA-512"
	case "SHA1-RSA", "ECDSA-SHA1":
		return "SHA-1"
	case "SM2-SM3":
		return "SM3"
	default:
		return ""
	}
}
