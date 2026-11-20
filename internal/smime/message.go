package smime

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/mail"
	"strings"

	_ "github.com/emersion/go-message/charset" // 与收件解析器使用相同的显示名字符集。
	messagemail "github.com/emersion/go-message/mail"

	"github.com/emmansun/gmsm/pkcs"
	"github.com/emmansun/gmsm/pkcs7"
	"github.com/emmansun/gmsm/smx509"
)

type Opened struct {
	Entity         []byte
	Encrypted      bool
	Signer         string
	SignerCert     []byte
	UnverifiedCert []byte
	VerifyErr      string
}

func IsCMSPart(contentType, name string) bool {
	switch strings.ToLower(contentType) {
	case "application/pkcs7-mime", "application/x-pkcs7-mime":
		return true
	case "application/octet-stream":
		return strings.EqualFold(name, "smime.p7m")
	}
	return false
}

func IsPart(contentType, name string) bool {
	if IsCMSPart(contentType, name) {
		return true
	}
	switch strings.ToLower(contentType) {
	case "application/pkcs7-signature", "application/x-pkcs7-signature":
		return true
	case "application/octet-stream":
		return strings.EqualFold(name, "smime.p7s")
	}
	return false
}

// splitSigned 保留第一段的原始 MIME 头、折行、传输编码及正文；分隔线前的 CRLF 属于分隔线。
func splitSigned(body []byte, boundary string) ([][]byte, error) {
	if boundary == "" || len(boundary) > 70 {
		return nil, errors.New("invalid S/MIME boundary")
	}
	marker := []byte("--" + boundary)
	end := append(bytes.Clone(marker), '-', '-')
	var parts [][]byte
	start := -1
	for pos := 0; pos < len(body); {
		n := bytes.IndexByte(body[pos:], '\n')
		if n < 0 {
			n = len(body) - pos
		} else {
			n++
		}
		line := bytes.TrimRight(body[pos:pos+n], " \t\r\n")
		closing := bytes.Equal(line, end)
		if closing || bytes.Equal(line, marker) {
			if start >= 0 {
				part := bytes.TrimSuffix(body[start:pos], []byte("\n"))
				part = bytes.TrimSuffix(part, []byte("\r"))
				parts = append(parts, part)
			}
			if closing && len(parts) == 2 {
				return parts, nil
			}
			if closing || len(parts) >= 2 {
				break
			}
			start = pos + n
		}
		pos += n
	}
	return nil, errors.New("detached signature must contain body and signature")
}

func readCMS(m *mail.Message) ([]byte, error) {
	var r io.Reader = m.Body
	switch strings.ToLower(strings.TrimSpace(m.Header.Get("Content-Transfer-Encoding"))) {
	case "base64":
		data, err := io.ReadAll(r)
		if err != nil {
			return nil, err
		}
		// MIME 允许折行，部分客户端也省略最后一组的填充。保持 CMS 原始字节不变。
		data = bytes.Map(func(c rune) rune {
			switch c {
			case ' ', '\t', '\r', '\n':
				return -1
			}
			return c
		}, data)
		encoding := base64.StdEncoding
		if !bytes.HasSuffix(data, []byte("=")) {
			encoding = base64.RawStdEncoding
		}
		decoded := make([]byte, encoding.DecodedLen(len(data)))
		n, err := encoding.Decode(decoded, data)
		if err != nil {
			return nil, fmt.Errorf("CMS Base64: %w", err)
		}
		return decoded[:n], nil
	case "", "binary", "7bit", "8bit":
	default:
		return nil, errors.New("unsupported CMS Content-Transfer-Encoding")
	}
	return io.ReadAll(r)
}

func openEnvelope(ctx context.Context, p *pkcs7.PKCS7) ([]byte, error) {
	recipients, err := p.GetRecipients()
	if err != nil {
		return nil, err
	}
	certs, err := identities(ctx)
	if err != nil {
		return nil, err
	}
	for _, c := range certs {
		for _, r := range recipients {
			if (r.SerialNumber != nil && c.SerialNumber.Cmp(r.SerialNumber) == 0 && bytes.Equal(c.RawIssuer, r.RawIssuer)) || (len(r.SubjectKeyIdentifier) > 0 && bytes.Equal(c.SubjectKeyId, r.SubjectKeyIdentifier)) {
				return p.Decrypt(c, key{ctx, c})
			}
		}
	}
	return nil, errors.New("no matching personal S/MIME certificate or private key found for encrypted message")
}

func verify(ctx context.Context, p *pkcs7.PKCS7, from string) ([]byte, error) {
	signer := p.GetOnlySigner()
	var signerDER []byte
	if signer != nil {
		signerDER = bytes.Clone(signer.Raw)
	}
	if err := p.Verify(); err != nil {
		return signerDER, fmt.Errorf("invalid S/MIME signature: %w", err)
	}
	if signer == nil {
		return nil, errors.New("unable to identify unique S/MIME signer")
	}
	if err := trust(ctx, "sign", from, signer, p.Certificates); err != nil {
		return signerDER, fmt.Errorf("signature intact, but sender certificate failed verification: %w", err)
	}
	return signerDER, nil
}

var oidCMSSignedData = []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02}

func singleSender(field string) string {
	addrs, err := messagemail.ParseAddressList(field)
	if err != nil || len(addrs) != 1 {
		return ""
	}
	return addrs[0].Address
}

// isCMSSignedData reports whether a CMS ContentInfo begins with the SignedData OID,
// supporting both DER definite-length and BER indefinite-length outer encodings.
func isCMSSignedData(der []byte) bool {
	if len(der) < 2+len(oidCMSSignedData) || der[0] != 0x30 {
		return false
	}
	offset := 2
	if b := der[1]; b != 0x80 && b&0x80 != 0 {
		n := int(b & 0x7f)
		if n == 0 || n > 4 || len(der) < 2+n+len(oidCMSSignedData) {
			return false
		}
		offset += n
	}
	return len(der) >= offset+len(oidCMSSignedData) && bytes.Equal(der[offset:offset+len(oidCMSSignedData)], oidCMSSignedData)
}

// Open 只对用户正在查看的原件执行，所有签名层均验证成功后才交付正文。
func Open(ctx context.Context, raw []byte) (Opened, error) {
	return openRaw(ctx, raw, false)
}

// OpenForRead decrypts and unwraps raw for reading; signature/trust failures are recorded in
// Opened.VerifyErr instead of discarding decrypted content.
func OpenForRead(ctx context.Context, raw []byte) (Opened, error) {
	return openRaw(ctx, raw, true)
}

func openRaw(ctx context.Context, raw []byte, allowUnverified bool) (Opened, error) {
	outer, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return Opened{}, err
	}
	from := ""
	if fields := outer.Header["From"]; len(fields) == 1 {
		from = singleSender(fields[0])
	}
	return openMIME(ctx, from, raw, 0, Opened{}, allowUnverified)
}

// OpenCMS 对已拆出的单层 application/pkcs7-mime 字节直接解封并验签，避免重复下载整封邮件。
func OpenCMS(ctx context.Context, fromHeader string, der []byte) (Opened, error) {
	return openCMSRaw(ctx, fromHeader, der, false)
}

// OpenCMSForRead unwraps and decrypts a single application/pkcs7-mime part for reading;
// signature/trust failures are recorded in Opened.VerifyErr instead of discarding decrypted content.
func OpenCMSForRead(ctx context.Context, fromHeader string, der []byte) (Opened, error) {
	return openCMSRaw(ctx, fromHeader, der, true)
}

func openCMSRaw(ctx context.Context, fromHeader string, der []byte, allowUnverified bool) (Opened, error) {
	from := singleSender(fromHeader)
	var result Opened
	inner, err := unwrapCMS(ctx, from, der, nil, &result, allowUnverified)
	if err != nil {
		return Opened{}, err
	}
	return openMIME(ctx, from, inner, 1, result, allowUnverified)
}

func openMIME(ctx context.Context, from string, raw []byte, startDepth int, result Opened, allowUnverified bool) (Opened, error) {
	for depth := startDepth; depth < 12; depth++ {
		m, err := mail.ReadMessage(bytes.NewReader(raw))
		if err != nil {
			return Opened{}, err
		}
		ct, params, err := mime.ParseMediaType(m.Header.Get("Content-Type"))
		if err != nil && m.Header.Get("Content-Type") != "" {
			return Opened{}, err
		}
		if ct == "application/octet-stream" {
			_, disposition, _ := mime.ParseMediaType(m.Header.Get("Content-Disposition"))
			if strings.EqualFold(params["name"], "smime.p7m") || strings.EqualFold(disposition["filename"], "smime.p7m") {
				ct = "application/pkcs7-mime"
			}
		}
		var der, detached []byte
		switch ct {
		case "multipart/signed":
			if !signatureType(params["protocol"]) {
				return Opened{}, errors.New("unsupported detached signature protocol")
			}
			b, err := io.ReadAll(m.Body)
			if err != nil {
				return Opened{}, err
			}
			parts, err := splitSigned(b, params["boundary"])
			if err != nil {
				return Opened{}, err
			}
			sig, err := mail.ReadMessage(bytes.NewReader(parts[1]))
			if err != nil {
				return Opened{}, err
			}
			st, _, _ := mime.ParseMediaType(sig.Header.Get("Content-Type"))
			if !signatureType(st) {
				return Opened{}, errors.New("invalid S/MIME signature part")
			}
			detached = parts[0]
			der, err = readCMS(sig)
			if err != nil {
				return Opened{}, err
			}
		case "application/pkcs7-mime", "application/x-pkcs7-mime":
			der, err = readCMS(m)
			if err != nil {
				return Opened{}, err
			}
		default:
			if depth == 0 {
				return Opened{}, errors.New("outer message is not an S/MIME envelope or signature")
			}
			result.Entity = raw
			return result, nil
		}
		raw, err = unwrapCMS(ctx, from, der, detached, &result, allowUnverified)
		if err != nil {
			return Opened{}, err
		}
	}
	return Opened{}, errors.New("S/MIME nesting too deep")
}

func recordVerifyFailure(result *Opened, reason string, certDER []byte) {
	if result.VerifyErr == "" {
		result.VerifyErr = reason
	}
	result.Signer = ""
	result.SignerCert = nil
	if len(certDER) > 0 && len(result.UnverifiedCert) == 0 {
		result.UnverifiedCert = bytes.Clone(certDER)
	}
}

func unwrapCMS(ctx context.Context, from string, der, detached []byte, result *Opened, allowUnverified bool) ([]byte, error) {
	readerSession := ctx.Value(sessionKey{}) != nil
	runVerifyCMS := func() ([]byte, error) {
		if !allowUnverified && from == "" {
			return nil, errors.New("signed message lacks a unique sender address")
		}
		res, err := verifyCMS(ctx, from, der, detached)
		if err != nil {
			return nil, err
		}
		if res.verifyErr != nil {
			if !allowUnverified {
				return nil, res.verifyErr
			}
			recordVerifyFailure(result, res.verifyErr.Error(), res.signerDER)
			return res.content, nil
		}
		if result.VerifyErr == "" {
			result.Signer = from
			if len(res.signerDER) > 0 {
				result.SignerCert = res.signerDER
			}
		}
		return res.content, nil
	}
	// 系统解码器会拼齐 BER 分段的签名正文；部分 Apple 邮件含多个 OCTET STRING。
	// 当会话启用且已识别为 SignedData 时直接交由系统验签，跳过 Go 侧全量 ASN.1 解析。
	if readerSession && isCMSSignedData(der) {
		return runVerifyCMS()
	}
	p, err := pkcs7.Parse(der)
	// 名称和 MIME 参数都不能证明签名有效，仍须验证原始 CMS 及证书。
	signed := err == nil && len(p.Signers) > 0
	if signed {
		_, envelopeErr := p.GetRecipients()
		signed = envelopeErr != nil
	}
	if (readerSession && signed) || (err != nil && err.Error() == "x509: negative serial number") {
		return runVerifyCMS()
	}
	if err != nil {
		return nil, err
	}
	if _, e := p.GetRecipients(); e == nil {
		if detached != nil {
			return nil, errors.New("signed part unexpectedly contains an encrypted envelope")
		}
		raw, err := openEnvelope(ctx, p)
		if err != nil {
			return nil, err
		}
		result.Encrypted = true
		if len(p.Signers) > 0 {
			p.Content = raw
			signerDER, err := verify(ctx, p, from)
			if err != nil {
				if !allowUnverified {
					return nil, err
				}
				recordVerifyFailure(result, err.Error(), signerDER)
				return raw, nil
			}
			if result.VerifyErr == "" {
				result.Signer = from
				result.SignerCert = signerDER
			}
		}
		return raw, nil
	}
	if detached != nil {
		if len(p.Content) > 0 {
			return nil, errors.New("detached signature unexpectedly contains embedded content")
		}
		p.Content = detached
	}
	signerDER, err := verify(ctx, p, from)
	if err != nil {
		if !allowUnverified {
			return nil, err
		}
		recordVerifyFailure(result, err.Error(), signerDER)
		return p.Content, nil
	}
	if result.VerifyErr == "" {
		result.Signer = from
		result.SignerCert = signerDER
	}
	return p.Content, nil
}

func signatureType(s string) bool {
	return strings.EqualFold(s, "application/pkcs7-signature") || strings.EqualFold(s, "application/x-pkcs7-signature")
}

// 只移动 MIME 实体头，保留外层地址、主题、Message-ID 和会话标识。
func splitOutgoing(raw []byte) (outer, entity []byte, err error) {
	headers, body, ok := bytes.Cut(raw, []byte("\r\n\r\n"))
	if !ok {
		return nil, nil, errors.New("message missing MIME headers")
	}
	var content bool
	for line := range bytes.SplitSeq(headers, []byte("\r\n")) {
		if len(line) == 0 {
			return nil, nil, errors.New("empty MIME header line")
		}
		if line[0] != ' ' && line[0] != '\t' {
			content = strings.HasPrefix(strings.ToLower(string(line)), "content-")
		}
		if content {
			entity = append(entity, line...)
			entity = append(entity, '\r', '\n')
		} else {
			outer = append(outer, line...)
			outer = append(outer, '\r', '\n')
		}
	}
	entity = append(entity, '\r', '\n')
	return outer, append(entity, body...), nil
}

func wrap(der []byte, kind string) []byte {
	var out bytes.Buffer
	fmt.Fprintf(&out, "Content-Type: application/pkcs7-mime; smime-type=%s; name=\"smime.p7m\"\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=\"smime.p7m\"\r\n\r\n", kind)
	for len(der) > 0 {
		n := min(57, len(der))
		out.WriteString(base64.StdEncoding.EncodeToString(der[:n]))
		out.WriteString("\r\n")
		der = der[n:]
	}
	return out.Bytes()
}

type Lookup func(context.Context, []string) (map[string][]*smx509.Certificate, error)

// ProtectOptions configures signing, encrypting, and explicit certificate selection.
type ProtectOptions struct {
	Sign        bool
	Encrypt     bool
	OwnCertSHA  string
	PinnedCerts map[string]string // lower(addr) -> pinned SHA-256
}

// Protect 在入队之前完成签名和加密，重发直接使用同一份 MIME。
func Protect(ctx context.Context, raw []byte, from string, rcpts []string, sign, encrypt bool, lookup Lookup) ([]byte, error) {
	return ProtectWith(ctx, raw, from, rcpts, ProtectOptions{Sign: sign, Encrypt: encrypt}, lookup)
}

// ProtectWith signs and/or encrypts raw using standard OS/contact certificates and optional pinned SHA-256s.
func ProtectWith(ctx context.Context, raw []byte, from string, rcpts []string, opts ProtectOptions, lookup Lookup) ([]byte, error) {
	if ctx.Value(sessionKey{}) == nil && ctx.Value(providerKey{}) == nil {
		p := newPlatformProvider(false)
		defer p.Close()
		ctx = context.WithValue(ctx, providerKey{}, p)
	}
	outer, entity, err := splitOutgoing(raw)
	if err != nil {
		return nil, err
	}
	var recipients []*smx509.Certificate
	if opts.Encrypt {
		var other []string
		for _, recipient := range rcpts {
			if !strings.EqualFold(recipient, from) {
				other = append(other, recipient)
			}
		}
		var cards map[string][]*smx509.Certificate
		if len(other) > 0 && lookup != nil {
			cards, err = lookup(ctx, other)
			if err != nil {
				return nil, err
			}
		}
		for _, addr := range rcpts {
			if strings.EqualFold(addr, from) {
				continue
			}
			lowerAddr := strings.ToLower(addr)
			pinned := strings.ToLower(strings.TrimSpace(opts.PinnedCerts[lowerAddr]))
			var found *smx509.Certificate
			var reason error
			for _, cert := range cards[lowerAddr] {
				if _, ok := cert.PublicKey.(*rsa.PublicKey); !ok {
					continue
				}
				sum := CertSHA256(cert.Raw)
				if pinned != "" && sum != pinned {
					continue
				}
				if err := trust(ctx, "encrypt", addr, cert, nil); err != nil {
					reason = err
					continue
				}
				if found == nil || cert.NotBefore.After(found.NotBefore) ||
					(cert.NotBefore.Equal(found.NotBefore) && sum < CertSHA256(found.Raw)) {
					found = cert
				}
			}
			if found == nil {
				if reason != nil {
					return nil, fmt.Errorf("%s: %w", addr, reason)
				}
				if pinned != "" {
					return nil, fmt.Errorf("selected S/MIME encryption certificate for %s not found or untrusted", addr)
				}
				return nil, fmt.Errorf("no usable S/MIME encryption certificate found for recipient %s", addr)
			}
			recipients = append(recipients, found)
		}
		self, err := ownCertificate(ctx, from, "encrypt", opts.OwnCertSHA)
		if err != nil {
			return nil, err
		}
		recipients = append(recipients, self)
	}
	if opts.Sign {
		cert, err := ownCertificate(ctx, from, "sign", opts.OwnCertSHA)
		if err != nil {
			return nil, err
		}
		sd, err := pkcs7.NewSignedData(entity)
		if err != nil {
			return nil, err
		}
		hash, err := digestAlgorithm(ctx, cert.Raw)
		if err != nil {
			return nil, err
		}
		switch hash {
		case crypto.SHA256:
			sd.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
		case crypto.SHA1:
			sd.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA1)
		default:
			return nil, errors.New("selected S/MIME certificate has no usable signing algorithm")
		}
		if err = sd.AddSigner(cert, key{ctx, cert}, pkcs7.SignerInfoConfig{}); err != nil {
			return nil, err
		}
		der, err := sd.Finish()
		if err != nil {
			return nil, err
		}
		entity = wrap(der, "signed-data")
	}
	if opts.Encrypt {
		der, err := pkcs7.Encrypt(pkcs.AES256CBC, entity, recipients)
		if err != nil {
			return nil, err
		}
		entity = wrap(der, "enveloped-data")
	}
	return append(outer, entity...), nil
}
