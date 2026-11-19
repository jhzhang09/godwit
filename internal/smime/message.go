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
	Entity    []byte
	Encrypted bool
	Signer    string
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
		return nil, errors.New("无效的 S/MIME 分隔符")
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
	return nil, errors.New("分离签名必须包含正文与一个签名")
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
		return nil, errors.New("不支持的 CMS 传输编码")
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
	return nil, errors.New("请插入此邮件收件人的硬件 Key")
}

func verify(ctx context.Context, p *pkcs7.PKCS7, from string) error {
	if err := p.Verify(); err != nil {
		return fmt.Errorf("S/MIME 签名无效: %w", err)
	}
	signer := p.GetOnlySigner()
	if signer == nil {
		return errors.New("无法确定唯一的 S/MIME 签名人")
	}
	if err := trust(ctx, "sign", from, signer, p.Certificates); err != nil {
		return fmt.Errorf("签名完整，但发件人证书未通过验证: %w", err)
	}
	return nil
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
	outer, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return Opened{}, err
	}
	from := ""
	if fields := outer.Header["From"]; len(fields) == 1 {
		from = singleSender(fields[0])
	}
	return openMIME(ctx, from, raw, 0, Opened{})
}

// OpenCMS 对已拆出的单层 application/pkcs7-mime 字节直接解封并验签，避免重复下载整封邮件。
func OpenCMS(ctx context.Context, fromHeader string, der []byte) (Opened, error) {
	from := singleSender(fromHeader)
	var result Opened
	inner, err := unwrapCMS(ctx, from, der, nil, &result)
	if err != nil {
		return Opened{}, err
	}
	return openMIME(ctx, from, inner, 1, result)
}

func openMIME(ctx context.Context, from string, raw []byte, startDepth int, result Opened) (Opened, error) {
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
				return Opened{}, errors.New("不支持的分离签名协议")
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
				return Opened{}, errors.New("无效的 S/MIME 签名部分")
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
				return Opened{}, errors.New("邮件最外层不是 S/MIME 信封或签名")
			}
			result.Entity = raw
			return result, nil
		}
		raw, err = unwrapCMS(ctx, from, der, detached, &result)
		if err != nil {
			return Opened{}, err
		}
	}
	return Opened{}, errors.New("S/MIME 嵌套过深")
}

func unwrapCMS(ctx context.Context, from string, der, detached []byte, result *Opened) ([]byte, error) {
	readerSession := ctx.Value(sessionKey{}) != nil
	// 系统解码器会拼齐 BER 分段的签名正文；部分 Apple 邮件含多个 OCTET STRING。
	// 当会话启用且已识别为 SignedData 时直接交由系统验签，跳过 Go 侧全量 ASN.1 解析。
	if readerSession && isCMSSignedData(der) {
		if from == "" {
			return nil, errors.New("签名邮件缺少唯一的发件邮箱")
		}
		content, err := verifyCMS(ctx, from, der, detached)
		if err != nil {
			return nil, err
		}
		result.Signer = from
		return content, nil
	}
	p, err := pkcs7.Parse(der)
	// 名称和 MIME 参数都不能证明签名有效，仍须验证原始 CMS 及证书。
	signed := err == nil && len(p.Signers) > 0
	if signed {
		_, envelopeErr := p.GetRecipients()
		signed = envelopeErr != nil
	}
	if (readerSession && signed) || (err != nil && err.Error() == "x509: negative serial number") {
		if from == "" {
			return nil, errors.New("签名邮件缺少唯一的发件邮箱")
		}
		content, err := verifyCMS(ctx, from, der, detached)
		if err != nil {
			return nil, err
		}
		result.Signer = from
		return content, nil
	}
	if err != nil {
		return nil, err
	}
	if _, e := p.GetRecipients(); e == nil {
		if detached != nil {
			return nil, errors.New("签名部分含有意外的加密信封")
		}
		raw, err := openEnvelope(ctx, p)
		if err != nil {
			return nil, err
		}
		result.Encrypted = true
		if len(p.Signers) > 0 {
			p.Content = raw
			if err := verify(ctx, p, from); err != nil {
				return nil, err
			}
			result.Signer = from
		}
		return raw, nil
	}
	if detached != nil {
		if len(p.Content) > 0 {
			return nil, errors.New("分离签名中含有另一份正文")
		}
		p.Content = detached
	}
	if err := verify(ctx, p, from); err != nil {
		return nil, err
	}
	result.Signer = from
	return p.Content, nil
}

func signatureType(s string) bool {
	return strings.EqualFold(s, "application/pkcs7-signature") || strings.EqualFold(s, "application/x-pkcs7-signature")
}

// 只移动 MIME 实体头，保留外层地址、主题、Message-ID 和会话标识。
func splitOutgoing(raw []byte) (outer, entity []byte, err error) {
	headers, body, ok := bytes.Cut(raw, []byte("\r\n\r\n"))
	if !ok {
		return nil, nil, errors.New("邮件缺少 MIME 头")
	}
	var content bool
	for line := range bytes.SplitSeq(headers, []byte("\r\n")) {
		if len(line) == 0 {
			return nil, nil, errors.New("空邮件头")
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

// Protect 在入队之前完成签名和加密，重发直接使用同一份 MIME。
func Protect(ctx context.Context, raw []byte, from string, rcpts []string, sign, encrypt bool, lookup Lookup) ([]byte, error) {
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
	if encrypt {
		var other []string
		for _, recipient := range rcpts {
			if !strings.EqualFold(recipient, from) {
				other = append(other, recipient)
			}
		}
		var cards map[string][]*smx509.Certificate
		if len(other) > 0 {
			cards, err = lookup(ctx, other)
			if err != nil {
				return nil, err
			}
		}
		for _, addr := range rcpts {
			if strings.EqualFold(addr, from) {
				continue
			}
			var found *smx509.Certificate
			var reason error
			for _, cert := range cards[strings.ToLower(addr)] {
				if _, ok := cert.PublicKey.(*rsa.PublicKey); !ok {
					continue
				}
				if err := trust(ctx, "encrypt", addr, cert, nil); err != nil {
					reason = err
					continue
				}
				if found == nil || cert.NotBefore.After(found.NotBefore) {
					found = cert
				}
			}
			if found == nil {
				if reason != nil {
					return nil, fmt.Errorf("%s: %w", addr, reason)
				}
				return nil, fmt.Errorf("邮箱名片中缺少 %s 的可用加密证书", addr)
			}
			recipients = append(recipients, found)
		}
		self, err := ownCertificate(ctx, from, "encrypt")
		if err != nil {
			return nil, err
		}
		recipients = append(recipients, self)
	}
	if sign {
		cert, err := ownCertificate(ctx, from, "sign")
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
			return nil, errors.New("硬件 Key 没有可用的签名算法")
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
	if encrypt {
		der, err := pkcs7.Encrypt(pkcs.AES256CBC, entity, recipients)
		if err != nil {
			return nil, err
		}
		entity = wrap(der, "enveloped-data")
	}
	return append(outer, entity...), nil
}
