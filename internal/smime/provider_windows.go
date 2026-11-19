//go:build windows

package smime

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"fmt"
	"unsafe"

	"github.com/emmansun/gmsm/smx509"
	"golang.org/x/sys/windows"
)

const (
	ncryptImplHardwareFlag  uint32 = 0x00000001
	ncryptImplRemovableFlag uint32 = 0x00000008
	ncryptPadPKCS1Flag      uint32 = 0x00000002
	bcryptPadPKCS1          uint32 = 0x00000002

	ppImpType          uint32 = 3
	cryptImplHardware  uint32 = 1
	cryptImplRemovable uint32 = 8

	calgSHA1   uint32 = 0x00008004
	calgSHA256 uint32 = 0x0000800c
	hpHashVal  uint32 = 0x0002

	cmsgDetachedFlag        uint32 = 0x00000004
	cmsgContentParam        uint32 = 2
	cmsgSignerCountParam    uint32 = 5
	cmsgSignerCertInfoParam uint32 = 7
	cmsgCtrlVerifySignature uint32 = 1

	certChainCacheOnlyURLRetrieval uint32 = 0x00000004
)

var oidEmailProtection = []byte("1.3.6.1.5.5.7.3.4\x00")

var (
	modCrypt32  = windows.NewLazySystemDLL("crypt32.dll")
	modNCrypt   = windows.NewLazySystemDLL("ncrypt.dll")
	modAdvapi32 = windows.NewLazySystemDLL("advapi32.dll")

	procCertAddEncodedCertificateToStore   = modCrypt32.NewProc("CertAddEncodedCertificateToStore")
	procCertGetSubjectCertificateFromStore = modCrypt32.NewProc("CertGetSubjectCertificateFromStore")
	procCryptMsgOpenToDecode               = modCrypt32.NewProc("CryptMsgOpenToDecode")
	procCryptMsgUpdate                     = modCrypt32.NewProc("CryptMsgUpdate")
	procCryptMsgGetParam                   = modCrypt32.NewProc("CryptMsgGetParam")
	procCryptMsgControl                    = modCrypt32.NewProc("CryptMsgControl")
	procCryptMsgClose                      = modCrypt32.NewProc("CryptMsgClose")

	procNCryptFreeObject  = modNCrypt.NewProc("NCryptFreeObject")
	procNCryptGetProperty = modNCrypt.NewProc("NCryptGetProperty")
	procNCryptDecrypt     = modNCrypt.NewProc("NCryptDecrypt")
	procNCryptSignHash    = modNCrypt.NewProc("NCryptSignHash")

	procCryptGetProvParam = modAdvapi32.NewProc("CryptGetProvParam")
	procCryptGetUserKey   = modAdvapi32.NewProc("CryptGetUserKey")
	procCryptDestroyKey   = modAdvapi32.NewProc("CryptDestroyKey")
	procCryptDecrypt      = modAdvapi32.NewProc("CryptDecrypt")
	procCryptCreateHash   = modAdvapi32.NewProc("CryptCreateHash")
	procCryptDestroyHash  = modAdvapi32.NewProc("CryptDestroyHash")
	procCryptSetHashParam = modAdvapi32.NewProc("CryptSetHashParam")
	procCryptSignHashW    = modAdvapi32.NewProc("CryptSignHashW")
)

type bcryptPKCS1PaddingInfo struct {
	pszAlgID *uint16
}

type windowsIdentity struct {
	der        []byte
	certCtx    *windows.CertContext
	handle     windows.Handle
	keySpec    uint32
	callerFree bool
}

type windowsProvider struct {
	session    bool
	items      []windowsIdentity
	authorized map[string]bool
	failures   map[string]string
}

func platformSupported() bool { return true }

func newPlatformProvider(session bool) provider {
	return &windowsProvider{
		session:    session,
		authorized: map[string]bool{},
		failures:   map[string]string{},
	}
}

func (p *windowsProvider) releaseItems() {
	for _, it := range p.items {
		if it.callerFree && it.handle != 0 {
			if it.keySpec == windows.CERT_NCRYPT_KEY_SPEC {
				_, _, _ = procNCryptFreeObject.Call(uintptr(it.handle))
			} else {
				_ = windows.CryptReleaseContext(it.handle, 0)
			}
		}
		if it.certCtx != nil {
			_ = windows.CertFreeCertificateContext(it.certCtx)
		}
	}
	p.items = nil
	clear(p.authorized)
}

func (p *windowsProvider) reset() {
	p.releaseItems()
	clear(p.failures)
}

func ncryptGetUint32Prop(handle windows.Handle, prop string) (uint32, uint32) {
	name, err := windows.UTF16PtrFromString(prop)
	if err != nil {
		return 0, uint32(windows.ERROR_INVALID_PARAMETER)
	}
	var val, cb uint32
	r1, _, _ := procNCryptGetProperty.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(name)),
		uintptr(unsafe.Pointer(&val)),
		4,
		uintptr(unsafe.Pointer(&cb)),
		0,
	)
	return val, uint32(r1)
}

func isHardwareKey(handle windows.Handle, keySpec uint32) bool {
	if keySpec == windows.CERT_NCRYPT_KEY_SPEC {
		if impl, status := ncryptGetUint32Prop(handle, "Impl Type"); status == 0 {
			return impl&(ncryptImplHardwareFlag|ncryptImplRemovableFlag) != 0
		}
		name, err := windows.UTF16PtrFromString("Provider Handle")
		if err != nil {
			return false
		}
		var hProv windows.Handle
		var cb uint32
		r1, _, _ := procNCryptGetProperty.Call(
			uintptr(handle),
			uintptr(unsafe.Pointer(name)),
			uintptr(unsafe.Pointer(&hProv)),
			unsafe.Sizeof(hProv),
			uintptr(unsafe.Pointer(&cb)),
			0,
		)
		if uint32(r1) == 0 && hProv != 0 {
			defer func() { _, _, _ = procNCryptFreeObject.Call(uintptr(hProv)) }()
			if impl, status := ncryptGetUint32Prop(hProv, "Impl Type"); status == 0 {
				return impl&(ncryptImplHardwareFlag|ncryptImplRemovableFlag) != 0
			}
		}
		return false
	}
	var impl uint32
	cb := uint32(4)
	r1, _, _ := procCryptGetProvParam.Call(
		uintptr(handle),
		uintptr(ppImpType),
		uintptr(unsafe.Pointer(&impl)),
		uintptr(unsafe.Pointer(&cb)),
		0,
	)
	if r1 == 0 {
		return false
	}
	return impl&(cryptImplHardware|cryptImplRemovable) != 0
}

func (p *windowsProvider) ensureKeys() ([]windowsIdentity, error) {
	if len(p.items) > 0 {
		return p.items, nil
	}
	storeName, err := windows.UTF16PtrFromString("MY")
	if err != nil {
		return nil, err
	}
	store, err := windows.CertOpenSystemStore(0, storeName)
	if err != nil {
		return nil, err
	}
	defer windows.CertCloseStore(store, 0)

	var prev *windows.CertContext
	var items []windowsIdentity
	const flags = windows.CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG | windows.CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG
	for {
		ctx, err := windows.CertEnumCertificatesInStore(store, prev)
		if err != nil {
			if errors.Is(err, windows.Errno(windows.CRYPT_E_NOT_FOUND)) || errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
				break
			}
			for _, it := range items {
				if it.callerFree && it.handle != 0 {
					if it.keySpec == windows.CERT_NCRYPT_KEY_SPEC {
						_, _, _ = procNCryptFreeObject.Call(uintptr(it.handle))
					} else {
						_ = windows.CryptReleaseContext(it.handle, 0)
					}
				}
				if it.certCtx != nil {
					_ = windows.CertFreeCertificateContext(it.certCtx)
				}
			}
			return nil, err
		}
		prev = ctx
		var handle windows.Handle
		var keySpec uint32
		var callerFree bool
		if err := windows.CryptAcquireCertificatePrivateKey(ctx, flags, nil, &handle, &keySpec, &callerFree); err != nil {
			continue
		}
		if !isHardwareKey(handle, keySpec) {
			if callerFree && handle != 0 {
				if keySpec == windows.CERT_NCRYPT_KEY_SPEC {
					_, _, _ = procNCryptFreeObject.Call(uintptr(handle))
				} else {
					_ = windows.CryptReleaseContext(handle, 0)
				}
			}
			continue
		}
		var retainedCert *windows.CertContext
		if !callerFree {
			// Retain an independent key handle or keep a duplicated cert context so cached handles stay valid past CertCloseStore.
			var dupHandle windows.Handle
			var dupSpec uint32
			var dupFree bool
			if err := windows.CryptAcquireCertificatePrivateKey(ctx, flags, nil, &dupHandle, &dupSpec, &dupFree); err == nil && dupFree {
				handle, keySpec, callerFree = dupHandle, dupSpec, dupFree
			} else {
				retainedCert = windows.CertDuplicateCertificateContext(ctx)
			}
		}
		der := make([]byte, ctx.Length)
		copy(der, unsafe.Slice(ctx.EncodedCert, ctx.Length))
		items = append(items, windowsIdentity{
			der:        der,
			certCtx:    retainedCert,
			handle:     handle,
			keySpec:    keySpec,
			callerFree: callerFree,
		})
	}
	p.items = items
	return p.items, nil
}

func (p *windowsProvider) findKey(certDER []byte) (windowsIdentity, error) {
	items, err := p.ensureKeys()
	if err != nil {
		return windowsIdentity{}, err
	}
	for _, it := range items {
		if bytes.Equal(it.der, certDER) {
			return it, nil
		}
	}
	return windowsIdentity{}, errors.New("请插入与邮件证书匹配的硬件 Key")
}

func (p *windowsProvider) handleHardwareErr(idKey string, code uint32) error {
	if p.session && isWindowsCardRemoved(code) {
		p.reset()
	}
	err := windows.Errno(code)
	if p.session && isWindowsAuthFailure(code) {
		p.failures[idKey] = err.Error()
	}
	return fmt.Errorf("硬件操作失败 (0x%08x): %w", code, err)
}

func (p *windowsProvider) Identities(context.Context) ([][]byte, error) {
	items, err := p.ensureKeys()
	if err != nil {
		return nil, err
	}
	out := make([][]byte, len(items))
	for i, it := range items {
		out[i] = bytes.Clone(it.der)
	}
	return out, nil
}

func (p *windowsProvider) Prepare(_ context.Context, certDER, sealed []byte) error {
	idKey := string(certDER)
	if p.session && p.authorized[idKey] {
		if _, err := p.findKey(certDER); err == nil {
			return nil
		}
	}
	if _, err := p.Decrypt(context.Background(), certDER, sealed); err != nil {
		return err
	}
	return nil
}

func (p *windowsProvider) DigestAlgorithm(_ context.Context, certDER []byte) (crypto.Hash, error) {
	id, err := p.findKey(certDER)
	if err != nil {
		return 0, err
	}
	if reason, ok := p.failures[string(certDER)]; ok {
		return 0, errors.New(reason)
	}
	if id.keySpec == windows.CERT_NCRYPT_KEY_SPEC {
		return crypto.SHA256, nil
	}
	var hHash windows.Handle
	r1, _, _ := procCryptCreateHash.Call(uintptr(id.handle), uintptr(calgSHA256), 0, 0, uintptr(unsafe.Pointer(&hHash)))
	if r1 != 0 {
		_, _, _ = procCryptDestroyHash.Call(uintptr(hHash))
		return crypto.SHA256, nil
	}
	r1, _, e1 := procCryptCreateHash.Call(uintptr(id.handle), uintptr(calgSHA1), 0, 0, uintptr(unsafe.Pointer(&hHash)))
	if r1 != 0 {
		_, _, _ = procCryptDestroyHash.Call(uintptr(hHash))
		return crypto.SHA1, nil
	}
	_ = e1
	return 0, errors.New("硬件 Key 没有可用的签名算法")
}

func (p *windowsProvider) Sign(_ context.Context, certDER []byte, hash crypto.Hash, digest []byte) ([]byte, error) {
	id, err := p.findKey(certDER)
	if err != nil {
		return nil, err
	}
	idKey := string(certDER)
	if reason, ok := p.failures[idKey]; ok {
		return nil, errors.New(reason)
	}
	var algName string
	var calg uint32
	var wantLen int
	switch hash {
	case crypto.SHA256:
		algName, calg, wantLen = "SHA256", calgSHA256, 32
	case crypto.SHA1:
		algName, calg, wantLen = "SHA1", calgSHA1, 20
	default:
		return nil, errors.New("不支持的硬件签名摘要")
	}
	if len(digest) != wantLen {
		return nil, errors.New("签名摘要长度无效")
	}

	if id.keySpec == windows.CERT_NCRYPT_KEY_SPEC {
		algPtr, err := windows.UTF16PtrFromString(algName)
		if err != nil {
			return nil, err
		}
		pad := bcryptPKCS1PaddingInfo{pszAlgID: algPtr}
		var sigLen uint32
		r1, _, _ := procNCryptSignHash.Call(
			uintptr(id.handle),
			uintptr(unsafe.Pointer(&pad)),
			uintptr(unsafe.Pointer(&digest[0])),
			uintptr(len(digest)),
			0,
			0,
			uintptr(unsafe.Pointer(&sigLen)),
			uintptr(bcryptPadPKCS1),
		)
		if uint32(r1) != 0 {
			return nil, p.handleHardwareErr(idKey, uint32(r1))
		}
		sig := make([]byte, sigLen)
		r1, _, _ = procNCryptSignHash.Call(
			uintptr(id.handle),
			uintptr(unsafe.Pointer(&pad)),
			uintptr(unsafe.Pointer(&digest[0])),
			uintptr(len(digest)),
			uintptr(unsafe.Pointer(&sig[0])),
			uintptr(sigLen),
			uintptr(unsafe.Pointer(&sigLen)),
			uintptr(bcryptPadPKCS1),
		)
		if uint32(r1) != 0 {
			return nil, p.handleHardwareErr(idKey, uint32(r1))
		}
		if p.session {
			p.authorized[idKey] = true
		}
		return sig[:sigLen], nil
	}

	var hHash windows.Handle
	r1, _, e1 := procCryptCreateHash.Call(uintptr(id.handle), uintptr(calg), 0, 0, uintptr(unsafe.Pointer(&hHash)))
	if r1 == 0 {
		code := uint32(0)
		if errno, ok := e1.(windows.Errno); ok {
			code = uint32(errno)
		}
		if hash == crypto.SHA256 && code == uint32(windows.NTE_BAD_ALGID) {
			return nil, errors.New("硬件 Key 不支持 SHA-256 签名算法")
		}
		return nil, p.handleHardwareErr(idKey, code)
	}
	defer func() { _, _, _ = procCryptDestroyHash.Call(uintptr(hHash)) }()

	r1, _, e1 = procCryptSetHashParam.Call(uintptr(hHash), uintptr(hpHashVal), uintptr(unsafe.Pointer(&digest[0])), 0)
	if r1 == 0 {
		code := uint32(0)
		if errno, ok := e1.(windows.Errno); ok {
			code = uint32(errno)
		}
		return nil, p.handleHardwareErr(idKey, code)
	}
	var sigLen uint32
	r1, _, e1 = procCryptSignHashW.Call(uintptr(hHash), uintptr(id.keySpec), 0, 0, 0, uintptr(unsafe.Pointer(&sigLen)))
	if r1 == 0 {
		code := uint32(0)
		if errno, ok := e1.(windows.Errno); ok {
			code = uint32(errno)
		}
		return nil, p.handleHardwareErr(idKey, code)
	}
	sig := make([]byte, sigLen)
	r1, _, e1 = procCryptSignHashW.Call(uintptr(hHash), uintptr(id.keySpec), 0, 0, uintptr(unsafe.Pointer(&sig[0])), uintptr(unsafe.Pointer(&sigLen)))
	if r1 == 0 {
		code := uint32(0)
		if errno, ok := e1.(windows.Errno); ok {
			code = uint32(errno)
		}
		return nil, p.handleHardwareErr(idKey, code)
	}
	sig = sig[:sigLen]
	reverseBytes(sig)
	if p.session {
		p.authorized[idKey] = true
	}
	return sig, nil
}

func (p *windowsProvider) Decrypt(_ context.Context, certDER, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, errors.New("缺少硬件操作数据")
	}
	id, err := p.findKey(certDER)
	if err != nil {
		return nil, err
	}
	idKey := string(certDER)
	if reason, ok := p.failures[idKey]; ok {
		return nil, errors.New(reason)
	}

	if id.keySpec == windows.CERT_NCRYPT_KEY_SPEC {
		var outLen uint32
		r1, _, _ := procNCryptDecrypt.Call(
			uintptr(id.handle),
			uintptr(unsafe.Pointer(&ciphertext[0])),
			uintptr(len(ciphertext)),
			0,
			0,
			0,
			uintptr(unsafe.Pointer(&outLen)),
			uintptr(ncryptPadPKCS1Flag),
		)
		if uint32(r1) != 0 {
			return nil, p.handleHardwareErr(idKey, uint32(r1))
		}
		out := make([]byte, outLen)
		r1, _, _ = procNCryptDecrypt.Call(
			uintptr(id.handle),
			uintptr(unsafe.Pointer(&ciphertext[0])),
			uintptr(len(ciphertext)),
			0,
			uintptr(unsafe.Pointer(&out[0])),
			uintptr(outLen),
			uintptr(unsafe.Pointer(&outLen)),
			uintptr(ncryptPadPKCS1Flag),
		)
		if uint32(r1) != 0 {
			return nil, p.handleHardwareErr(idKey, uint32(r1))
		}
		if p.session {
			p.authorized[idKey] = true
		}
		return out[:outLen], nil
	}

	var hKey windows.Handle
	r1, _, e1 := procCryptGetUserKey.Call(uintptr(id.handle), uintptr(id.keySpec), uintptr(unsafe.Pointer(&hKey)))
	if r1 == 0 {
		code := uint32(0)
		if errno, ok := e1.(windows.Errno); ok {
			code = uint32(errno)
		}
		return nil, p.handleHardwareErr(idKey, code)
	}
	defer func() { _, _, _ = procCryptDestroyKey.Call(uintptr(hKey)) }()

	buf := bytes.Clone(ciphertext)
	reverseBytes(buf)
	dataLen := uint32(len(buf))
	r1, _, e1 = procCryptDecrypt.Call(uintptr(hKey), 0, 1, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&dataLen)))
	if r1 == 0 {
		code := uint32(0)
		if errno, ok := e1.(windows.Errno); ok {
			code = uint32(errno)
		}
		return nil, p.handleHardwareErr(idKey, code)
	}
	if p.session {
		p.authorized[idKey] = true
	}
	return buf[:dataLen], nil
}

func (p *windowsProvider) VerifyTrust(_ context.Context, usage, email string, certsDER [][]byte) error {
	if email == "" || len(certsDER) == 0 {
		return errors.New("缺少 S/MIME 证书或邮箱地址")
	}
	leaf, err := ParseCertificate(certsDER[0])
	if err != nil {
		return errors.New("无效的 X.509 证书")
	}
	if !MatchesMailbox(leaf, email) {
		return fmt.Errorf("证书邮箱与 %s 不匹配", email)
	}
	if leaf.KeyUsage != 0 {
		switch usage {
		case "sign":
			if leaf.KeyUsage&(smx509.KeyUsageDigitalSignature|smx509.KeyUsageContentCommitment) == 0 {
				return errors.New("证书不支持数字签名用途")
			}
		case "encrypt":
			if leaf.KeyUsage&smx509.KeyUsageKeyEncipherment == 0 {
				return errors.New("证书不支持密钥加密用途")
			}
		default:
			return errors.New("未知的证书用途")
		}
	}

	memStore, err := windows.CertOpenStore(windows.CERT_STORE_PROV_MEMORY, 0, 0, 0, 0)
	if err != nil {
		return err
	}
	defer windows.CertCloseStore(memStore, 0)

	var leafCtx *windows.CertContext
	for i, der := range certsDER {
		if len(der) == 0 {
			return errors.New("无效的 X.509 证书")
		}
		var ctx *windows.CertContext
		var outArg uintptr
		if i == 0 {
			outArg = uintptr(unsafe.Pointer(&ctx))
		}
		r1, _, e1 := procCertAddEncodedCertificateToStore.Call(
			uintptr(memStore),
			uintptr(windows.X509_ASN_ENCODING),
			uintptr(unsafe.Pointer(&der[0])),
			uintptr(len(der)),
			uintptr(windows.CERT_STORE_ADD_USE_EXISTING),
			outArg,
		)
		if r1 == 0 {
			return e1
		}
		if i == 0 {
			leafCtx = ctx
		}
	}
	if leafCtx == nil {
		return errors.New("无法加载待验证证书")
	}
	defer windows.CertFreeCertificateContext(leafCtx)

	oidPtr := &oidEmailProtection[0]
	var para windows.CertChainPara
	para.Size = uint32(unsafe.Sizeof(para))
	para.RequestedUsage = windows.CertUsageMatch{
		Type: windows.USAGE_MATCH_TYPE_AND,
		Usage: windows.CertEnhKeyUsage{
			Length:           1,
			UsageIdentifiers: &oidPtr,
		},
	}
	var chain *windows.CertChainContext
	if err := windows.CertGetCertificateChain(0, leafCtx, nil, memStore, &para, certChainCacheOnlyURLRetrieval, 0, &chain); err != nil {
		return fmt.Errorf("证书不受信任: %w", err)
	}
	defer windows.CertFreeCertificateChain(chain)

	var policyPara windows.CertChainPolicyPara
	policyPara.Size = uint32(unsafe.Sizeof(policyPara))
	var policyStatus windows.CertChainPolicyStatus
	policyStatus.Size = uint32(unsafe.Sizeof(policyStatus))
	if err := windows.CertVerifyCertificateChainPolicy(windows.CERT_CHAIN_POLICY_BASE, chain, &policyPara, &policyStatus); err != nil {
		return fmt.Errorf("证书不受信任: %w", err)
	}
	if policyStatus.Error != 0 {
		return fmt.Errorf("证书不受信任: %w", windows.Errno(policyStatus.Error))
	}
	return nil
}

func (p *windowsProvider) VerifyCMS(ctx context.Context, email string, cmsDER, detached []byte) ([]byte, error) {
	if len(cmsDER) == 0 || email == "" {
		return nil, errors.New("缺少签名或发件人")
	}
	var flags uint32
	if detached != nil {
		flags = cmsgDetachedFlag
	}
	hMsg, _, e1 := procCryptMsgOpenToDecode.Call(
		uintptr(windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING),
		uintptr(flags),
		0,
		0,
		0,
		0,
	)
	if hMsg == 0 {
		return nil, e1
	}
	defer func() { _, _, _ = procCryptMsgClose.Call(hMsg) }()

	r1, _, e1 := procCryptMsgUpdate.Call(hMsg, uintptr(unsafe.Pointer(&cmsDER[0])), uintptr(len(cmsDER)), 1)
	if r1 == 0 {
		return nil, fmt.Errorf("S/MIME 签名无效: %w", e1)
	}
	if detached != nil {
		var ptr unsafe.Pointer
		var dummy byte
		ptr = unsafe.Pointer(&dummy)
		if len(detached) > 0 {
			ptr = unsafe.Pointer(&detached[0])
		}
		r1, _, e1 = procCryptMsgUpdate.Call(hMsg, uintptr(ptr), uintptr(len(detached)), 1)
		if r1 == 0 {
			return nil, fmt.Errorf("分离签名无效: %w", e1)
		}
	}

	var signerCount uint32
	cbCount := uint32(unsafe.Sizeof(signerCount))
	r1, _, e1 = procCryptMsgGetParam.Call(hMsg, uintptr(cmsgSignerCountParam), 0, uintptr(unsafe.Pointer(&signerCount)), uintptr(unsafe.Pointer(&cbCount)))
	if r1 == 0 {
		return nil, e1
	}
	if signerCount != 1 {
		return nil, errors.New("无法确定唯一的 S/MIME 签名人")
	}

	msgStore, err := windows.CertOpenStore(windows.CERT_STORE_PROV_MSG, windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING, 0, 0, hMsg)
	if err != nil {
		return nil, err
	}
	defer windows.CertCloseStore(msgStore, 0)

	var cbInfo uint32
	r1, _, e1 = procCryptMsgGetParam.Call(hMsg, uintptr(cmsgSignerCertInfoParam), 0, 0, uintptr(unsafe.Pointer(&cbInfo)))
	if r1 == 0 || cbInfo == 0 {
		return nil, fmt.Errorf("缺少签名证书: %w", e1)
	}
	infoBuf := make([]byte, cbInfo)
	r1, _, e1 = procCryptMsgGetParam.Call(hMsg, uintptr(cmsgSignerCertInfoParam), 0, uintptr(unsafe.Pointer(&infoBuf[0])), uintptr(unsafe.Pointer(&cbInfo)))
	if r1 == 0 {
		return nil, fmt.Errorf("缺少签名证书: %w", e1)
	}

	rCtx, _, e1 := procCertGetSubjectCertificateFromStore.Call(
		uintptr(msgStore),
		uintptr(windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING),
		uintptr(unsafe.Pointer(&infoBuf[0])),
	)
	if rCtx == 0 {
		return nil, fmt.Errorf("缺少签名证书: %w", e1)
	}
	signerCtx := (*windows.CertContext)(unsafe.Pointer(rCtx))
	defer windows.CertFreeCertificateContext(signerCtx)

	r1, _, e1 = procCryptMsgControl.Call(hMsg, 0, uintptr(cmsgCtrlVerifySignature), uintptr(unsafe.Pointer(signerCtx.CertInfo)))
	if r1 == 0 {
		return nil, fmt.Errorf("S/MIME 签名无效: %w", e1)
	}

	signerDER := bytes.Clone(unsafe.Slice(signerCtx.EncodedCert, signerCtx.Length))
	certsDER := [][]byte{signerDER}
	var prev *windows.CertContext
	for {
		c, err := windows.CertEnumCertificatesInStore(msgStore, prev)
		if err != nil {
			break
		}
		prev = c
		der := unsafe.Slice(c.EncodedCert, c.Length)
		if !bytes.Equal(der, signerDER) {
			certsDER = append(certsDER, bytes.Clone(der))
		}
	}

	if err := p.VerifyTrust(ctx, "sign", email, certsDER); err != nil {
		return nil, fmt.Errorf("签名完整，但发件人证书未通过验证: %w", err)
	}
	if detached != nil {
		return detached, nil
	}

	var cbContent uint32
	r1, _, e1 = procCryptMsgGetParam.Call(hMsg, uintptr(cmsgContentParam), 0, 0, uintptr(unsafe.Pointer(&cbContent)))
	if r1 == 0 || cbContent == 0 {
		return nil, errors.New("签名中没有正文")
	}
	content := make([]byte, cbContent)
	r1, _, e1 = procCryptMsgGetParam.Call(hMsg, uintptr(cmsgContentParam), 0, uintptr(unsafe.Pointer(&content[0])), uintptr(unsafe.Pointer(&cbContent)))
	if r1 == 0 {
		return nil, e1
	}
	return content[:cbContent], nil
}

func (p *windowsProvider) Retry(context.Context) error {
	clear(p.failures)
	return nil
}

func (p *windowsProvider) Close() error {
	p.reset()
	return nil
}

func reverseBytes(b []byte) {
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
}

func isWindowsAuthFailure(code uint32) bool {
	return code == uint32(windows.ERROR_CANCELLED) ||
		code == uint32(windows.NTE_USER_CANCELLED) ||
		code == uint32(windows.SCARD_W_CANCELLED_BY_USER) ||
		code == uint32(windows.SCARD_W_WRONG_CHV) ||
		code == uint32(windows.SCARD_W_CHV_BLOCKED)
}

func isWindowsCardRemoved(code uint32) bool {
	return code == uint32(windows.SCARD_W_REMOVED_CARD) ||
		code == uint32(windows.SCARD_E_NO_SMARTCARD) ||
		code == uint32(windows.NTE_DEVICE_NOT_READY)
}
