//go:build darwin

package smime

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"fmt"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/ebitengine/purego"
	"github.com/ebitengine/purego/objc"
)

const (
	cfStringUTF8 uint32 = 0x08000100

	errSecSuccess      int32 = 0
	errSecUserCanceled int32 = -128
	errSecAuthFailed   int32 = -25293
	errSecItemNotFound int32 = -25300
	laErrorUserCancel  int   = -2

	kSecKeyOperationTypeSign    int = 0
	kSecKeyOperationTypeDecrypt int = 3

	kCMSSignerValid                uint32 = 1
	kCMSSignerNeedsDetachedContent uint32 = 2
)

type darwinAPI struct {
	cfRelease                        func(uintptr)
	cfRetain                         func(uintptr) uintptr
	cfDataCreate                     func(uintptr, unsafe.Pointer, int) uintptr
	cfDataGetBytePtr                 func(uintptr) uintptr
	cfDataGetLength                  func(uintptr) int
	cfStringCreateWithBytes          func(uintptr, unsafe.Pointer, int, uint32, bool) uintptr
	cfStringGetLength                func(uintptr) int
	cfStringGetMaximumSizeForEnc     func(int, uint32) int
	cfStringGetCString               func(uintptr, unsafe.Pointer, int, uint32) bool
	cfDictionaryCreate               func(uintptr, unsafe.Pointer, unsafe.Pointer, int, uintptr, uintptr) uintptr
	cfDictionaryGetValue             func(uintptr, uintptr) uintptr
	cfArrayCreate                    func(uintptr, unsafe.Pointer, int, uintptr) uintptr
	cfArrayGetCount                  func(uintptr) int
	cfArrayGetValueAtIndex           func(uintptr, int) uintptr
	cfErrorGetCode                   func(uintptr) int
	cfErrorCopyDescription           func(uintptr) uintptr
	secCopyErrorMessageString        func(int32, uintptr) uintptr
	secItemCopyMatching              func(uintptr, *uintptr) int32
	secIdentityCopyCertificate       func(uintptr, *uintptr) int32
	secIdentityCopyPrivateKey        func(uintptr, *uintptr) int32
	secKeyCopyAttributes             func(uintptr) uintptr
	secCertificateCreateWithData     func(uintptr, uintptr) uintptr
	secCertificateCopyData           func(uintptr) uintptr
	secCertificateCopyEmailAddresses func(uintptr, *uintptr) int32
	secKeyIsAlgorithmSupported       func(uintptr, int, uintptr) bool
	secKeyCreateSignature            func(uintptr, uintptr, uintptr, *uintptr) uintptr
	secKeyCreateDecryptedData        func(uintptr, uintptr, uintptr, *uintptr) uintptr
	secPolicyCreateWithProperties    func(uintptr, uintptr) uintptr
	secTrustCreateWithCertificates   func(uintptr, uintptr, *uintptr) int32
	secTrustSetNetworkFetchAllowed   func(uintptr, bool) int32
	secTrustEvaluateWithError        func(uintptr, *uintptr) bool
	cmsDecoderCreate                 func(*uintptr) int32
	cmsDecoderUpdateMessage          func(uintptr, unsafe.Pointer, uintptr) int32
	cmsDecoderFinalizeMessage        func(uintptr) int32
	cmsDecoderGetNumSigners          func(uintptr, *uintptr) int32
	cmsDecoderCopySignerStatus       func(uintptr, uintptr, uintptr, bool, *uint32, *uintptr, *int32) int32
	cmsDecoderSetDetachedContent     func(uintptr, uintptr) int32
	cmsDecoderCopySignerCert         func(uintptr, uintptr, *uintptr) int32
	cmsDecoderCopyContent            func(uintptr, *uintptr) int32

	kCFBooleanTrue               uintptr
	kCFTypeDictionaryKeyCB       uintptr
	kCFTypeDictionaryValueCB     uintptr
	kCFTypeArrayCB               uintptr
	kSecClass                    uintptr
	kSecClassIdentity            uintptr
	kSecReturnRef                uintptr
	kSecMatchLimit               uintptr
	kSecMatchLimitAll            uintptr
	kSecUseDataProtectionKC      uintptr
	kSecUseAuthenticationContext uintptr
	kSecAttrTokenID              uintptr
	kSecPolicyAppleSMIME         uintptr
	kSecPolicyName               uintptr
	kSecPolicyKUDigitalSig       uintptr
	kSecPolicyKUKeyEncipherment  uintptr
	kSecKeyAlgSignSHA256         uintptr
	kSecKeyAlgSignSHA1           uintptr
	kSecKeyAlgDecryptPKCS1       uintptr

	clsPool         objc.Class
	clsLAContext    objc.Class
	clsTokenWatcher objc.Class
	selNew          objc.SEL
	selDrain        objc.SEL
	selInvalidate   objc.SEL
	selTokenIDs     objc.SEL
}

var loadDarwinAPI = sync.OnceValues(func() (*darwinAPI, error) {
	cf, err := purego.Dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", purego.RTLD_GLOBAL|purego.RTLD_NOW)
	if err != nil {
		return nil, err
	}
	sec, err := purego.Dlopen("/System/Library/Frameworks/Security.framework/Security", purego.RTLD_GLOBAL|purego.RTLD_NOW)
	if err != nil {
		return nil, err
	}
	for _, fw := range []string{"Foundation", "LocalAuthentication", "CryptoTokenKit"} {
		if _, err := purego.Dlopen("/System/Library/Frameworks/"+fw+".framework/"+fw, purego.RTLD_GLOBAL|purego.RTLD_NOW); err != nil {
			return nil, err
		}
	}

	d := &darwinAPI{}
	purego.RegisterLibFunc(&d.cfRelease, cf, "CFRelease")
	purego.RegisterLibFunc(&d.cfRetain, cf, "CFRetain")
	purego.RegisterLibFunc(&d.cfDataCreate, cf, "CFDataCreate")
	purego.RegisterLibFunc(&d.cfDataGetBytePtr, cf, "CFDataGetBytePtr")
	purego.RegisterLibFunc(&d.cfDataGetLength, cf, "CFDataGetLength")
	purego.RegisterLibFunc(&d.cfStringCreateWithBytes, cf, "CFStringCreateWithBytes")
	purego.RegisterLibFunc(&d.cfStringGetLength, cf, "CFStringGetLength")
	purego.RegisterLibFunc(&d.cfStringGetMaximumSizeForEnc, cf, "CFStringGetMaximumSizeForEncoding")
	purego.RegisterLibFunc(&d.cfStringGetCString, cf, "CFStringGetCString")
	purego.RegisterLibFunc(&d.cfDictionaryCreate, cf, "CFDictionaryCreate")
	purego.RegisterLibFunc(&d.cfDictionaryGetValue, cf, "CFDictionaryGetValue")
	purego.RegisterLibFunc(&d.cfArrayCreate, cf, "CFArrayCreate")
	purego.RegisterLibFunc(&d.cfArrayGetCount, cf, "CFArrayGetCount")
	purego.RegisterLibFunc(&d.cfArrayGetValueAtIndex, cf, "CFArrayGetValueAtIndex")
	purego.RegisterLibFunc(&d.cfErrorGetCode, cf, "CFErrorGetCode")
	purego.RegisterLibFunc(&d.cfErrorCopyDescription, cf, "CFErrorCopyDescription")

	purego.RegisterLibFunc(&d.secCopyErrorMessageString, sec, "SecCopyErrorMessageString")
	purego.RegisterLibFunc(&d.secItemCopyMatching, sec, "SecItemCopyMatching")
	purego.RegisterLibFunc(&d.secIdentityCopyCertificate, sec, "SecIdentityCopyCertificate")
	purego.RegisterLibFunc(&d.secIdentityCopyPrivateKey, sec, "SecIdentityCopyPrivateKey")
	purego.RegisterLibFunc(&d.secKeyCopyAttributes, sec, "SecKeyCopyAttributes")
	purego.RegisterLibFunc(&d.secCertificateCreateWithData, sec, "SecCertificateCreateWithData")
	purego.RegisterLibFunc(&d.secCertificateCopyData, sec, "SecCertificateCopyData")
	purego.RegisterLibFunc(&d.secCertificateCopyEmailAddresses, sec, "SecCertificateCopyEmailAddresses")
	purego.RegisterLibFunc(&d.secKeyIsAlgorithmSupported, sec, "SecKeyIsAlgorithmSupported")
	purego.RegisterLibFunc(&d.secKeyCreateSignature, sec, "SecKeyCreateSignature")
	purego.RegisterLibFunc(&d.secKeyCreateDecryptedData, sec, "SecKeyCreateDecryptedData")
	purego.RegisterLibFunc(&d.secPolicyCreateWithProperties, sec, "SecPolicyCreateWithProperties")
	purego.RegisterLibFunc(&d.secTrustCreateWithCertificates, sec, "SecTrustCreateWithCertificates")
	purego.RegisterLibFunc(&d.secTrustSetNetworkFetchAllowed, sec, "SecTrustSetNetworkFetchAllowed")
	purego.RegisterLibFunc(&d.secTrustEvaluateWithError, sec, "SecTrustEvaluateWithError")
	purego.RegisterLibFunc(&d.cmsDecoderCreate, sec, "CMSDecoderCreate")
	purego.RegisterLibFunc(&d.cmsDecoderUpdateMessage, sec, "CMSDecoderUpdateMessage")
	purego.RegisterLibFunc(&d.cmsDecoderFinalizeMessage, sec, "CMSDecoderFinalizeMessage")
	purego.RegisterLibFunc(&d.cmsDecoderGetNumSigners, sec, "CMSDecoderGetNumSigners")
	purego.RegisterLibFunc(&d.cmsDecoderCopySignerStatus, sec, "CMSDecoderCopySignerStatus")
	purego.RegisterLibFunc(&d.cmsDecoderSetDetachedContent, sec, "CMSDecoderSetDetachedContent")
	purego.RegisterLibFunc(&d.cmsDecoderCopySignerCert, sec, "CMSDecoderCopySignerCert")
	purego.RegisterLibFunc(&d.cmsDecoderCopyContent, sec, "CMSDecoderCopyContent")

	symPtr := func(lib uintptr, name string) (uintptr, error) {
		addr, err := purego.Dlsym(lib, name)
		if err != nil {
			return 0, fmt.Errorf("dlsym %s: %w", name, err)
		}
		return *(*uintptr)(unsafe.Pointer(addr)), nil
	}
	symAddr := func(lib uintptr, name string) (uintptr, error) {
		addr, err := purego.Dlsym(lib, name)
		if err != nil {
			return 0, fmt.Errorf("dlsym %s: %w", name, err)
		}
		return addr, nil
	}

	if d.kCFBooleanTrue, err = symPtr(cf, "kCFBooleanTrue"); err != nil {
		return nil, err
	}
	if d.kCFTypeDictionaryKeyCB, err = symAddr(cf, "kCFTypeDictionaryKeyCallBacks"); err != nil {
		return nil, err
	}
	if d.kCFTypeDictionaryValueCB, err = symAddr(cf, "kCFTypeDictionaryValueCallBacks"); err != nil {
		return nil, err
	}
	if d.kCFTypeArrayCB, err = symAddr(cf, "kCFTypeArrayCallBacks"); err != nil {
		return nil, err
	}
	for dst, name := range map[*uintptr]string{
		&d.kSecClass:                    "kSecClass",
		&d.kSecClassIdentity:            "kSecClassIdentity",
		&d.kSecReturnRef:                "kSecReturnRef",
		&d.kSecMatchLimit:               "kSecMatchLimit",
		&d.kSecMatchLimitAll:            "kSecMatchLimitAll",
		&d.kSecUseDataProtectionKC:      "kSecUseDataProtectionKeychain",
		&d.kSecUseAuthenticationContext: "kSecUseAuthenticationContext",
		&d.kSecAttrTokenID:              "kSecAttrTokenID",
		&d.kSecPolicyAppleSMIME:         "kSecPolicyAppleSMIME",
		&d.kSecPolicyName:               "kSecPolicyName",
		&d.kSecPolicyKUDigitalSig:       "kSecPolicyKU_DigitalSignature",
		&d.kSecPolicyKUKeyEncipherment:  "kSecPolicyKU_KeyEncipherment",
		&d.kSecKeyAlgSignSHA256:         "kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256",
		&d.kSecKeyAlgSignSHA1:           "kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1",
		&d.kSecKeyAlgDecryptPKCS1:       "kSecKeyAlgorithmRSAEncryptionPKCS1",
	} {
		if *dst, err = symPtr(sec, name); err != nil {
			return nil, err
		}
	}

	d.clsPool = objc.GetClass("NSAutoreleasePool")
	d.clsLAContext = objc.GetClass("LAContext")
	d.clsTokenWatcher = objc.GetClass("TKTokenWatcher")
	if d.clsPool == 0 || d.clsLAContext == 0 || d.clsTokenWatcher == 0 {
		return nil, errors.New("缺少 macOS LocalAuthentication / CryptoTokenKit 运行时类")
	}
	d.selNew = objc.RegisterName("new")
	d.selDrain = objc.RegisterName("drain")
	d.selInvalidate = objc.RegisterName("invalidate")
	d.selTokenIDs = objc.RegisterName("tokenIDs")
	return d, nil
})

func platformSupported() bool { return true }

type darwinIdentity struct {
	der        []byte
	key        uintptr // SecKeyRef, retained
	canDecrypt bool
}

type darwinProvider struct {
	session        bool
	watcher        objc.ID
	laCtx          objc.ID
	items          []darwinIdentity
	authorized     map[string]bool
	failures       map[string]string
	tokenIDs       []string
	hadTokens      bool
	lastTokenCheck time.Time
}

func newPlatformProvider(session bool) provider {
	return &darwinProvider{
		session:    session,
		authorized: map[string]bool{},
		failures:   map[string]string{},
	}
}

func (d *darwinAPI) release(ref uintptr) {
	if ref != 0 {
		d.cfRelease(ref)
	}
}

func (d *darwinAPI) cfData(b []byte) uintptr {
	var dummy byte
	ptr := unsafe.Pointer(&dummy)
	if len(b) > 0 {
		ptr = unsafe.Pointer(&b[0])
	}
	return d.cfDataCreate(0, ptr, len(b))
}

func (d *darwinAPI) goBytes(cfData uintptr) []byte {
	if cfData == 0 {
		return nil
	}
	n := d.cfDataGetLength(cfData)
	if n <= 0 {
		return nil
	}
	ptr := d.cfDataGetBytePtr(cfData)
	if ptr == 0 {
		return nil
	}
	out := make([]byte, n)
	copy(out, unsafe.Slice((*byte)(unsafe.Pointer(ptr)), n))
	return out
}

func (d *darwinAPI) cfString(s string) uintptr {
	var dummy byte
	ptr := unsafe.Pointer(&dummy)
	if len(s) > 0 {
		ptr = unsafe.Pointer(unsafe.StringData(s))
	}
	return d.cfStringCreateWithBytes(0, ptr, len(s), cfStringUTF8, false)
}

func (d *darwinAPI) goString(cfStr uintptr) string {
	if cfStr == 0 {
		return ""
	}
	maxLen := d.cfStringGetMaximumSizeForEnc(d.cfStringGetLength(cfStr), cfStringUTF8) + 1
	if maxLen <= 1 {
		return ""
	}
	buf := make([]byte, maxLen)
	if !d.cfStringGetCString(cfStr, unsafe.Pointer(&buf[0]), len(buf), cfStringUTF8) {
		return ""
	}
	if i := bytes.IndexByte(buf, 0); i >= 0 {
		return string(buf[:i])
	}
	return string(buf)
}

func (d *darwinAPI) cfDict(keys, vals []uintptr) uintptr {
	return d.cfDictionaryCreate(0, unsafe.Pointer(&keys[0]), unsafe.Pointer(&vals[0]), len(keys), d.kCFTypeDictionaryKeyCB, d.kCFTypeDictionaryValueCB)
}

func (d *darwinAPI) secErr(status int32) error {
	if status == errSecSuccess {
		return nil
	}
	var msg string
	if s := d.secCopyErrorMessageString(status, 0); s != 0 {
		msg = d.goString(s)
		d.release(s)
	}
	if msg == "" {
		msg = "Security.framework"
	}
	return fmt.Errorf("%s (%d)", msg, status)
}

func (d *darwinAPI) cfErr(cfErr uintptr, fallback string) (code int, err error) {
	if cfErr == 0 {
		return 0, errors.New(fallback)
	}
	code = d.cfErrorGetCode(cfErr)
	var msg string
	if desc := d.cfErrorCopyDescription(cfErr); desc != 0 {
		msg = d.goString(desc)
		d.release(desc)
	}
	if msg == "" {
		msg = fallback
	}
	return code, errors.New(msg)
}

func (p *darwinProvider) withPool(fn func()) {
	d, err := loadDarwinAPI()
	if err != nil {
		return
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	pool := objc.ID(d.clsPool).Send(d.selNew)
	defer pool.Send(d.selDrain)
	fn()
}

func (p *darwinProvider) resetItems(d *darwinAPI) {
	for _, it := range p.items {
		d.release(it.key)
	}
	p.items = nil
	p.lastTokenCheck = time.Time{}
	clear(p.authorized)
	clear(p.failures)
	if p.laCtx != 0 {
		p.withPool(func() {
			p.laCtx.Send(d.selInvalidate)
		})
		d.release(uintptr(p.laCtx))
		p.laCtx = 0
	}
}

func (p *darwinProvider) readTokenIDs(d *darwinAPI) []string {
	var out []string
	p.withPool(func() {
		if p.watcher == 0 {
			p.watcher = objc.ID(d.clsTokenWatcher).Send(d.selNew)
		}
		if p.watcher == 0 {
			return
		}
		arr := uintptr(p.watcher.Send(d.selTokenIDs))
		if arr == 0 {
			return
		}
		n := d.cfArrayGetCount(arr)
		out = make([]string, 0, n)
		for i := range n {
			if s := d.goString(d.cfArrayGetValueAtIndex(arr, i)); s != "" {
				out = append(out, s)
			}
		}
		sort.Strings(out)
	})
	return out
}

func (p *darwinProvider) ensureKeys(d *darwinAPI) ([]darwinIdentity, error) {
	if p.session {
		if len(p.items) == 0 || p.lastTokenCheck.IsZero() || time.Since(p.lastTokenCheck) >= 2*time.Second {
			current := p.readTokenIDs(d)
			now := time.Now()
			if !p.hadTokens {
				if len(current) > 0 {
					p.tokenIDs, p.hadTokens = current, true
				}
			} else if !slices.Equal(current, p.tokenIDs) {
				p.resetItems(d)
				p.tokenIDs = current
				p.hadTokens = len(current) > 0
			}
			p.lastTokenCheck = now
		}
	}
	if len(p.items) > 0 {
		return p.items, nil
	}
	p.withPool(func() {
		if p.laCtx == 0 {
			p.laCtx = objc.ID(d.clsLAContext).Send(d.selNew)
		}
	})
	if p.laCtx == 0 {
		return nil, errors.New("无法创建系统认证上下文")
	}
	query := d.cfDict(
		[]uintptr{d.kSecClass, d.kSecReturnRef, d.kSecMatchLimit, d.kSecUseDataProtectionKC, d.kSecUseAuthenticationContext},
		[]uintptr{d.kSecClassIdentity, d.kCFBooleanTrue, d.kSecMatchLimitAll, d.kCFBooleanTrue, uintptr(p.laCtx)},
	)
	if query == 0 {
		return nil, errors.New("无法构造钥匙串查询")
	}
	defer d.release(query)

	var result uintptr
	status := d.secItemCopyMatching(query, &result)
	if status == errSecItemNotFound {
		return nil, nil
	}
	if status != errSecSuccess {
		return nil, d.secErr(status)
	}
	if result == 0 {
		return nil, nil
	}
	defer d.release(result)

	n := d.cfArrayGetCount(result)
	items := make([]darwinIdentity, 0, n)
	for i := range n {
		ident := d.cfArrayGetValueAtIndex(result, i)
		if ident == 0 {
			continue
		}
		var cert, privKey uintptr
		if st := d.secIdentityCopyCertificate(ident, &cert); st != errSecSuccess {
			d.release(cert)
			for _, it := range items {
				d.release(it.key)
			}
			return nil, d.secErr(st)
		}
		if st := d.secIdentityCopyPrivateKey(ident, &privKey); st != errSecSuccess {
			d.release(cert)
			d.release(privKey)
			for _, it := range items {
				d.release(it.key)
			}
			return nil, d.secErr(st)
		}
		attrs := d.secKeyCopyAttributes(privKey)
		hasToken := attrs != 0 && d.cfDictionaryGetValue(attrs, d.kSecAttrTokenID) != 0
		d.release(attrs)
		if !hasToken {
			d.release(cert)
			d.release(privKey)
			continue
		}
		certData := d.secCertificateCopyData(cert)
		der := d.goBytes(certData)
		d.release(certData)
		d.release(cert)
		if len(der) == 0 {
			d.release(privKey)
			continue
		}
		items = append(items, darwinIdentity{
			der:        der,
			key:        privKey,
			canDecrypt: d.secKeyIsAlgorithmSupported(privKey, kSecKeyOperationTypeDecrypt, d.kSecKeyAlgDecryptPKCS1),
		})
	}
	p.items = items
	return p.items, nil
}

func (p *darwinProvider) findKey(d *darwinAPI, certDER []byte) (darwinIdentity, error) {
	items, err := p.ensureKeys(d)
	if err != nil {
		return darwinIdentity{}, err
	}
	for _, it := range items {
		if bytes.Equal(it.der, certDER) {
			return it, nil
		}
	}
	return darwinIdentity{}, errors.New("请插入与邮件证书匹配的硬件 Key")
}

func (p *darwinProvider) Identities(context.Context) ([][]byte, error) {
	d, err := loadDarwinAPI()
	if err != nil {
		return nil, err
	}
	items, err := p.ensureKeys(d)
	if err != nil {
		return nil, err
	}
	out := make([][]byte, len(items))
	for i, it := range items {
		out[i] = bytes.Clone(it.der)
	}
	return out, nil
}

func (p *darwinProvider) Prepare(_ context.Context, certDER, sealed []byte) error {
	d, err := loadDarwinAPI()
	if err != nil {
		return err
	}
	id, err := p.findKey(d, certDER)
	if err != nil {
		return err
	}
	idKey := string(certDER)
	if p.authorized[idKey] {
		return nil
	}
	if reason, ok := p.failures[idKey]; ok {
		return errors.New(reason)
	}
	if !id.canDecrypt {
		return errors.New("硬件 Key 不支持 RSA PKCS#1 解密")
	}
	cfIn := d.cfData(sealed)
	if cfIn == 0 {
		return errors.New("缺少硬件操作数据")
	}
	defer d.release(cfIn)
	var cfErr uintptr
	out := d.secKeyCreateDecryptedData(id.key, d.kSecKeyAlgDecryptPKCS1, cfIn, &cfErr)
	if out == 0 {
		code, e := d.cfErr(cfErr, "硬件操作失败")
		d.release(cfErr)
		if p.session && isDarwinAuthFailure(code) {
			p.failures[idKey] = e.Error()
		} else {
			p.lastTokenCheck = time.Time{}
		}
		return e
	}
	d.release(out)
	if p.session {
		p.authorized[idKey] = true
	}
	return nil
}

func (p *darwinProvider) DigestAlgorithm(_ context.Context, certDER []byte) (crypto.Hash, error) {
	d, err := loadDarwinAPI()
	if err != nil {
		return 0, err
	}
	id, err := p.findKey(d, certDER)
	if err != nil {
		return 0, err
	}
	if reason, ok := p.failures[string(certDER)]; ok {
		return 0, errors.New(reason)
	}
	if d.secKeyIsAlgorithmSupported(id.key, kSecKeyOperationTypeSign, d.kSecKeyAlgSignSHA256) {
		return crypto.SHA256, nil
	}
	if d.secKeyIsAlgorithmSupported(id.key, kSecKeyOperationTypeSign, d.kSecKeyAlgSignSHA1) {
		return crypto.SHA1, nil
	}
	return 0, errors.New("硬件 Key 没有可用的签名算法")
}

func (p *darwinProvider) Sign(_ context.Context, certDER []byte, hash crypto.Hash, digest []byte) ([]byte, error) {
	d, err := loadDarwinAPI()
	if err != nil {
		return nil, err
	}
	id, err := p.findKey(d, certDER)
	if err != nil {
		return nil, err
	}
	idKey := string(certDER)
	if reason, ok := p.failures[idKey]; ok {
		return nil, errors.New(reason)
	}
	var alg uintptr
	var digestLen int
	switch hash {
	case crypto.SHA256:
		alg, digestLen = d.kSecKeyAlgSignSHA256, 32
	case crypto.SHA1:
		alg, digestLen = d.kSecKeyAlgSignSHA1, 20
	default:
		return nil, errors.New("不支持的硬件签名摘要")
	}
	if len(digest) != digestLen || !d.secKeyIsAlgorithmSupported(id.key, kSecKeyOperationTypeSign, alg) {
		return nil, errors.New("硬件 Key 不支持所选签名算法")
	}
	cfIn := d.cfData(digest)
	if cfIn == 0 {
		return nil, errors.New("缺少硬件操作数据")
	}
	defer d.release(cfIn)
	var cfErr uintptr
	out := d.secKeyCreateSignature(id.key, alg, cfIn, &cfErr)
	if out == 0 {
		code, e := d.cfErr(cfErr, "硬件操作失败")
		d.release(cfErr)
		if p.session && isDarwinAuthFailure(code) {
			p.failures[idKey] = e.Error()
		} else {
			p.lastTokenCheck = time.Time{}
		}
		return nil, e
	}
	defer d.release(out)
	if p.session {
		p.authorized[idKey] = true
	}
	return d.goBytes(out), nil
}

func (p *darwinProvider) Decrypt(_ context.Context, certDER, ciphertext []byte) ([]byte, error) {
	d, err := loadDarwinAPI()
	if err != nil {
		return nil, err
	}
	id, err := p.findKey(d, certDER)
	if err != nil {
		return nil, err
	}
	idKey := string(certDER)
	if reason, ok := p.failures[idKey]; ok {
		return nil, errors.New(reason)
	}
	if !id.canDecrypt {
		return nil, errors.New("硬件 Key 不支持 RSA PKCS#1 解密")
	}
	cfIn := d.cfData(ciphertext)
	if cfIn == 0 {
		return nil, errors.New("缺少硬件操作数据")
	}
	defer d.release(cfIn)
	var cfErr uintptr
	out := d.secKeyCreateDecryptedData(id.key, d.kSecKeyAlgDecryptPKCS1, cfIn, &cfErr)
	if out == 0 {
		code, e := d.cfErr(cfErr, "硬件操作失败")
		d.release(cfErr)
		if p.session && isDarwinAuthFailure(code) {
			p.failures[idKey] = e.Error()
		} else {
			p.lastTokenCheck = time.Time{}
		}
		return nil, e
	}
	defer d.release(out)
	if p.session {
		p.authorized[idKey] = true
	}
	return d.goBytes(out), nil
}

func (p *darwinProvider) VerifyTrust(_ context.Context, usage, email string, certsDER [][]byte) error {
	d, err := loadDarwinAPI()
	if err != nil {
		return err
	}
	if email == "" || len(certsDER) == 0 {
		return errors.New("缺少 S/MIME 证书或邮箱地址")
	}
	var usageKey uintptr
	switch usage {
	case "sign":
		usageKey = d.kSecPolicyKUDigitalSig
	case "encrypt":
		usageKey = d.kSecPolicyKUKeyEncipherment
	default:
		return errors.New("未知的证书用途")
	}
	cfEmail := d.cfString(email)
	if cfEmail == 0 {
		return errors.New("无法创建邮箱字符串")
	}
	defer d.release(cfEmail)

	certs := make([]uintptr, 0, len(certsDER))
	defer func() {
		for _, c := range certs {
			d.release(c)
		}
	}()
	for _, der := range certsDER {
		data := d.cfData(der)
		cert := d.secCertificateCreateWithData(0, data)
		d.release(data)
		if cert == 0 {
			return errors.New("无效的 X.509 证书")
		}
		certs = append(certs, cert)
	}
	cfCerts := d.cfArrayCreate(0, unsafe.Pointer(&certs[0]), len(certs), d.kCFTypeArrayCB)
	if cfCerts == 0 {
		return errors.New("无法创建证书列表")
	}
	defer d.release(cfCerts)

	props := d.cfDict([]uintptr{d.kSecPolicyName, usageKey}, []uintptr{cfEmail, d.kCFBooleanTrue})
	if props == 0 {
		return errors.New("无法创建系统 S/MIME 证书策略")
	}
	defer d.release(props)

	policy := d.secPolicyCreateWithProperties(d.kSecPolicyAppleSMIME, props)
	if policy == 0 {
		return errors.New("无法创建系统 S/MIME 证书策略")
	}
	defer d.release(policy)

	var trust uintptr
	if st := d.secTrustCreateWithCertificates(cfCerts, policy, &trust); st != errSecSuccess || trust == 0 {
		d.release(trust)
		if st != errSecSuccess {
			return d.secErr(st)
		}
		return errors.New("无法评估证书")
	}
	defer d.release(trust)

	if st := d.secTrustSetNetworkFetchAllowed(trust, false); st != errSecSuccess {
		return d.secErr(st)
	}
	var cfErr uintptr
	if !d.secTrustEvaluateWithError(trust, &cfErr) {
		_, e := d.cfErr(cfErr, "证书不受信任")
		d.release(cfErr)
		return e
	}
	d.release(cfErr)
	return nil
}

func (p *darwinProvider) VerifyCMS(_ context.Context, email string, cmsDER, detached []byte) ([]byte, error) {
	d, err := loadDarwinAPI()
	if err != nil {
		return nil, err
	}
	if len(cmsDER) == 0 || email == "" {
		return nil, errors.New("缺少签名或发件人")
	}
	cfEmail := d.cfString(email)
	if cfEmail == 0 {
		return nil, errors.New("无法创建邮箱字符串")
	}
	defer d.release(cfEmail)

	props := d.cfDict([]uintptr{d.kSecPolicyName, d.kSecPolicyKUDigitalSig}, []uintptr{cfEmail, d.kCFBooleanTrue})
	if props == 0 {
		return nil, errors.New("无法创建系统 S/MIME 证书策略")
	}
	defer d.release(props)

	policy := d.secPolicyCreateWithProperties(d.kSecPolicyAppleSMIME, props)
	if policy == 0 {
		return nil, errors.New("无法创建系统 S/MIME 证书策略")
	}
	defer d.release(policy)

	var decoder uintptr
	if st := d.cmsDecoderCreate(&decoder); st != errSecSuccess || decoder == 0 {
		d.release(decoder)
		return nil, d.secErr(st)
	}
	defer d.release(decoder)

	if st := d.cmsDecoderUpdateMessage(decoder, unsafe.Pointer(&cmsDER[0]), uintptr(len(cmsDER))); st != errSecSuccess {
		return nil, d.secErr(st)
	}
	if st := d.cmsDecoderFinalizeMessage(decoder); st != errSecSuccess {
		return nil, d.secErr(st)
	}
	var signers uintptr
	if st := d.cmsDecoderGetNumSigners(decoder, &signers); st != errSecSuccess {
		return nil, d.secErr(st)
	}
	if signers != 1 {
		return nil, errors.New("无法确定唯一的 S/MIME 签名人")
	}
	var status uint32
	if detached != nil {
		if st := d.cmsDecoderCopySignerStatus(decoder, 0, policy, false, &status, nil, nil); st != errSecSuccess {
			return nil, d.secErr(st)
		}
		if status != kCMSSignerNeedsDetachedContent {
			return nil, errors.New("分离签名中含有另一份正文")
		}
		cfDetached := d.cfData(detached)
		if cfDetached == 0 {
			return nil, errors.New("无法读取分离签名正文")
		}
		st := d.cmsDecoderSetDetachedContent(decoder, cfDetached)
		d.release(cfDetached)
		if st != errSecSuccess {
			return nil, d.secErr(st)
		}
	}
	var trust uintptr
	if st := d.cmsDecoderCopySignerStatus(decoder, 0, policy, false, &status, &trust, nil); st != errSecSuccess {
		d.release(trust)
		return nil, d.secErr(st)
	}
	defer d.release(trust)
	if status != kCMSSignerValid || trust == 0 {
		return nil, errors.New("S/MIME 签名无效")
	}
	if st := d.secTrustSetNetworkFetchAllowed(trust, false); st != errSecSuccess {
		return nil, d.secErr(st)
	}
	var cfErr uintptr
	if !d.secTrustEvaluateWithError(trust, &cfErr) {
		_, e := d.cfErr(cfErr, "证书不受信任")
		d.release(cfErr)
		return nil, e
	}
	d.release(cfErr)

	var signer uintptr
	if st := d.cmsDecoderCopySignerCert(decoder, 0, &signer); st != errSecSuccess {
		d.release(signer)
		return nil, d.secErr(st)
	}
	if signer == 0 {
		return nil, errors.New("缺少签名证书")
	}
	defer d.release(signer)

	var addrs uintptr
	if st := d.secCertificateCopyEmailAddresses(signer, &addrs); st != errSecSuccess {
		d.release(addrs)
		return nil, d.secErr(st)
	}
	matched := false
	if addrs != 0 {
		n := d.cfArrayGetCount(addrs)
		for i := range n {
			if strings.EqualFold(d.goString(d.cfArrayGetValueAtIndex(addrs, i)), email) {
				matched = true
				break
			}
		}
		d.release(addrs)
	}
	if !matched {
		certData := d.secCertificateCopyData(signer)
		der := d.goBytes(certData)
		d.release(certData)
		if len(der) > 0 {
			if cert, err := ParseCertificate(der); err == nil && MatchesMailbox(cert, email) {
				matched = true
			}
		}
	}
	if !matched {
		return nil, errors.New("签名证书邮箱与发件人不匹配")
	}
	if detached != nil {
		return detached, nil
	}
	var content uintptr
	if st := d.cmsDecoderCopyContent(decoder, &content); st != errSecSuccess {
		d.release(content)
		return nil, d.secErr(st)
	}
	defer d.release(content)
	if content == 0 {
		return nil, errors.New("签名中没有正文")
	}
	return d.goBytes(content), nil
}

func (p *darwinProvider) Retry(context.Context) error {
	clear(p.failures)
	return nil
}

func (p *darwinProvider) Close() error {
	d, err := loadDarwinAPI()
	if err != nil {
		return nil
	}
	p.resetItems(d)
	if p.watcher != 0 {
		d.release(uintptr(p.watcher))
		p.watcher = 0
	}
	return nil
}

func isDarwinAuthFailure(code int) bool {
	return code == int(errSecUserCanceled) || code == int(errSecAuthFailed) || code == laErrorUserCancel
}
