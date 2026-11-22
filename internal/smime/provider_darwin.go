//go:build darwin

package smime

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
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
	cfStringUTF8        uint32 = 0x08000100
	kCFNumberSInt64Type int    = 4

	errSecSuccess            int32 = 0
	errSecUserCanceled       int32 = -128
	errSecAuthFailed         int32 = -25293
	errSecItemNotFound       int32 = -25300
	errSecUnsupportedKeySize int   = -67735
	laErrorUserCancel        int   = -2

	kSecTrustResultRecoverableTrustFailure int64 = 5
	cssmErrCSPUnsupportedKeySize           int64 = -2147415784
	minCompatRSAKeyBits                    int   = 1024
	minCompatECDSAKeyBits                  int   = 192

	kSecKeyOperationTypeSign    int = 0
	kSecKeyOperationTypeDecrypt int = 3

	kCMSSignerValid                uint32 = 1
	kCMSSignerNeedsDetachedContent uint32 = 2
)

type darwinAPI struct {
	cfRelease                        func(uintptr)
	cfRetain                         func(uintptr) uintptr
	cfGetTypeID                      func(uintptr) uintptr
	cfDictionaryGetTypeID            func() uintptr
	cfArrayGetTypeID                 func() uintptr
	cfStringGetTypeID                func() uintptr
	cfNumberGetTypeID                func() uintptr
	cfBooleanGetTypeID               func() uintptr
	cfDataCreate                     func(uintptr, unsafe.Pointer, int) uintptr
	cfDataGetBytePtr                 func(uintptr) uintptr
	cfDataGetLength                  func(uintptr) int
	cfStringCreateWithBytes          func(uintptr, unsafe.Pointer, int, uint32, bool) uintptr
	cfStringGetLength                func(uintptr) int
	cfStringGetMaximumSizeForEnc     func(int, uint32) int
	cfStringGetCString               func(uintptr, unsafe.Pointer, int, uint32) bool
	cfDictionaryCreate               func(uintptr, unsafe.Pointer, unsafe.Pointer, int, uintptr, uintptr) uintptr
	cfDictionaryGetValue             func(uintptr, uintptr) uintptr
	cfDictionaryGetCount             func(uintptr) int
	cfDictionaryGetKeysAndValues     func(uintptr, unsafe.Pointer, unsafe.Pointer)
	cfArrayCreate                    func(uintptr, unsafe.Pointer, int, uintptr) uintptr
	cfArrayGetCount                  func(uintptr) int
	cfArrayGetValueAtIndex           func(uintptr, int) uintptr
	cfNumberGetValue                 func(uintptr, int, unsafe.Pointer) bool
	cfBooleanGetValue                func(uintptr) bool
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
	secTrustSetAnchorCertificates    func(uintptr, uintptr) int32
	secTrustSetNetworkFetchAllowed   func(uintptr, bool) int32
	secTrustEvaluateWithError        func(uintptr, *uintptr) bool
	secTrustCopyResult               func(uintptr) uintptr
	secTrustCopyCertificateChain     func(uintptr) uintptr
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
	kSecClassCertificate         uintptr
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
	purego.RegisterLibFunc(&d.cfGetTypeID, cf, "CFGetTypeID")
	purego.RegisterLibFunc(&d.cfDictionaryGetTypeID, cf, "CFDictionaryGetTypeID")
	purego.RegisterLibFunc(&d.cfArrayGetTypeID, cf, "CFArrayGetTypeID")
	purego.RegisterLibFunc(&d.cfStringGetTypeID, cf, "CFStringGetTypeID")
	purego.RegisterLibFunc(&d.cfNumberGetTypeID, cf, "CFNumberGetTypeID")
	purego.RegisterLibFunc(&d.cfBooleanGetTypeID, cf, "CFBooleanGetTypeID")
	purego.RegisterLibFunc(&d.cfDataCreate, cf, "CFDataCreate")
	purego.RegisterLibFunc(&d.cfDataGetBytePtr, cf, "CFDataGetBytePtr")
	purego.RegisterLibFunc(&d.cfDataGetLength, cf, "CFDataGetLength")
	purego.RegisterLibFunc(&d.cfStringCreateWithBytes, cf, "CFStringCreateWithBytes")
	purego.RegisterLibFunc(&d.cfStringGetLength, cf, "CFStringGetLength")
	purego.RegisterLibFunc(&d.cfStringGetMaximumSizeForEnc, cf, "CFStringGetMaximumSizeForEncoding")
	purego.RegisterLibFunc(&d.cfStringGetCString, cf, "CFStringGetCString")
	purego.RegisterLibFunc(&d.cfDictionaryCreate, cf, "CFDictionaryCreate")
	purego.RegisterLibFunc(&d.cfDictionaryGetValue, cf, "CFDictionaryGetValue")
	purego.RegisterLibFunc(&d.cfDictionaryGetCount, cf, "CFDictionaryGetCount")
	purego.RegisterLibFunc(&d.cfDictionaryGetKeysAndValues, cf, "CFDictionaryGetKeysAndValues")
	purego.RegisterLibFunc(&d.cfArrayCreate, cf, "CFArrayCreate")
	purego.RegisterLibFunc(&d.cfArrayGetCount, cf, "CFArrayGetCount")
	purego.RegisterLibFunc(&d.cfArrayGetValueAtIndex, cf, "CFArrayGetValueAtIndex")
	purego.RegisterLibFunc(&d.cfNumberGetValue, cf, "CFNumberGetValue")
	purego.RegisterLibFunc(&d.cfBooleanGetValue, cf, "CFBooleanGetValue")
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
	purego.RegisterLibFunc(&d.secTrustSetAnchorCertificates, sec, "SecTrustSetAnchorCertificates")
	purego.RegisterLibFunc(&d.secTrustSetNetworkFetchAllowed, sec, "SecTrustSetNetworkFetchAllowed")
	purego.RegisterLibFunc(&d.secTrustEvaluateWithError, sec, "SecTrustEvaluateWithError")
	purego.RegisterLibFunc(&d.secTrustCopyResult, sec, "SecTrustCopyResult")
	purego.RegisterLibFunc(&d.secTrustCopyCertificateChain, sec, "SecTrustCopyCertificateChain")
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
		&d.kSecClassCertificate:         "kSecClassCertificate",
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
		return nil, errors.New("missing macOS LocalAuthentication / CryptoTokenKit runtime classes")
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
	hardware   bool
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
		return nil, errors.New("unable to create system authentication context")
	}
	seen := map[string]int{}
	var items []darwinIdentity
	releaseAll := func() {
		for _, it := range items {
			d.release(it.key)
		}
	}
	for _, useDP := range []bool{true, false} {
		keys := []uintptr{d.kSecClass, d.kSecReturnRef, d.kSecMatchLimit, d.kSecUseAuthenticationContext}
		vals := []uintptr{d.kSecClassIdentity, d.kCFBooleanTrue, d.kSecMatchLimitAll, uintptr(p.laCtx)}
		if useDP {
			keys = append(keys, d.kSecUseDataProtectionKC)
			vals = append(vals, d.kCFBooleanTrue)
		}
		query := d.cfDict(keys, vals)
		if query == 0 {
			releaseAll()
			return nil, errors.New("unable to build keychain query")
		}
		var result uintptr
		status := d.secItemCopyMatching(query, &result)
		d.release(query)
		if status == errSecItemNotFound || result == 0 {
			continue
		}
		if status != errSecSuccess {
			releaseAll()
			return nil, d.secErr(status)
		}
		n := d.cfArrayGetCount(result)
		for i := range n {
			ident := d.cfArrayGetValueAtIndex(result, i)
			if ident == 0 {
				continue
			}
			var cert, privKey uintptr
			if st := d.secIdentityCopyCertificate(ident, &cert); st != errSecSuccess {
				d.release(cert)
				continue
			}
			if st := d.secIdentityCopyPrivateKey(ident, &privKey); st != errSecSuccess {
				d.release(cert)
				d.release(privKey)
				continue
			}
			attrs := d.secKeyCopyAttributes(privKey)
			hasToken := attrs != 0 && d.cfDictionaryGetValue(attrs, d.kSecAttrTokenID) != 0
			d.release(attrs)
			certData := d.secCertificateCopyData(cert)
			der := d.goBytes(certData)
			d.release(certData)
			d.release(cert)
			if len(der) == 0 {
				d.release(privKey)
				continue
			}
			sum := CertSHA256(der)
			if idx, dup := seen[sum]; dup {
				// Prefer the hardware-token identity handle if present in both queries.
				if hasToken && !items[idx].hardware {
					d.release(items[idx].key)
					items[idx] = darwinIdentity{
						der:        der,
						key:        privKey,
						hardware:   true,
						canDecrypt: d.secKeyIsAlgorithmSupported(privKey, kSecKeyOperationTypeDecrypt, d.kSecKeyAlgDecryptPKCS1),
					}
				} else {
					d.release(privKey)
				}
				continue
			}
			seen[sum] = len(items)
			items = append(items, darwinIdentity{
				der:        der,
				key:        privKey,
				hardware:   hasToken,
				canDecrypt: d.secKeyIsAlgorithmSupported(privKey, kSecKeyOperationTypeDecrypt, d.kSecKeyAlgDecryptPKCS1),
			})
		}
		d.release(result)
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
	return darwinIdentity{}, errors.New("matching personal S/MIME certificate or security key not found")
}

func (p *darwinProvider) Identities(context.Context) ([]RawIdentity, error) {
	d, err := loadDarwinAPI()
	if err != nil {
		return nil, err
	}
	items, err := p.ensureKeys(d)
	if err != nil {
		return nil, err
	}
	out := make([]RawIdentity, len(items))
	for i, it := range items {
		out[i] = RawIdentity{DER: bytes.Clone(it.der), Hardware: it.hardware}
	}
	return out, nil
}

func (p *darwinProvider) FindCertificates(_ context.Context, email string) ([][]byte, error) {
	d, err := loadDarwinAPI()
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out [][]byte
	for _, useDP := range []bool{false, true} {
		keys := []uintptr{d.kSecClass, d.kSecReturnRef, d.kSecMatchLimit}
		vals := []uintptr{d.kSecClassCertificate, d.kCFBooleanTrue, d.kSecMatchLimitAll}
		if useDP {
			keys = append(keys, d.kSecUseDataProtectionKC)
			vals = append(vals, d.kCFBooleanTrue)
		}
		query := d.cfDict(keys, vals)
		if query == 0 {
			continue
		}
		var result uintptr
		status := d.secItemCopyMatching(query, &result)
		d.release(query)
		if status != errSecSuccess || result == 0 {
			continue
		}
		n := d.cfArrayGetCount(result)
		for i := range n {
			ref := d.cfArrayGetValueAtIndex(result, i)
			if ref == 0 {
				continue
			}
			certData := d.secCertificateCopyData(ref)
			der := d.goBytes(certData)
			d.release(certData)
			if len(der) == 0 {
				continue
			}
			cert, err := ParseCertificate(der)
			if err != nil || !MatchesMailbox(cert, email) {
				continue
			}
			sum := CertSHA256(cert.Raw)
			if !seen[sum] {
				seen[sum] = true
				out = append(out, der)
			}
		}
		d.release(result)
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
		return errors.New("selected S/MIME private key does not support RSA PKCS#1 decryption")
	}
	cfIn := d.cfData(sealed)
	if cfIn == 0 {
		return errors.New("missing input data")
	}
	defer d.release(cfIn)
	var cfErr uintptr
	out := d.secKeyCreateDecryptedData(id.key, d.kSecKeyAlgDecryptPKCS1, cfIn, &cfErr)
	if out == 0 {
		code, e := d.cfErr(cfErr, "private key operation failed")
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
	return 0, errors.New("selected S/MIME certificate has no usable signing algorithm")
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
		return nil, errors.New("unsupported signature digest algorithm")
	}
	if len(digest) != digestLen || !d.secKeyIsAlgorithmSupported(id.key, kSecKeyOperationTypeSign, alg) {
		return nil, errors.New("selected S/MIME certificate does not support this signing algorithm")
	}
	cfIn := d.cfData(digest)
	if cfIn == 0 {
		return nil, errors.New("missing digest to sign")
	}
	defer d.release(cfIn)
	var cfErr uintptr
	out := d.secKeyCreateSignature(id.key, alg, cfIn, &cfErr)
	if out == 0 {
		code, e := d.cfErr(cfErr, "signing failed")
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
		return nil, errors.New("security key does not support RSA PKCS#1 decryption")
	}
	cfIn := d.cfData(ciphertext)
	if cfIn == 0 {
		return nil, errors.New("missing ciphertext data")
	}
	defer d.release(cfIn)
	var cfErr uintptr
	out := d.secKeyCreateDecryptedData(id.key, d.kSecKeyAlgDecryptPKCS1, cfIn, &cfErr)
	if out == 0 {
		code, e := d.cfErr(cfErr, "decryption failed")
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

type darwinTrustDetails struct {
	hasDetails       bool
	resultValue      int64
	hasKeySizeFail   bool
	hasWeakKeyFail   bool
	allKeySizeCompat bool
	otherFailureKey  string
	otherStatusCode  bool
	firstKeySizeFail *WeakKeySizeError
}

func darwinTrustFailureError(key string) error {
	switch key {
	case "AnchorTrusted", "ValidRoot", "MissingIntermediate":
		return errors.New("certificate is not trusted")
	case "TemporalValidity", "NotValidBefore":
		return errors.New("certificate has expired or is not yet valid")
	case "Email":
		return errors.New("signer certificate email does not match sender")
	case "KeyUsage", "ExtendedKeyUsage":
		return errors.New("certificate key usage is not permitted")
	case "SignatureHashAlgorithms", "WeakSignature":
		return errors.New("certificate uses an unsupported signature hash algorithm")
	case "Revocation", "RevocationResponseRequired":
		return errors.New("certificate has been revoked")
	default:
		return errors.New("certificate is not trusted")
	}
}

func (d *darwinAPI) inspectTrustResult(trustResult, chain uintptr) darwinTrustDetails {
	if trustResult == 0 || d.cfGetTypeID(trustResult) != d.cfDictionaryGetTypeID() {
		return darwinTrustDetails{}
	}
	var info darwinTrustDetails
	if kVal := d.cfString("TrustResultValue"); kVal != 0 {
		if val := d.cfDictionaryGetValue(trustResult, kVal); val != 0 && d.cfGetTypeID(val) == d.cfNumberGetTypeID() {
			var rv int64
			if d.cfNumberGetValue(val, kCFNumberSInt64Type, unsafe.Pointer(&rv)) {
				info.resultValue = rv
			}
		}
		d.release(kVal)
	}
	kDet := d.cfString("TrustResultDetails")
	if kDet == 0 {
		return info
	}
	detailsArr := d.cfDictionaryGetValue(trustResult, kDet)
	d.release(kDet)
	if detailsArr == 0 || d.cfGetTypeID(detailsArr) != d.cfArrayGetTypeID() {
		return info
	}
	n := d.cfArrayGetCount(detailsArr)
	if n <= 0 {
		return info
	}
	info.hasDetails = true
	info.allKeySizeCompat = true

	chainLen := 0
	if chain != 0 && d.cfGetTypeID(chain) == d.cfArrayGetTypeID() {
		chainLen = d.cfArrayGetCount(chain)
	}

	dictTypeID := d.cfDictionaryGetTypeID()
	strTypeID := d.cfStringGetTypeID()
	boolTypeID := d.cfBooleanGetTypeID()
	arrTypeID := d.cfArrayGetTypeID()
	numTypeID := d.cfNumberGetTypeID()

	for i := range n {
		elem := d.cfArrayGetValueAtIndex(detailsArr, i)
		if elem == 0 || d.cfGetTypeID(elem) != dictTypeID {
			if info.otherFailureKey == "" {
				info.otherFailureKey = "unknown"
			}
			info.allKeySizeCompat = false
			continue
		}
		cnt := d.cfDictionaryGetCount(elem)
		if cnt <= 0 {
			continue
		}
		keys := make([]uintptr, cnt)
		vals := make([]uintptr, cnt)
		d.cfDictionaryGetKeysAndValues(elem, unsafe.Pointer(&keys[0]), unsafe.Pointer(&vals[0]))
		certHasKeySize := false
		for j := range cnt {
			kRef, v := keys[j], vals[j]
			if kRef == 0 || d.cfGetTypeID(kRef) != strTypeID {
				if info.otherFailureKey == "" {
					info.otherFailureKey = "unknown"
				}
				continue
			}
			k := d.goString(kRef)
			switch k {
			case "KeySize":
				if v != 0 && d.cfGetTypeID(v) == boolTypeID {
					if !d.cfBooleanGetValue(v) {
						certHasKeySize = true
						info.hasKeySizeFail = true
					}
				} else if info.otherFailureKey == "" {
					info.otherFailureKey = k
				}
			case "WeakKeySize":
				certHasKeySize = true
				info.hasKeySizeFail = true
				info.hasWeakKeyFail = true
				info.allKeySizeCompat = false
			case "StatusCodes":
				if v == 0 || d.cfGetTypeID(v) != arrTypeID {
					info.otherStatusCode = true
					continue
				}
				scCount := d.cfArrayGetCount(v)
				for si := range scCount {
					scRef := d.cfArrayGetValueAtIndex(v, si)
					if scRef == 0 || d.cfGetTypeID(scRef) != numTypeID {
						info.otherStatusCode = true
						continue
					}
					var sc int64
					if !d.cfNumberGetValue(scRef, kCFNumberSInt64Type, unsafe.Pointer(&sc)) || sc != cssmErrCSPUnsupportedKeySize {
						info.otherStatusCode = true
					}
				}
			default:
				if info.otherFailureKey == "" {
					info.otherFailureKey = k
				}
			}
		}
		if certHasKeySize {
			if i >= chainLen {
				info.allKeySizeCompat = false
				continue
			}
			certRef := d.cfArrayGetValueAtIndex(chain, i)
			var der []byte
			if certRef != 0 {
				derData := d.secCertificateCopyData(certRef)
				der = d.goBytes(derData)
				d.release(derData)
			}
			cert, err := ParseCertificate(der)
			if err != nil {
				info.allKeySizeCompat = false
				continue
			}
			wk := weakKeySizeErrorFromCert(cert)
			if info.firstKeySizeFail == nil {
				info.firstKeySizeFail = wk
			}
			switch pub := cert.PublicKey.(type) {
			case *rsa.PublicKey:
				if pub == nil || pub.N == nil || pub.N.BitLen() < minCompatRSAKeyBits {
					info.allKeySizeCompat = false
				}
			case *ecdsa.PublicKey:
				if pub == nil || pub.Curve == nil || pub.Curve.Params().BitSize < minCompatECDSAKeyBits {
					info.allKeySizeCompat = false
				}
			default:
				info.allKeySizeCompat = false
			}
		}
	}
	return info
}

func (d *darwinAPI) evaluateTrust(trust uintptr, allowWeakRSA bool) error {
	var cfErr uintptr
	if d.secTrustEvaluateWithError(trust, &cfErr) {
		d.release(cfErr)
		return nil
	}
	code, origErr := d.cfErr(cfErr, "certificate is not trusted")
	d.release(cfErr)

	trustResult := d.secTrustCopyResult(trust)
	defer d.release(trustResult)
	chain := d.secTrustCopyCertificateChain(trust)
	defer d.release(chain)

	info := d.inspectTrustResult(trustResult, chain)
	if allowWeakRSA && info.hasDetails && info.resultValue == kSecTrustResultRecoverableTrustFailure &&
		info.hasKeySizeFail && !info.hasWeakKeyFail && info.otherFailureKey == "" && !info.otherStatusCode && info.allKeySizeCompat {
		return nil
	}
	if allowWeakRSA && code == errSecUnsupportedKeySize && info.allKeySizeCompat {
		return darwinTrustFailureError(info.otherFailureKey)
	}
	if code == errSecUnsupportedKeySize || (info.hasKeySizeFail && (!allowWeakRSA || !info.allKeySizeCompat)) {
		if info.firstKeySizeFail != nil {
			return info.firstKeySizeFail
		}
		return &WeakKeySizeError{}
	}
	return origErr
}

func (d *darwinAPI) copyChainDER(trust uintptr) [][]byte {
	if trust == 0 {
		return nil
	}
	chain := d.secTrustCopyCertificateChain(trust)
	if chain == 0 {
		return nil
	}
	defer d.release(chain)
	if d.cfGetTypeID(chain) != d.cfArrayGetTypeID() {
		return nil
	}
	n := d.cfArrayGetCount(chain)
	if n <= 0 {
		return nil
	}
	out := make([][]byte, 0, n)
	for i := range n {
		certRef := d.cfArrayGetValueAtIndex(chain, i)
		if certRef == 0 {
			continue
		}
		derData := d.secCertificateCopyData(certRef)
		if der := d.goBytes(derData); len(der) > 0 {
			out = append(out, der)
		}
		d.release(derData)
	}
	return out
}

func (p *darwinProvider) VerifyTrust(ctx context.Context, usage, email string, certsDER [][]byte) error {
	_, err := p.VerifyTrustWithChain(ctx, usage, email, certsDER)
	return err
}

func (p *darwinProvider) VerifyTrustWithChain(ctx context.Context, usage, email string, certsDER [][]byte) ([][]byte, error) {
	d, err := loadDarwinAPI()
	if err != nil {
		return nil, err
	}
	if email == "" || len(certsDER) == 0 {
		return nil, errors.New("missing S/MIME certificate or email address")
	}
	var usageKey uintptr
	switch usage {
	case "sign":
		usageKey = d.kSecPolicyKUDigitalSig
	case "encrypt":
		usageKey = d.kSecPolicyKUKeyEncipherment
	default:
		return nil, errors.New("unknown certificate usage")
	}
	cfEmail := d.cfString(email)
	if cfEmail == 0 {
		return nil, errors.New("unable to create email string")
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
			return nil, errors.New("invalid X.509 certificate")
		}
		certs = append(certs, cert)
	}
	cfCerts := d.cfArrayCreate(0, unsafe.Pointer(&certs[0]), len(certs), d.kCFTypeArrayCB)
	if cfCerts == 0 {
		return nil, errors.New("unable to build certificate list")
	}
	defer d.release(cfCerts)

	props := d.cfDict([]uintptr{d.kSecPolicyName, usageKey}, []uintptr{cfEmail, d.kCFBooleanTrue})
	if props == 0 {
		return nil, errors.New("unable to create S/MIME trust policy")
	}
	defer d.release(props)

	policy := d.secPolicyCreateWithProperties(d.kSecPolicyAppleSMIME, props)
	if policy == 0 {
		return nil, errors.New("unable to create S/MIME trust policy")
	}
	defer d.release(policy)

	var trust uintptr
	if st := d.secTrustCreateWithCertificates(cfCerts, policy, &trust); st != errSecSuccess || trust == 0 {
		d.release(trust)
		if st != errSecSuccess {
			return nil, d.secErr(st)
		}
		return nil, errors.New("unable to evaluate certificate trust")
	}
	defer d.release(trust)

	if st := d.secTrustSetNetworkFetchAllowed(trust, false); st != errSecSuccess {
		return nil, d.secErr(st)
	}
	evalErr := d.evaluateTrust(trust, AllowWeakKeySize(ctx))
	return d.copyChainDER(trust), evalErr
}

func (p *darwinProvider) VerifyCMS(ctx context.Context, email string, cmsDER, detached []byte) (cmsVerifyResult, error) {
	d, err := loadDarwinAPI()
	if err != nil {
		return cmsVerifyResult{}, err
	}
	if len(cmsDER) == 0 {
		return cmsVerifyResult{}, errors.New("missing signature data")
	}

	var decoder uintptr
	if st := d.cmsDecoderCreate(&decoder); st != errSecSuccess || decoder == 0 {
		d.release(decoder)
		return cmsVerifyResult{}, d.secErr(st)
	}
	defer d.release(decoder)

	if st := d.cmsDecoderUpdateMessage(decoder, unsafe.Pointer(&cmsDER[0]), uintptr(len(cmsDER))); st != errSecSuccess {
		return cmsVerifyResult{}, d.secErr(st)
	}
	if st := d.cmsDecoderFinalizeMessage(decoder); st != errSecSuccess {
		return cmsVerifyResult{}, d.secErr(st)
	}

	var signers uintptr
	signerErr := error(nil)
	if st := d.cmsDecoderGetNumSigners(decoder, &signers); st != errSecSuccess {
		signerErr = d.secErr(st)
	} else if signers != 1 {
		signerErr = errors.New("unable to identify unique S/MIME signer")
	}

	if detached != nil {
		var preStatus uint32
		if st := d.cmsDecoderCopySignerStatus(decoder, 0, 0, false, &preStatus, nil, nil); st == errSecSuccess && preStatus != kCMSSignerNeedsDetachedContent {
			return cmsVerifyResult{}, errors.New("detached signature unexpectedly contains embedded content")
		}
		cfDetached := d.cfData(detached)
		if cfDetached == 0 {
			return cmsVerifyResult{}, errors.New("unable to read detached signature content")
		}
		st := d.cmsDecoderSetDetachedContent(decoder, cfDetached)
		d.release(cfDetached)
		if st != errSecSuccess {
			return cmsVerifyResult{}, d.secErr(st)
		}
	}

	var contentBytes []byte
	if detached != nil {
		contentBytes = detached
	} else {
		var content uintptr
		if st := d.cmsDecoderCopyContent(decoder, &content); st != errSecSuccess {
			d.release(content)
			return cmsVerifyResult{}, d.secErr(st)
		}
		if content == 0 {
			return cmsVerifyResult{}, errors.New("signature contains no content")
		}
		contentBytes = d.goBytes(content)
		d.release(content)
	}

	var signerDER []byte
	if signers == 1 {
		var signerRef uintptr
		if st := d.cmsDecoderCopySignerCert(decoder, 0, &signerRef); st == errSecSuccess && signerRef != 0 {
			certData := d.secCertificateCopyData(signerRef)
			signerDER = d.goBytes(certData)
			d.release(certData)
			d.release(signerRef)
		} else {
			d.release(signerRef)
		}
	}

	var chainDER [][]byte
	verifyErr := signerErr
	if verifyErr == nil && email == "" {
		verifyErr = errors.New("signed message lacks a unique sender address")
	}
	if verifyErr == nil {
		cfEmail := d.cfString(email)
		if cfEmail == 0 {
			return cmsVerifyResult{content: contentBytes, signerDER: signerDER, verifyErr: errors.New("unable to create email string")}, nil
		}
		defer d.release(cfEmail)

		props := d.cfDict([]uintptr{d.kSecPolicyName, d.kSecPolicyKUDigitalSig}, []uintptr{cfEmail, d.kCFBooleanTrue})
		if props == 0 {
			return cmsVerifyResult{content: contentBytes, signerDER: signerDER, verifyErr: errors.New("unable to create S/MIME trust policy")}, nil
		}
		defer d.release(props)

		policy := d.secPolicyCreateWithProperties(d.kSecPolicyAppleSMIME, props)
		if policy == 0 {
			return cmsVerifyResult{content: contentBytes, signerDER: signerDER, verifyErr: errors.New("unable to create S/MIME trust policy")}, nil
		}
		defer d.release(policy)

		var status uint32
		var trust uintptr
		if st := d.cmsDecoderCopySignerStatus(decoder, 0, policy, false, &status, &trust, nil); st != errSecSuccess {
			d.release(trust)
			verifyErr = d.secErr(st)
		} else {
			defer d.release(trust)
			if status != kCMSSignerValid || trust == 0 {
				verifyErr = errors.New("invalid S/MIME signature")
			} else if st := d.secTrustSetNetworkFetchAllowed(trust, false); st != errSecSuccess {
				verifyErr = d.secErr(st)
			} else {
				evalErr := d.evaluateTrust(trust, AllowWeakKeySize(ctx))
				chainDER = d.copyChainDER(trust)
				if evalErr != nil {
					verifyErr = evalErr
				} else {
					var signer uintptr
					if st := d.cmsDecoderCopySignerCert(decoder, 0, &signer); st != errSecSuccess {
						d.release(signer)
						verifyErr = d.secErr(st)
					} else if signer == 0 {
						verifyErr = errors.New("missing signer certificate")
					} else {
						defer d.release(signer)
						if len(signerDER) == 0 {
							certData := d.secCertificateCopyData(signer)
							signerDER = d.goBytes(certData)
							d.release(certData)
						}

						var addrs uintptr
						if st := d.secCertificateCopyEmailAddresses(signer, &addrs); st != errSecSuccess {
							d.release(addrs)
							verifyErr = d.secErr(st)
						} else {
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
							if !matched && len(signerDER) > 0 {
								if cert, err := ParseCertificate(signerDER); err == nil && MatchesMailbox(cert, email) {
									matched = true
								}
							}
							if !matched {
								verifyErr = errors.New("signer certificate email does not match sender")
							}
						}
					}
				}
			}
		}
	}
	return cmsVerifyResult{content: contentBytes, signerDER: signerDER, chainDER: chainDER, verifyErr: verifyErr}, nil
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
