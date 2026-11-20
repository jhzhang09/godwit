package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emmansun/gmsm/pkcs7"
	"github.com/godwit-email/godwit/core"
	"github.com/godwit-email/godwit/core/coretest"
	"github.com/godwit-email/godwit/internal/i18n"
	"github.com/godwit-email/godwit/internal/smime"
)

func makeRawSMIME(from, to, id, subject, payload string) []byte {
	b64 := base64.StdEncoding.EncodeToString([]byte(payload))
	return []byte(fmt.Sprintf(
		"Message-ID: <%s>\r\nFrom: %s\r\nTo: %s\r\nSubject: %s\r\nDate: Mon, 05 Oct 2026 09:00:00 +0000\r\nMIME-Version: 1.0\r\nContent-Type: application/pkcs7-mime; smime-type=enveloped-data; name=\"smime.p7m\"\r\nContent-Transfer-Encoding: base64\r\n\r\n%s\r\n",
		id, from, to, subject, b64,
	))
}

func callIndex(calls []string, want string) int {
	for i, c := range calls {
		if c == want {
			return i
		}
	}
	return -1
}

func TestReaderSMIMEStartsBeforeNewBodyViewAndBuffersEarlyCompletion(t *testing.T) {
	h, accs := mailHarness(t, nil, "alice@example.com")
	h.app.cards = smime.NewSession(h.app.ctx)

	msg := h.deliverOne(accs[0], makeRawSMIME("bob@example.com", accs[0].Email, "s1@x", "Secret 1", "cipher-1"))

	r := h.app.mail.reader
	openStarted := make(chan struct{})
	openDone := make(chan struct{})
	r.openCMS = func(ctx context.Context, fromHeader string, der []byte) ([]byte, bool, string, error) {
		close(openStarted)
		defer close(openDone)
		return []byte("Content-Type: text/html; charset=utf-8\r\n\r\n<p>early body</p>"), true, "bob@example.com", nil
	}

	h.plat.onNewView = func(message int64) {
		if message != msg.ID {
			return
		}
		select {
		case <-openStarted:
		case <-time.After(2 * time.Second):
			t.Fatal("openSMIME did not start before NewBodyView")
		}
		// Pump the UI queue so openSMIME's completion runs BEFORE NewBodyView returns.
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			select {
			case <-openDone:
			default:
				time.Sleep(time.Millisecond)
				continue
			}
			h.drain()
			if b := r.bodies[msg.ID]; b != nil && b.smimePending != nil {
				return
			}
			time.Sleep(time.Millisecond)
		}
		t.Fatal("openSMIME completion was not buffered into smimePending before NewBodyView returned")
	}

	h.openThread(msg.ThreadID)
	wantNew := fmt.Sprintf("NewBodyView %d", msg.ID)
	wantShow := fmt.Sprintf("ShowSecureBody %d", msg.ID)
	h.until("ShowSecureBody after NewBodyView", func() bool {
		return callIndex(h.plat.Calls(), wantShow) >= 0
	})

	calls := h.plat.Calls()
	ni, si := callIndex(calls, wantNew), callIndex(calls, wantShow)
	if ni < 0 || si < 0 || ni >= si {
		t.Fatalf("calls = %v; want %s before %s", calls, wantNew, wantShow)
	}
	b := r.bodies[msg.ID]
	if b == nil || b.smimeResult == nil || !b.smimeResult.encrypted || b.smimePending != nil {
		t.Fatalf("unexpected smime body state: %+v", b)
	}
}

func TestReaderSMIMEDeliversAfterNewBodyViewAndReusesMemoryCacheOnReexpand(t *testing.T) {
	h, accs := mailHarness(t, nil, "alice@example.com")
	h.app.cards = smime.NewSession(h.app.ctx)

	msg := h.deliverOne(accs[0], makeRawSMIME("bob@example.com", accs[0].Email, "s2@x", "Secret 2", "cipher-2"))

	r := h.app.mail.reader
	var openCalls atomic.Int32
	allowOpen := make(chan struct{})
	openStarted := make(chan struct{})
	r.openCMS = func(ctx context.Context, fromHeader string, der []byte) ([]byte, bool, string, error) {
		openCalls.Add(1)
		close(openStarted)
		select {
		case <-allowOpen:
		case <-ctx.Done():
			return nil, false, "", ctx.Err()
		}
		return []byte("Content-Type: text/plain; charset=utf-8\r\n\r\nlate body"), true, "bob@example.com", nil
	}

	h.plat.onNewView = func(message int64) {
		if message == msg.ID {
			select {
			case <-openStarted:
			case <-time.After(2 * time.Second):
				t.Fatal("openSMIME did not start before NewBodyView")
			}
		}
	}

	h.openThread(msg.ThreadID)
	h.until("NewBodyView created", func() bool {
		return callIndex(h.plat.Calls(), fmt.Sprintf("NewBodyView %d", msg.ID)) >= 0
	})
	if callIndex(h.plat.Calls(), fmt.Sprintf("ShowSecureBody %d", msg.ID)) >= 0 {
		t.Fatal("ShowSecureBody fired before decryption completed")
	}

	close(allowOpen)
	h.until("ShowSecureBody after decryption completes", func() bool {
		return callIndex(h.plat.Calls(), fmt.Sprintf("ShowSecureBody %d", msg.ID)) >= 0
	})
	if openCalls.Load() != 1 {
		t.Fatalf("openCalls = %d, want 1", openCalls.Load())
	}

	// 折叠再重新展开，应命中内存缓存并紧随新 NewBodyView 后交付，且不再次调用 openCMS。
	h.plat.onNewView = nil
	r.toggle(msg.ID)
	h.tt.Frame()
	r.toggle(msg.ID)
	wantShow := fmt.Sprintf("ShowSecureBody %d", msg.ID)
	h.until("second ShowSecureBody from memory cache", func() bool {
		return h.countCalls(wantShow) == 2
	})
	if openCalls.Load() != 1 {
		t.Fatalf("openCalls after re-expand = %d, want 1", openCalls.Load())
	}
}

func TestReaderSMIMENewBodyViewErrorAndSwitchStopsDecryption(t *testing.T) {
	t.Run("view_error", func(t *testing.T) {
		h, accs := mailHarness(t, nil, "alice@example.com")
		h.app.cards = smime.NewSession(h.app.ctx)
		msg := h.deliverOne(accs[0], makeRawSMIME("bob@example.com", accs[0].Email, "s3@x", "Secret 3", "cipher-3"))

		r := h.app.mail.reader
		started := make(chan struct{})
		cancelled := make(chan struct{})
		r.openCMS = func(ctx context.Context, fromHeader string, der []byte) ([]byte, bool, string, error) {
			close(started)
			<-ctx.Done()
			close(cancelled)
			return nil, false, "", ctx.Err()
		}
		h.plat.onNewView = func(message int64) {
			if message == msg.ID {
				select {
				case <-started:
				case <-time.After(2 * time.Second):
					t.Fatal("openSMIME did not start before NewBodyView")
				}
			}
		}
		h.plat.viewErr = errors.New("webview boom")

		h.openThread(msg.ThreadID)
		h.until("body error set", func() bool {
			b := r.bodies[msg.ID]
			return b != nil && b.err != nil
		})
		select {
		case <-cancelled:
		case <-time.After(2 * time.Second):
			t.Fatal("smime decryption context not cancelled on NewBodyView error")
		}
		b := r.bodies[msg.ID]
		if b.smimePending != nil || h.countCalls(fmt.Sprintf("ShowSecureBody %d", msg.ID)) != 0 {
			t.Fatalf("unexpected secure delivery after NewBodyView error: %+v calls=%v", b, h.plat.Calls())
		}
	})

	t.Run("switch_during_view", func(t *testing.T) {
		h, accs := mailHarness(t, nil, "alice@example.com")
		h.app.cards = smime.NewSession(h.app.ctx)
		msg := h.deliverOne(accs[0], makeRawSMIME("bob@example.com", accs[0].Email, "s4@x", "Secret 4", "cipher-4"))

		r := h.app.mail.reader
		started := make(chan struct{})
		cancelled := make(chan struct{})
		r.openCMS = func(ctx context.Context, fromHeader string, der []byte) ([]byte, bool, string, error) {
			close(started)
			<-ctx.Done()
			close(cancelled)
			return nil, false, "", ctx.Err()
		}
		h.plat.onNewView = func(message int64) {
			if message == msg.ID {
				select {
				case <-started:
				case <-time.After(2 * time.Second):
					t.Fatal("openSMIME did not start before NewBodyView")
				}
				// 模拟在创建 NewBodyView 期间会话已被切走。
				r.reset([2]int64{})
			}
		}

		h.openThread(msg.ThreadID)
		h.until("NewBodyView attempted", func() bool {
			return callIndex(h.plat.Calls(), fmt.Sprintf("NewBodyView %d", msg.ID)) >= 0
		})
		select {
		case <-cancelled:
		case <-time.After(2 * time.Second):
			t.Fatal("smime decryption context not cancelled on session switch during NewBodyView")
		}
		if h.countCalls(fmt.Sprintf("ShowSecureBody %d", msg.ID)) != 0 {
			t.Fatalf("stale ShowSecureBody emitted: %v", h.plat.Calls())
		}
	})
}

func TestReaderSMIMEDefersAutoAIAndEnablesTranslateAndSummary(t *testing.T) {
	h, acc, llm := aiHarness(t, true, noQuick)
	h.app.cards = smime.NewSession(h.app.ctx)

	msg := h.deliverOne(acc, makeRawSMIME("bob@example.com", acc.Email, "ai-s1@x", "Encrypted Plan", "cipher"))
	other := h.deliverOne(acc, coretest.Msg("carol@example.com", acc.Email, "Plain Note", "plain body"))
	h.waitMail("both messages listed", func() bool { return len(h.items()) == 2 })

	// 列表条目应区分加密标识与真实附件标识：纯 smime.p7m 邮件不显示回形针。
	bySub := map[string]mailItem{}
	for _, it := range h.items() {
		bySub[it.Subject] = it
	}
	if bySub["Encrypted Plan"].Attach || bySub["Encrypted Plan"].SMIME != "encrypted" {
		t.Fatalf("encrypted item = %+v; want Attach=false SMIME=encrypted", bySub["Encrypted Plan"])
	}
	if signedAtt := threadItem(core.ThreadSummary{ID: 99, HasAttachments: true, SMIME: "signed"}); !signedAtt.Attach || signedAtt.SMIME != "signed" {
		t.Fatalf("signed+att item = %+v; want Attach=true SMIME=signed", signedAtt)
	}

	r := h.app.mail.reader
	var openStarted atomic.Bool
	allowOpen := make(chan struct{})
	r.openCMS = func(ctx context.Context, fromHeader string, der []byte) ([]byte, bool, string, error) {
		openStarted.Store(true)
		<-allowOpen
		return []byte("Content-Type: text/html; charset=utf-8\r\n\r\n<p>Secret project launch is Monday.</p>"), true, "bob@example.com", nil
	}

	llm.Script(
		coretest.Turn{Text: []string{"- Secret launch confirmed for Monday."}},
		coretest.Turn{Text: []string{`{"texts":["秘密发布定于周一。"],"source":"en"}`}},
		coretest.Turn{Text: []string{"- Plain note summary."}},
	)

	h.openThread(msg.ThreadID)
	h.until("openCMS started", openStarted.Load)
	if got := llm.Requests(); got != 0 {
		t.Fatalf("auto-summary fired before decryption finished (%d LLM requests)", got)
	}

	close(allowOpen)
	h.until("decrypted body shown and summary completed", func() bool {
		st := r.ai[msg.ID]
		return st != nil && st.summary != nil && st.summary.done && h.countCalls(fmt.Sprintf("ShowSecureBody %d", msg.ID)) >= 1
	})
	h.see("Secret launch confirmed for Monday.")

	h.click("翻译")
	h.seeTranslation(msg.ID, "秘密发布定于周一。")

	reqs := llm.RequestLog()
	if len(reqs) != 2 {
		t.Fatalf("LLM requests = %d, want 2", len(reqs))
	}
	for i, req := range reqs {
		body := string(req.Messages)
		if !strings.Contains(body, "Secret project launch is Monday.") || strings.Contains(body, "smime.p7m") {
			t.Fatalf("request %d did not carry decrypted text: %q", i, body)
		}
	}

	// 切换走再切回：命中前端内存缓存时仍会重同步到后端，无需再次访问硬件 Key，且关闭会话时不落盘。
	h.openThread(other.ThreadID)
	h.seeBody(other.ID)
	h.openThread(msg.ThreadID)
	h.until("cache-hit re-sync complete", func() bool {
		b := r.bodies[msg.ID]
		return b != nil && b.smimeResult != nil && b.smimeSynced
	})
	h.see("Secret launch confirmed for Monday.")
}

func TestSMIMECopyAndStandardWorkflows(t *testing.T) {
	// 1. All 15 catalog locales must translate standard S/MIME keys without legacy folder/hardware-only phrases.
	prevLang := i18n.Language()
	t.Cleanup(func() { i18n.SetLanguage(prevLang) })
	keys := []string{
		"smime.sign", "smime.sign.help", "smime.encrypt", "smime.encrypt.help",
		"smime.allow_weak_key", "smime.allow_weak_key.help", "smime.err.weak_key_size_generic",
		"smime.cert", "smime.cert.help", "smime.cert.view", "smime.cert.detail_title",
		"smime.contacts.title", "smime.contacts.empty", "smime.compose.sign", "smime.compose.encrypt",
	}
	forbidden := []string{"邮箱名片", "旧卡", "舊卡", "硬件 Key", "硬體金鑰", "hardware key"}
	langs := i18n.Catalog.Languages()
	if len(langs) < 15 {
		t.Fatalf("expected all 15 locales in i18n.Catalog, got %v", langs)
	}
	for _, lang := range langs {
		i18n.SetLanguage(lang)
		for _, k := range keys {
			txt := i18n.T(k)
			if txt == "" || txt == k {
				t.Fatalf("missing i18n.T(%q) for %q", k, lang)
			}
			low := strings.ToLower(txt)
			for _, bad := range forbidden {
				if strings.Contains(low, strings.ToLower(bad)) {
					t.Fatalf("legacy copy %q found in i18n.T(%q) for %q: %q", bad, k, lang, txt)
				}
			}
		}
	}
	i18n.SetLanguage("zh-Hans")

	if !smime.Supported() {
		t.Skip("S/MIME not supported on this platform")
	}

	h, accs := mailHarness(t, nil, "alice@example.com")
	acc := accs[0]
	h.app.cards = smime.NewSession(h.app.ctx)

	// Deliver mail from bob@example.com so bob appears in Contacts and verify RecordSMIMESignerCert.
	msg := h.deliverOne(acc, coretest.Msg("Bob <bob@example.com>", acc.Email, "Hello", "hi"))

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	requireReader := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	requireReader(err)
	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(777),
		Subject:        pkix.Name{CommonName: "Bob Signer"},
		EmailAddresses: []string{"bob@example.com"},
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(24 * time.Hour),
		KeyUsage:       x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}
	bobDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	requireReader(err)
	requireReader(h.env.Svc.RecordSMIMESignerCert(context.Background(), "Bob <bob@example.com>", bobDER))

	// Open Settings > Account and verify standard S/MIME copy + personal cert selector.
	h.openSettings(accountRoute(acc.ID))
	h.see("个人 S/MIME 证书")
	h.see("默认对发出邮件进行数字签名")
	h.see("默认对发出邮件进行加密")
	h.see("兼容 1024 位旧证书")

	// Return to mail sidebar, open Contacts, and verify bob@example.com S/MIME certificate panel + import + select + remove.
	h.resize(1440, 2000)
	_ = msg
	h.click("返回邮件")
	h.click("联系人")
	h.until("bob certs loaded", func() bool {
		return h.app.contacts().certsOf == "bob@example.com" && !h.app.contacts().certsLoading
	})
	h.see("S/MIME 公钥证书")
	h.see("Bob Signer")
	h.see("签名邮件")

	// View contact certificate details from Contacts and dismiss dialog.
	h.click("查看证书")
	h.until("contact cert dialog open", func() bool {
		return h.tt.HasText("证书详情") && h.tt.HasText("RSA (2048 bit)")
	})
	h.see("03:09")
	h.click("关闭")
	h.until("contact cert dialog closed", func() bool {
		return !h.app.smimeCertOpen && !h.tt.HasText("证书详情")
	})

	// Import another certificate file for bob via OpenFiles mock.
	impKey, err := rsa.GenerateKey(rand.Reader, 2048)
	requireReader(err)
	impTmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(778),
		Subject:        pkix.Name{CommonName: "Bob Imported"},
		EmailAddresses: []string{"bob@example.com"},
		NotBefore:      time.Now().Add(-30 * time.Minute),
		NotAfter:       time.Now().Add(24 * time.Hour),
		KeyUsage:       x509.KeyUsageKeyEncipherment,
	}
	impDER, err := x509.CreateCertificate(rand.Reader, impTmpl, impTmpl, &impKey.PublicKey, impKey)
	requireReader(err)
	certFile := filepath.Join(t.TempDir(), "bob_imported.cer")
	requireReader(os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: impDER}), 0o600))
	h.plat.mu.Lock()
	h.plat.files = []string{certFile}
	h.plat.mu.Unlock()

	h.click("导入证书")
	h.until("imported cert visible", func() bool {
		return h.tt.HasText("Bob Imported")
	})
	h.see("手动导入")
}

func TestReaderSMIMEUnverifiedSignatureShowsDecryptedAndDetails(t *testing.T) {
	if !smime.Supported() {
		t.Skip("S/MIME not supported on this platform")
	}
	h, accs := mailHarness(t, nil, "alice@example.com")
	h.app.cards = smime.NewSession(h.app.ctx)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(901),
		Subject:        pkix.Name{CommonName: "Bob Bad Sig"},
		EmailAddresses: []string{"bob@example.com"},
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(24 * time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := smime.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := pkcs7.NewSignedData([]byte("Content-Type: text/html; charset=utf-8\r\n\r\n<p>Body visible despite bad sig</p>"))
	if err != nil {
		t.Fatal(err)
	}
	sd.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	if err := sd.AddSigner(cert, key, pkcs7.SignerInfoConfig{}); err != nil {
		t.Fatal(err)
	}
	cms, err := sd.Finish()
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.ReplaceAll(cms, []byte("Body visible"), []byte("Text visible"))
	msg := h.deliverOne(accs[0], makeRawSMIME("Bob <bob@example.com>", accs[0].Email, "bad-sig@x", "Signed Report", string(tampered)))

	h.openThread(msg.ThreadID)
	wantShow := fmt.Sprintf("ShowSecureBody %d", msg.ID)
	h.until("unverified signed content displayed", func() bool {
		return callIndex(h.plat.Calls(), wantShow) >= 0 && h.tt.HasText("无法验证邮件签名")
	})

	// Unverified signer certs must NOT be stored as trusted mail_sig certificates.
	rcpts, err := h.env.Svc.ListContactCertificates(context.Background(), []string{"bob@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rcpts) > 0 && len(rcpts[0].Certs) > 0 {
		t.Fatalf("unverified signer cert was recorded: %+v", rcpts[0].Certs)
	}

	h.click("显示详细信息")
	h.see("请谨慎核实发件人身份与内容完整性")
	h.click("查看证书")
	h.until("unverified cert dialog open", func() bool {
		return h.tt.HasText("证书详情") && h.tt.HasText("Bob Bad Sig")
	})
	h.see("未通过系统信任验证")
	h.see("03:85")
	h.see("RSA (2048 bit)")
	h.click("复制指纹")
	h.until("copied fp", func() bool { return h.tt.Clipboard() != "" })
	h.click("关闭")
	h.until("unverified cert dialog closed", func() bool {
		return !h.app.smimeCertOpen && !h.tt.HasText("证书详情")
	})
	h.see("隐藏详细信息")
	h.click("隐藏详细信息")
	h.see("显示详细信息")
}

func TestReaderSMIMEVerifiedSignatureViewCert(t *testing.T) {
	if !smime.Supported() {
		t.Skip("S/MIME not supported on this platform")
	}
	h, accs := mailHarness(t, nil, "alice@example.com")
	h.app.cards = smime.NewSession(h.app.ctx)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test Root CA"},
	}
	leafTmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(0x12AB),
		Subject:        pkix.Name{CommonName: "Bob Verified"},
		EmailAddresses: []string{"bob@example.com"},
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(24 * time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
	}
	bobDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caTmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	h.app.mail.reader.openCMSFull = func(ctx context.Context, fromHeader string, der []byte) (smime.Opened, error) {
		return smime.Opened{
			Entity:     []byte("Content-Type: text/html; charset=utf-8\r\n\r\n<p>Trusted verified content</p>"),
			Encrypted:  true,
			Signer:     "bob@example.com",
			SignerCert: bobDER,
		}, nil
	}
	msg := h.deliverOne(accs[0], makeRawSMIME("Bob <bob@example.com>", accs[0].Email, "verified@x", "Signed and Encrypted", "opaque-cms"))

	h.openThread(msg.ThreadID)
	wantShow := fmt.Sprintf("ShowSecureBody %d", msg.ID)
	h.until("verified signature banner rendered", func() bool {
		return callIndex(h.plat.Calls(), wantShow) >= 0 && h.tt.HasText("签名已验证 · bob@example.com")
	})
	h.see("已解密")
	h.see("查看证书")

	// Clicking the verified signature label directly opens Certificate Details (Mac Mail style).
	h.click("签名已验证 · bob@example.com")
	h.until("verified cert dialog open", func() bool {
		return h.tt.HasText("证书详情") && h.tt.HasText("Bob Verified")
	})
	h.see("签名已验证且证书受信任")
	h.see("Test Root CA")
	h.see("12:AB")
	h.see("RSA (2048 bit)")
	h.click("复制指纹")
	wantFP := strings.ToUpper(smime.CertSHA256(bobDER))
	h.until("sha256 copied", func() bool {
		return strings.ReplaceAll(h.tt.Clipboard(), ":", "") == wantFP
	})
	h.click("关闭")
	h.until("verified cert dialog closed", func() bool {
		return !h.app.smimeCertOpen && !h.tt.HasText("证书详情")
	})
}

func TestReaderSMIMEWeakKeyWarningAndAccountCompat(t *testing.T) {
	if !smime.Supported() {
		t.Skip("S/MIME not supported on this platform")
	}
	prevLang := i18n.Language()
	t.Cleanup(func() { i18n.SetLanguage(prevLang) })
	i18n.SetLanguage("zh-Hans")

	h, accs := mailHarness(t, nil, "alice@example.com")
	h.app.cards = smime.NewSession(h.app.ctx)

	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(0x1024),
		Subject:        pkix.Name{CommonName: "yczhang"},
		EmailAddresses: []string{"bob@example.com"},
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(24 * time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
	}
	bobDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, leafTmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	var calls atomic.Int32
	var sawAllowTrue atomic.Bool
	h.app.mail.reader.openCMSFull = func(ctx context.Context, fromHeader string, der []byte) (smime.Opened, error) {
		calls.Add(1)
		if smime.AllowWeakKeySize(ctx) {
			sawAllowTrue.Store(true)
			return smime.Opened{
				Entity:     []byte("Content-Type: text/html; charset=utf-8\r\n\r\n<p>Compat verified</p>"),
				Encrypted:  true,
				Signer:     "bob@example.com",
				SignerCert: bobDER,
			}, nil
		}
		wk := &smime.WeakKeySizeError{Subject: "yczhang", KeyAlgo: "RSA", KeyBits: 1024, MinBits: 2048}
		return smime.Opened{
			Entity:         []byte("Content-Type: text/html; charset=utf-8\r\n\r\n<p>Unverified 1024</p>"),
			Encrypted:      true,
			VerifyErr:      wk.Error(),
			VerifyErrCause: wk,
			UnverifiedCert: bobDER,
		}, nil
	}
	msg := h.deliverOne(accs[0], makeRawSMIME("Bob <bob@example.com>", accs[0].Email, "weak1024@x", "Legacy 1024 Mail", "opaque-cms"))

	h.openThread(msg.ThreadID)
	wantShow := fmt.Sprintf("ShowSecureBody %d", msg.ID)
	h.until("unverified 1024 banner rendered", func() bool {
		return callIndex(h.plat.Calls(), wantShow) >= 0 && h.tt.HasText("已解密 · 无法验证邮件签名")
	})
	h.click("显示详细信息")
	h.see("“yczhang”证书的密钥长度过短（RSA 1024 bit，系统要求至少 2048 位）")
	if h.tt.HasText("无效的密钥大小") {
		t.Fatal("must not display Apple's misleading translation 无效的密钥大小")
	}

	// Enabling SMIMEAllowWeakKey in Account Settings invalidates the reader secure cache
	// and re-runs verification with AllowWeakKeySize(ctx) == true.
	h.openSettings(accountRoute(accs[0].ID))
	h.see("兼容 1024 位旧证书")
	h.click("兼容 1024 位旧证书")
	h.until("account compat saved", func() bool {
		for _, a := range h.app.accounts {
			if a.ID == accs[0].ID {
				return a.SMIMEAllowWeakKey
			}
		}
		return false
	})

	h.click("返回邮件")
	h.openThread(msg.ThreadID)
	h.until("compat verified banner rendered", func() bool {
		return sawAllowTrue.Load() && h.tt.HasText("签名已验证 · bob@example.com") && !h.tt.HasText("无法验证邮件签名")
	})
	if calls.Load() < 2 {
		t.Fatalf("expected openCMSFull to re-run after toggling compat, got %d calls", calls.Load())
	}
}
