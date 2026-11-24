package core

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/egoist/mygo/plugins/sqlite"
	"github.com/emmansun/gmsm/pkcs7"
	"github.com/godwit-email/godwit/core/gateway"
	"github.com/godwit-email/godwit/core/internal/testllm"
	gomail "github.com/godwit-email/godwit/core/mail"
	"github.com/godwit-email/godwit/core/store"
	"github.com/godwit-email/godwit/internal/carddav"
	"github.com/godwit-email/godwit/internal/i18n"
	"github.com/godwit-email/godwit/internal/smime"
	"io"
	"math/big"
	"net/mail"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSMIMEMailboxCertificates(t *testing.T) {
	e := newSendEnv(t, false)
	const folder = "INBOX/邮箱名片"
	require.NoError(t, e.im.User.Create(folder, nil))
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), EmailAddresses: []string{"bob@example.com"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageKeyEncipherment}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	b64 := base64.StdEncoding.EncodeToString(der)
	card := "BEGIN:VCARD\r\nVERSION:2.1\r\nKEY;X509;ENCODING=BASE64:\r\n " + b64[:64] + "\r\n " + b64[64:] + "\r\nEMAIL;PREF;INTERNET:bob@example.com\r\nEMAIL:eve@example.com\r\nEND:VCARD\r\n"
	sample := withAttachments("contact@test", "business card", 1)
	sample = strings.ReplaceAll(sample, "application/pdf", "application/octet-stream")
	sample = strings.ReplaceAll(sample, "f0.pdf", "contact.vcf")
	e.put(t, folder, strings.ReplaceAll(sample, "JVBERi0xLjQK", base64.StdEncoding.EncodeToString([]byte(card))))
	e.sync(t)
	got, err := e.s.mailboxCertificates(t.Context(), e.acc.ID, []string{"BOB@example.com", "eve@example.com"})
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Len(t, got["bob@example.com"], 1)
	require.Equal(t, der, got["bob@example.com"][0].Raw)
}

func TestSMIMEFailureKeepsDraft(t *testing.T) {
	e := newSendEnv(t, false)
	ctx := WithUISession(t.Context(), e.s)
	d, err := e.s.NewDraft(ctx, e.acc.ID, "new", 0)
	require.NoError(t, err)
	d.To = []string{"missing@example.com"}
	d.Subject = "protected"
	d.HTML = "<p>hello</p>"
	d, err = e.s.SaveDraft(ctx, d)
	require.NoError(t, err)
	for _, cfg := range []struct{ sign, encrypt bool }{{true, false}, {false, true}, {true, true}} {
		t.Run(fmt.Sprintf("sign=%t/encrypt=%t", cfg.sign, cfg.encrypt), func(t *testing.T) {
			acc, err := e.s.UpdateAccount(ctx, e.acc.ID, AccountPatch{SMIMESign: &cfg.sign, SMIMEEncrypt: &cfg.encrypt})
			require.NoError(t, err)
			require.Equal(t, cfg.sign, acc.SMIMESign)
			require.Equal(t, cfg.encrypt, acc.SMIMEEncrypt)
			err = e.s.SendRevision(ctx, d.ID, d.Revision)
			if cfg.encrypt {
				require.ErrorContains(t, err, "missing@example.com")
			} else {
				require.Error(t, err)
			}
			require.ErrorIs(t, e.s.Send(t.Context(), d.ID), ErrSMIMEManualSend)
			require.Empty(t, e.rows(t, "SELECT id FROM outbox"))
			saved, err := e.s.GetDraft(ctx, d.ID)
			require.NoError(t, err)
			require.Equal(t, d.Revision, saved.Revision)
		})
	}
	off := false
	_, err = e.s.UpdateAccount(ctx, e.acc.ID, AccountPatch{SMIMESign: &off, SMIMEEncrypt: &off})
	require.NoError(t, err)
	require.NoError(t, e.s.SendRevision(ctx, d.ID, d.Revision))
	require.Len(t, e.rows(t, "SELECT id FROM outbox"), 1)
}

// 可选的真机验收只操作临时账户和本地 IMAP。出站数据在队列中检查，不投递。
func TestSMIMEHardwareOutbox(t *testing.T) {
	if os.Getenv("GODWIT_TEST_SMIME_TOKEN") != "1" {
		t.Skip("需要用户授权及硬件 Key")
	}
	path := os.Getenv("GODWIT_TEST_SMIME_VCARD")
	from := os.Getenv("GODWIT_TEST_SMIME_FROM")
	if path == "" || from == "" {
		t.Skip("需要收件人公开名片及测试发件地址")
	}
	vcf, err := os.ReadFile(path)
	require.NoError(t, err)
	card := carddav.ParseVCard(string(vcf))
	require.NotEmpty(t, card.Emails)
	to := card.Emails[0].Address
	require.False(t, strings.EqualFold(to, from))
	e := newSendEnv(t, false)
	ctx := WithUISession(t.Context(), e.s)
	_, err = e.s.db.Execute(ctx, "UPDATE accounts SET email=? WHERE id=?", from, e.acc.ID)
	require.NoError(t, err)
	require.NoError(t, e.im.User.Create("邮箱名片", nil))
	sample := strings.NewReplacer("application/pdf", "text/x-vcard", "f0.pdf", "test.vcf", "JVBERi0xLjQK", base64.StdEncoding.EncodeToString(vcf)).Replace(withAttachments("card@test", "card", 1))
	e.put(t, "邮箱名片", sample)
	e.sync(t)
	candidates, err := e.s.mailboxCertificates(ctx, e.acc.ID, []string{to})
	require.NoError(t, err)
	if len(candidates[strings.ToLower(to)]) == 0 {
		t.Fatalf("找不到匹配证书 (名片中有 %d 个证书，IMAP 附件数 %d)", len(card.Certificates), len(e.rows(t, "SELECT id FROM attachments")))
	}
	on := true
	_, err = e.s.UpdateAccount(ctx, e.acc.ID, AccountPatch{SMIMESign: &on, SMIMEEncrypt: &on})
	require.NoError(t, err)
	d, err := e.s.NewDraft(ctx, e.acc.ID, "new", 0)
	require.NoError(t, err)
	d.To = []string{to}
	d.Subject = "Local test"
	d.HTML = "<p>Local S/MIME round trip</p>"
	d, err = e.s.SaveDraft(ctx, d)
	require.NoError(t, err)
	require.NoError(t, e.s.SendRevision(ctx, d.ID, d.Revision))
	rows := e.rows(t, "SELECT raw_path FROM outbox")
	require.Len(t, rows, 1)
	raw, err := os.ReadFile(store.Str(rows[0][0]))
	require.NoError(t, err)
	require.False(t, bytes.Contains(raw, []byte("Local S/MIME round trip")))
	m, err := mail.ReadMessage(bytes.NewReader(raw))
	require.NoError(t, err)
	require.Contains(t, m.Header.Get("Content-Type"), "enveloped-data")
	der, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding, m.Body))
	require.NoError(t, err)
	cms, err := pkcs7.Parse(der)
	require.NoError(t, err)
	recipients, err := cms.GetRecipients()
	require.NoError(t, err)
	require.Len(t, recipients, 2)
	peer := candidates[strings.ToLower(to)][0]
	require.True(t, slices.ContainsFunc(recipients, func(r pkcs7.RecipientInfo) bool {
		return r.SerialNumber != nil && r.SerialNumber.Cmp(peer.SerialNumber) == 0 && bytes.Equal(r.RawIssuer, peer.RawIssuer)
	}), "信封必须包含名片中的收件人证书")

	opened, err := smime.Open(ctx, raw)
	require.NoError(t, err)
	require.True(t, opened.Encrypted)
	require.True(t, strings.EqualFold(opened.Signer, from))
	require.Contains(t, string(opened.Entity), "Local S/MIME round trip")
	require.Empty(t, e.smtp.Messages())
}

func TestSMIMEPrefetchCachesP7MOnly(t *testing.T) {
	e := newSendEnv(t, false)
	oldMax := smimePrefetchMaxItem
	smimePrefetchMaxItem = 128
	t.Cleanup(func() { smimePrefetchMaxItem = oldMax })

	makeP7M := func(id, payload string) string {
		b64 := base64.StdEncoding.EncodeToString([]byte(payload))
		return fmt.Sprintf("Message-ID: <%s>\r\nFrom: bob@example.com\r\nTo: alice@example.com\r\nSubject: enc %s\r\nDate: Mon, 05 Oct 2026 09:00:00 +0000\r\nMIME-Version: 1.0\r\nContent-Type: application/pkcs7-mime; smime-type=enveloped-data; name=\"smime.p7m\"\r\nContent-Transfer-Encoding: base64\r\n\r\n%s\r\n", id, id, b64)
	}
	makeSigned := func(id string) string {
		sig := base64.StdEncoding.EncodeToString([]byte("sig-bytes"))
		return fmt.Sprintf("Message-ID: <%s>\r\nFrom: bob@example.com\r\nTo: alice@example.com\r\nSubject: sig %s\r\nDate: Mon, 05 Oct 2026 09:00:00 +0000\r\nMIME-Version: 1.0\r\nContent-Type: multipart/signed; protocol=\"application/pkcs7-signature\"; boundary=b1\r\n\r\n--b1\r\nContent-Type: text/plain\r\n\r\nhello\r\n--b1\r\nContent-Type: application/pkcs7-signature; name=\"smime.p7s\"\r\nContent-Transfer-Encoding: base64\r\n\r\n%s\r\n--b1--\r\n", id, id, sig)
	}

	e.put(t, "INBOX", makeP7M("p1@x", "cipher-one"))
	e.put(t, "INBOX", makeP7M("p2@x", "cipher-two"))
	e.put(t, "INBOX", makeSigned("s1@x"))
	e.put(t, "INBOX", makeP7M("big@x", strings.Repeat("Z", 300)))
	e.sync(t)

	beforeLogins := e.im.Logins()
	retryAfter := e.s.prefetchSMIMEAccount(t.Context(), e.acc.ID)
	require.Zero(t, retryAfter)
	require.Equal(t, beforeLogins+1, e.im.Logins(), "one batch reuses a single IMAP login")

	rows := e.rows(t, `SELECT m.message_id, a.filename, a.cache_path
		FROM attachments a JOIN messages m ON m.id = a.message_id ORDER BY m.message_id`)
	got := map[string]string{}
	for _, r := range rows {
		got[store.Str(r[0])] = store.Str(r[2])
	}
	require.NotEmpty(t, got["p1@x"])
	require.NotEmpty(t, got["p2@x"])
	require.Empty(t, got["s1@x"])
	require.Empty(t, got["big@x"])

	b1, err := os.ReadFile(got["p1@x"])
	require.NoError(t, err)
	require.Equal(t, []byte("cipher-one"), b1)
	b2, err := os.ReadFile(got["p2@x"])
	require.NoError(t, err)
	require.Equal(t, []byte("cipher-two"), b2)
}

func TestSMIMEDirectFetchBypassesAccountLockAndReusesConn(t *testing.T) {
	e := newSendEnv(t, false)
	makeP7M := func(id, payload string) string {
		b64 := base64.StdEncoding.EncodeToString([]byte(payload))
		return fmt.Sprintf("Message-ID: <%s>\r\nFrom: bob@example.com\r\nTo: alice@example.com\r\nSubject: enc %s\r\nDate: Mon, 05 Oct 2026 09:00:00 +0000\r\nMIME-Version: 1.0\r\nContent-Type: application/pkcs7-mime; smime-type=enveloped-data; name=\"smime.p7m\"\r\nContent-Transfer-Encoding: base64\r\n\r\n%s\r\n", id, id, b64)
	}
	e.put(t, "INBOX", makeP7M("d1@x", "direct-one"))
	e.put(t, "INBOX", makeP7M("d2@x", "direct-two"))
	e.sync(t)

	rows := e.rows(t, `SELECT m.message_id, a.id FROM attachments a JOIN messages m ON m.id = a.message_id ORDER BY a.id`)
	ids := map[string]int64{}
	for _, r := range rows {
		ids[store.Str(r[0])] = store.Int(r[1])
	}

	// 模拟后台 34 个文件夹全量同步正在长时间占用 lockAccount。
	unlock, err := e.s.lockAccount(bg, e.acc.ID)
	require.NoError(t, err)
	defer unlock()

	beforeLogins := e.im.Logins()
	ctx, cancel := context.WithTimeout(bg, 2*time.Second)
	defer cancel()

	p1, _, err := e.s.GetAttachment(ctx, ids["d1@x"])
	require.NoError(t, err)
	p2, _, err := e.s.GetAttachment(ctx, ids["d2@x"])
	require.NoError(t, err)
	require.Equal(t, beforeLogins+1, e.im.Logins(), "交互直连与二次点击复用同一条常驻连接")

	b1, err := os.ReadFile(p1)
	require.NoError(t, err)
	require.Equal(t, []byte("direct-one"), b1)
	b2, err := os.ReadFile(p2)
	require.NoError(t, err)
	require.Equal(t, []byte("direct-two"), b2)
}

func TestSMIMEPrefetchOrdersNewestAcrossFolders(t *testing.T) {
	e := newSendEnv(t, false)
	require.NoError(t, e.im.User.Create("INBOX/Team", nil))

	setFor(t, &smimePrefetchBudget, 160)
	setFor(t, &smimePrefetchBatch, 1)

	makeP7MDate := func(id, date, payload string) string {
		b64 := base64.StdEncoding.EncodeToString([]byte(payload))
		return fmt.Sprintf("Message-ID: <%s>\r\nFrom: bob@example.com\r\nTo: alice@example.com\r\nSubject: %s\r\nDate: %s\r\nMIME-Version: 1.0\r\nContent-Type: application/pkcs7-mime; smime-type=enveloped-data; name=\"smime.p7m\"\r\nContent-Transfer-Encoding: base64\r\n\r\n%s\r\n", id, id, date, b64)
	}
	payload := strings.Repeat("A", 75) // base64 size ~100 bytes
	e.put(t, "INBOX", makeP7MDate("old-inbox@x", "Thu, 01 Oct 2026 09:00:00 +0000", payload))
	e.put(t, "Sent", makeP7MDate("new-sent@x", "Mon, 05 Oct 2026 09:00:00 +0000", payload))
	e.put(t, "INBOX/Team", makeP7MDate("newest-sub@x", "Tue, 06 Oct 2026 09:00:00 +0000", payload))
	e.put(t, "Trash", makeP7MDate("trash-new@x", "Wed, 07 Oct 2026 09:00:00 +0000", payload))
	e.sync(t)

	retryAfter := e.s.prefetchSMIMEAccount(t.Context(), e.acc.ID)
	require.Zero(t, retryAfter)

	rows := e.rows(t, `SELECT m.message_id, a.cache_path FROM attachments a JOIN messages m ON m.id = a.message_id`)
	got := map[string]string{}
	for _, r := range rows {
		got[store.Str(r[0])] = store.Str(r[1])
	}
	require.NotEmpty(t, got["newest-sub@x"], "最新子文件夹邮件应优先预取")
	require.NotEmpty(t, got["new-sent@x"], "最新已发送邮件应先于较早收件箱预取")
	require.Empty(t, got["old-inbox@x"], "预算满后较早收件箱应延后")
	require.Empty(t, got["trash-new@x"], "已删除文件夹即使时间最新也应降权延后")
}

func makeTestP7M(id, date, payload string) string {
	b64 := base64.StdEncoding.EncodeToString([]byte(payload))
	return fmt.Sprintf("Message-ID: <%s>\r\nFrom: bob@example.com\r\nTo: alice@example.com\r\nSubject: %s\r\nDate: %s\r\nMIME-Version: 1.0\r\nContent-Type: application/pkcs7-mime; smime-type=enveloped-data; name=\"smime.p7m\"\r\nContent-Transfer-Encoding: base64\r\n\r\n%s\r\n", id, id, date, b64)
}

func TestSMIMEInteractiveKeepsWarmConnAcrossPrefetchPause(t *testing.T) {
	e := newSendEnv(t, false)
	setFor(t, &smimePrefetchPause, 150*time.Millisecond)

	e.put(t, "INBOX", makeTestP7M("warm1@x", "Mon, 05 Oct 2026 09:00:00 +0000", "warm-one"))
	e.put(t, "INBOX", makeTestP7M("warm2@x", "Mon, 05 Oct 2026 08:00:00 +0000", "warm-two"))
	e.put(t, "INBOX", makeTestP7M("warm3@x", "Mon, 05 Oct 2026 07:00:00 +0000", "warm-three"))
	e.sync(t)

	rows := e.rows(t, `SELECT m.message_id, a.id FROM attachments a JOIN messages m ON m.id = a.message_id`)
	ids := map[string]int64{}
	for _, r := range rows {
		ids[store.Str(r[0])] = store.Int(r[1])
	}

	beforeLogins := e.im.Logins()
	p1, _, err := e.s.GetAttachment(t.Context(), ids["warm1@x"])
	require.NoError(t, err)
	loginsAfterFirst := e.im.Logins()
	require.Equal(t, beforeLogins+1, loginsAfterFirst)

	// 点击第一封会设置软暂停窗口，但绝不能关闭已建好的交互常驻连接。
	p2, _, err := e.s.GetAttachment(t.Context(), ids["warm2@x"])
	require.NoError(t, err)
	require.Equal(t, loginsAfterFirst, e.im.Logins(), "交互常驻连接应被直接复用，不重新登录")

	b1, err := os.ReadFile(p1)
	require.NoError(t, err)
	require.Equal(t, []byte("warm-one"), b1)
	b2, err := os.ReadFile(p2)
	require.NoError(t, err)
	require.Equal(t, []byte("warm-two"), b2)

	// 软暂停结束后，预取继续补齐剩余邮件，且再次读取已缓存项不触发新登录。
	require.Zero(t, e.s.prefetchSMIMEAccount(t.Context(), e.acc.ID))
	p3, _, err := e.s.GetAttachment(t.Context(), ids["warm3@x"])
	require.NoError(t, err)
	b3, err := os.ReadFile(p3)
	require.NoError(t, err)
	require.Equal(t, []byte("warm-three"), b3)
}

func TestSMIMEPrefetchSkipsPoisonItemAndRetriesTransientError(t *testing.T) {
	e := newSendEnv(t, false)
	e.put(t, "INBOX", makeTestP7M("bad@x", "Wed, 07 Oct 2026 09:00:00 +0000", "poison-data"))
	e.put(t, "INBOX", makeTestP7M("good@x", "Tue, 06 Oct 2026 09:00:00 +0000", "healthy-data"))
	e.sync(t)

	// 把最新的附件编码改成非法 base64（非缺失错误），模拟会失败的毒丸条目。
	_, err := e.s.db.Execute(t.Context(), `UPDATE attachments SET part = 'bad-part'
		WHERE message_id = (SELECT id FROM messages WHERE message_id = 'bad@x')`)
	require.NoError(t, err)

	// 1. 临时断网拨号失败应返回退避时长，而非永久放弃。
	e.im.Stop()
	retryAfter := e.s.prefetchSMIMEAccount(t.Context(), e.acc.ID)
	require.Greater(t, retryAfter, time.Duration(0))

	// 恢复网络并清除退避窗口，再次预取：毒丸应被跳过，后面的健康邮件应成功缓存。
	e.im.Restart()
	e.s.smime.clearBackoff(e.acc.ID)
	retryAfter = e.s.prefetchSMIMEAccount(t.Context(), e.acc.ID)
	require.Zero(t, retryAfter)

	rows := e.rows(t, `SELECT m.message_id, a.cache_path FROM attachments a JOIN messages m ON m.id = a.message_id`)
	got := map[string]string{}
	for _, r := range rows {
		got[store.Str(r[0])] = store.Str(r[1])
	}
	require.Empty(t, got["bad@x"], "失败条目应记入短期跳过列表")
	require.NotEmpty(t, got["good@x"], "毒丸条目不能阻塞同一批后续正常邮件的预取")
}

func TestSMIMEPrefetchPrioritizesViewedFolderAndOpenThread(t *testing.T) {
	e := newSendEnv(t, false)
	require.NoError(t, e.im.User.Create("INBOX/Team", nil))

	setFor(t, &smimePrefetchBudget, 150)
	setFor(t, &smimePrefetchBatch, 1)

	payload := strings.Repeat("B", 75) // ~100 bytes
	e.put(t, "INBOX", makeTestP7M("global-new@x", "Fri, 09 Oct 2026 09:00:00 +0000", payload))
	e.put(t, "INBOX/Team", makeTestP7M("team-visible@x", "Tue, 06 Oct 2026 09:00:00 +0000", payload))
	e.put(t, "INBOX/Team", makeTestP7M("team-open@x", "Mon, 05 Oct 2026 09:00:00 +0000", payload))
	e.sync(t)

	folderRows := e.rows(t, `SELECT id FROM folders WHERE name = 'INBOX/Team'`)
	require.Len(t, folderRows, 1)
	teamFolderID := store.Int(folderRows[0][0])

	page, err := e.s.ListThreads(t.Context(), View{FolderID: teamFolderID}, "", 50)
	require.NoError(t, err)
	require.Len(t, page.Items, 2)

	var openThreadID int64
	for _, it := range page.Items {
		if it.Subject == "team-open@x" {
			openThreadID = it.ID
		}
	}
	require.NotZero(t, openThreadID)
	_, err = e.s.GetThread(t.Context(), openThreadID)
	require.NoError(t, err)

	// 预算只够大约 2~3 封时，先用仅容纳 2 封的预算验证 Tier1(打开会话) 与 Tier2(当前视图文件夹) 优先于全局最新。
	_ = e.s.prefetchSMIMEAccount(t.Context(), e.acc.ID)

	rows := e.rows(t, `SELECT m.message_id, a.cache_path FROM attachments a JOIN messages m ON m.id = a.message_id`)
	got := map[string]string{}
	for _, r := range rows {
		got[store.Str(r[0])] = store.Str(r[1])
	}
	require.NotEmpty(t, got["team-open@x"], "当前打开会话的 S/MIME 密文应最高优先预取")
	require.NotEmpty(t, got["team-visible@x"], "当前列表视图中的子文件夹邮件应先于全局其他文件夹预取")
	require.Empty(t, got["global-new@x"], "其他文件夹较新邮件应排在打开会话与当前列表视图之后")
}

func makeTestSigned(id, date, body string, withRealAttachment bool) string {
	const sigB64 = "c2lnbmF0dXJlLWJ5dGVz"
	var bodyPart string
	if withRealAttachment {
		bodyPart = "--inner-bnd\r\n" +
			"Content-Type: text/plain; charset=utf-8\r\n\r\n" +
			body + "\r\n" +
			"--inner-bnd\r\n" +
			"Content-Type: application/pdf; name=\"report.pdf\"\r\n" +
			"Content-Disposition: attachment; filename=\"report.pdf\"\r\n" +
			"Content-Transfer-Encoding: base64\r\n\r\n" +
			"JVBERi0xLjQK\r\n" +
			"--inner-bnd--\r\n"
		bodyPart = "Content-Type: multipart/mixed; boundary=\"inner-bnd\"\r\n\r\n" + bodyPart
	} else {
		bodyPart = "Content-Type: text/plain; charset=utf-8\r\n\r\n" + body + "\r\n"
	}
	return fmt.Sprintf("Message-ID: <%s>\r\nFrom: bob@example.com\r\nTo: alice@example.com\r\nSubject: %s\r\nDate: %s\r\nMIME-Version: 1.0\r\nContent-Type: multipart/signed; protocol=\"application/pkcs7-signature\"; micalg=sha-256; boundary=\"sig-bnd\"\r\n\r\n--sig-bnd\r\n%s\r\n--sig-bnd\r\nContent-Type: application/pkcs7-signature; name=\"smime.p7s\"\r\nContent-Disposition: attachment; filename=\"smime.p7s\"\r\nContent-Transfer-Encoding: base64\r\n\r\n%s\r\n--sig-bnd--\r\n",
		id, id, date, bodyPart, sigB64)
}

func TestSMIMEHasAttachmentsSMIMEKindAndRepair(t *testing.T) {
	e := newSendEnv(t, false)
	e.put(t, "INBOX", makeTestP7M("p7m-only@x", "Wed, 07 Oct 2026 09:00:00 +0000", "cipher"))
	e.put(t, "INBOX", makeTestSigned("p7s-only@x", "Tue, 06 Oct 2026 09:00:00 +0000", "signed text", false))
	e.put(t, "INBOX", makeTestSigned("p7s-att@x", "Mon, 05 Oct 2026 09:00:00 +0000", "signed with pdf", true))
	e.sync(t)

	tp, err := e.s.ListThreads(t.Context(), View{Unified: "inbox"}, "", 50)
	require.NoError(t, err)
	threads := map[string]ThreadSummary{}
	for _, it := range tp.Items {
		threads[it.Subject] = it
	}
	assert.False(t, threads["p7m-only@x"].HasAttachments, "smime.p7m-only thread must not show paperclip")
	assert.Equal(t, "encrypted", threads["p7m-only@x"].SMIME)
	assert.False(t, threads["p7s-only@x"].HasAttachments, "smime.p7s-only thread must not show paperclip")
	assert.Equal(t, "signed", threads["p7s-only@x"].SMIME)
	assert.True(t, threads["p7s-att@x"].HasAttachments, "smime.p7s + real PDF must keep paperclip")
	assert.Equal(t, "signed", threads["p7s-att@x"].SMIME)

	mp, err := e.s.ListMessages(t.Context(), View{Unified: "inbox"}, "", 50)
	require.NoError(t, err)
	msgs := map[string]MessageSummary{}
	for _, m := range mp.Items {
		msgs[m.Subject] = m
	}
	assert.False(t, msgs["p7m-only@x"].HasAttachments)
	assert.Equal(t, "encrypted", msgs["p7m-only@x"].SMIME)
	assert.False(t, msgs["p7s-only@x"].HasAttachments)
	assert.Equal(t, "signed", msgs["p7s-only@x"].SMIME)
	assert.True(t, msgs["p7s-att@x"].HasAttachments)
	assert.Equal(t, "signed", msgs["p7s-att@x"].SMIME)

	sr, err := e.s.SearchWith(t.Context(), SearchQuery{From: "bob@example.com"}, 50)
	require.NoError(t, err)
	assert.Len(t, sr, 3)
	for _, m := range sr {
		assert.Equal(t, msgs[m.Subject].SMIME, m.SMIME)
		assert.Equal(t, msgs[m.Subject].HasAttachments, m.HasAttachments)
	}

	th, err := e.s.GetThread(t.Context(), threads["p7m-only@x"].ID)
	require.NoError(t, err)
	require.Len(t, th.Messages, 1)
	assert.Equal(t, "encrypted", th.Messages[0].SMIME)
	assert.False(t, th.Messages[0].HasAttachments)

	foundSMIME, err := e.s.Find(t.Context(), FindQuery{Kind: "attachment", SearchQuery: SearchQuery{Text: "smime"}})
	require.NoError(t, err)
	assert.Empty(t, foundSMIME.Attachments.Items, "smime.p7m/smime.p7s must be excluded from attachment search")

	foundPDF, err := e.s.Find(t.Context(), FindQuery{Kind: "attachment", SearchQuery: SearchQuery{Text: "report"}})
	require.NoError(t, err)
	require.Len(t, foundPDF.Attachments.Items, 1)
	assert.Equal(t, "report.pdf", foundPDF.Attachments.Items[0].Filename)

	// Simulate pre-existing DB rows where S/MIME parts marked has_attachments = 1, then run startup repair.
	_, err = e.s.db.Execute(t.Context(), `UPDATE messages SET has_attachments = 1`)
	require.NoError(t, err)
	require.NoError(t, e.s.repairSMIMEHasAttachments(t.Context()))

	mp2, err := e.s.ListMessages(t.Context(), View{Unified: "inbox"}, "", 50)
	require.NoError(t, err)
	for _, m := range mp2.Items {
		assert.Equal(t, m.Subject == "p7s-att@x", m.HasAttachments, "repaired has_attachments for %s", m.Subject)
	}
}

func TestSMIMEDecryptedBodyUIOnlySkillsWitAndCacheBypass(t *testing.T) {
	e := newSkillEnv(t)
	encID := addMessage(t, e.s, "Secret Q4", "Bob <bob@x>", "", "", 1_700_000_200)
	_, err := e.s.db.Execute(t.Context(), "UPDATE messages SET thread_id = 1 WHERE id = ?", encID)
	require.NoError(t, err)
	_, err = e.s.db.Execute(t.Context(), `INSERT INTO attachments(message_id, part, filename, content_type, size, inline)
		VALUES (?, '1', 'smime.p7m', 'application/pkcs7-mime', 128, 0)`, encID)
	require.NoError(t, err)

	// Running summarize before decryption must neither leak/cache into ai_cache
	// nor poison subsequent decrypted runs.
	e.srv.Script(testllm.Turn{Text: []string{"placeholder before decrypt"}})
	chBefore, err := e.s.RunSkill(t.Context(), "summarize", Target{Kind: "message", ID: encID})
	require.NoError(t, err)
	_ = drain(chBefore)
	require.Equal(t, 0, e.cacheRows(t), "encrypted message must not populate ai_cache before decryption")

	// Also seed a dummy ai_cache row to verify all decrypted AI/translation runs leave ai_cache untouched.
	_, err = e.s.db.Execute(t.Context(), `INSERT INTO ai_cache(key, account_id, output, created_at)
		VALUES ('stale-key', 1, 'stale empty ciphertext summary', 1700000000)`)
	require.NoError(t, err)
	initialCacheRows := e.cacheRows(t)

	rawUI, cancelUI := context.WithCancel(t.Context())
	uiCtx := WithUISession(rawUI, e.s)

	const secretPlain = "Confidential Q4 budget is approved for $99M."
	const secretHTML = "<p>Confidential Q4 budget is approved for $99M.</p>"
	require.NoError(t, e.s.SetDecryptedBody(uiCtx, encID, DecryptedBody{
		HTML:        secretHTML,
		Text:        secretPlain,
		Attachments: []AttachmentInfo{{Filename: "budget.pdf", ContentType: "application/pdf", Size: 2048}},
	}))

	// 1. UI session sees decrypted content and decrypted attachment metadata, without smime.p7m.
	uiItems, err := e.s.mailContext(uiCtx, &gateway.Scope{}, []int64{encID}, defaultMailBudget)
	require.NoError(t, err)
	require.Len(t, uiItems, 1)
	assert.Contains(t, uiItems[0].Block, secretPlain)
	assert.Contains(t, uiItems[0].Block, "budget.pdf")
	assert.NotContains(t, uiItems[0].Block, "smime.p7m")

	// 2. Non-UI context (no uiSession) and plugins (pluginMail even under uiCtx) NEVER see decrypted content.
	nonUIItems, err := e.s.mailContext(t.Context(), &gateway.Scope{}, []int64{encID}, defaultMailBudget)
	require.NoError(t, err)
	require.Len(t, nonUIItems, 1)
	assert.NotContains(t, nonUIItems[0].Block, secretPlain)
	assert.Contains(t, nonUIItems[0].Block, "smime.p7m")

	pm, err := e.s.pluginMail(uiCtx, encID)
	require.NoError(t, err)
	assert.Empty(t, pm.Text)
	assert.Empty(t, pm.HTML)

	// 3. Summarize, whole-body translate, QuickReplies, MessageGist, and Wit AskWith all receive decrypted plaintext.
	e.srv.Script(
		testllm.Turn{Text: []string{"Approved Q4 budget is $99M."}},
		testllm.Turn{Text: []string{`{"texts":["机密第四季度预算已批准，金额为 9900 万美元。"],"source":"en"}`}},
		testllm.Turn{Text: []string{`{"replies":[{"label":"收到","html":"<p>收到，已确认第四季度预算。</p>"}]}`}},
		testllm.Turn{Text: []string{"第四季度 9900 万美元预算已批"}},
		testllm.Turn{Text: []string{"预算为 9900 万美元。"}},
	)

	chSum, err := e.s.RunSkill(uiCtx, "summarize", Target{Kind: "message", ID: encID})
	require.NoError(t, err)
	assert.Equal(t, []string{"Approved Q4 budget is $99M."}, texts(drain(chSum)))

	chTr, err := e.s.RunSkill(uiCtx, "translate", Target{Kind: "message", ID: encID, PreserveHTML: true})
	require.NoError(t, err)
	trEvs := drain(chTr)
	require.GreaterOrEqual(t, len(trEvs), 2)
	assert.Equal(t, "机密第四季度预算已批准，金额为 9900 万美元。", trEvs[1].Translations[secretPlain])

	qrs, err := e.s.QuickReplies(uiCtx, encID)
	require.NoError(t, err)
	require.Len(t, qrs, 1)

	gist, err := e.s.MessageGist(uiCtx, encID)
	require.NoError(t, err)
	assert.Contains(t, gist, "9900")

	conv, err := e.s.NewConversation(uiCtx, "ask", 0)
	require.NoError(t, err)
	chWit, err := e.s.AskWith(uiCtx, conv.ID, "How much is the budget?", []int64{encID})
	require.NoError(t, err)
	witEvs := drainWit(t, chWit)
	require.Equal(t, "done", witEvs[len(witEvs)-1].Kind)

	reqs := e.srv.Requests()
	require.Len(t, reqs, 6)
	assert.Contains(t, string(reqs[0].Messages), "smime.p7m", "pre-decrypt call used encrypted DB view")
	for i, req := range reqs[1:] {
		body := string(req.Messages)
		assert.Contains(t, body, secretPlain, "request %d did not receive decrypted plaintext", i+1)
		assert.NotContains(t, body, "smime.p7m", "request %d leaked encrypted placeholder", i+1)
	}

	// 4. None of those AI/translation/gist/quick-reply runs wrote anything to ai_cache on disk.
	assert.Equal(t, initialCacheRows, e.cacheRows(t), "ai_cache must not persist decrypted S/MIME outputs")

	// 5. Disconnecting the UI session clears decrypted bodies from RAM immediately.
	cancelUI()
	require.Eventually(t, func() bool {
		_, ok := e.s.decryptedBody(uiCtx, encID)
		return !ok
	}, time.Second, time.Millisecond)
}

func TestSMIMEStandardCertificateSourcesAndSelection(t *testing.T) {
	e := newSendEnv(t, false)
	ctx := WithUISession(t.Context(), e.s)

	makeCert := func(email, cn string, serial int64, offset time.Duration) []byte {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		now := time.Now()
		tmpl := &x509.Certificate{
			SerialNumber:   big.NewInt(serial),
			Subject:        pkix.Name{CommonName: cn},
			EmailAddresses: []string{email},
			NotBefore:      now.Add(offset),
			NotAfter:       now.Add(24 * time.Hour),
			KeyUsage:       x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		require.NoError(t, err)
		return der
	}

	// 1. Generic .vcf in a standard folder (Archive, NOT '邮箱名片') and .cer in INBOX are indexed,
	//    while certificates placed in Trash are ignored.
	_ = e.im.User.Create("Trash", nil)
	bobVCardDER := makeCert("bob@example.com", "Bob Archive Card", 101, -2*time.Hour)
	carolCerDER := makeCert("carol@example.com", "Carol Inbox CER", 102, -time.Hour)
	trashDER := makeCert("trash@example.com", "Ignored Trash Cert", 103, -time.Hour)

	b64Bob := base64.StdEncoding.EncodeToString(bobVCardDER)
	bobCard := "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Bob\r\nKEY;ENCODING=BASE64:" + b64Bob + "\r\nEMAIL:bob@example.com\r\nEND:VCARD\r\n"
	msgVCard := withAttachments("sender@example.com", "card in archive", 1)
	msgVCard = strings.ReplaceAll(msgVCard, "application/pdf", "text/vcard")
	msgVCard = strings.ReplaceAll(msgVCard, "f0.pdf", "bob.vcf")
	e.put(t, "Archive", strings.ReplaceAll(msgVCard, "JVBERi0xLjQK", base64.StdEncoding.EncodeToString([]byte(bobCard))))

	pemCarol := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: carolCerDER})
	msgCer := withAttachments("carol@example.com", "cert in inbox", 1)
	msgCer = strings.ReplaceAll(msgCer, "application/pdf", "application/pkix-cert")
	msgCer = strings.ReplaceAll(msgCer, "f0.pdf", "carol.cer")
	e.put(t, "INBOX", strings.ReplaceAll(msgCer, "JVBERi0xLjQK", base64.StdEncoding.EncodeToString(pemCarol)))

	msgTrash := withAttachments("trash@example.com", "junk cert", 1)
	msgTrash = strings.ReplaceAll(msgTrash, "application/pdf", "application/pkix-cert")
	msgTrash = strings.ReplaceAll(msgTrash, "f0.pdf", "trash.cer")
	e.put(t, "Trash", strings.ReplaceAll(msgTrash, "JVBERi0xLjQK", base64.StdEncoding.EncodeToString(trashDER)))

	e.sync(t)
	require.NoError(t, e.s.exec(ctx, sqlite.Statement{SQL: "UPDATE folders SET role = 'trash' WHERE name = 'Trash'"}))

	certs, err := e.s.mailboxCertificates(ctx, e.acc.ID, []string{"bob@example.com", "carol@example.com", "trash@example.com"})
	require.NoError(t, err)
	require.Len(t, certs["bob@example.com"], 1)
	require.Equal(t, bobVCardDER, certs["bob@example.com"][0].Raw)
	require.Len(t, certs["carol@example.com"], 1)
	require.Equal(t, carolCerDER, certs["carol@example.com"][0].Raw)
	require.Empty(t, certs["trash@example.com"])

	// 2. CardDAV parsed certificate helper extracts matching cert for upsert.
	daveDER := makeCert("dave@example.com", "Dave CardDAV", 104, -time.Hour)
	daveCard := "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Dave\r\nEMAIL:dave@example.com\r\nKEY;ENCODING=BASE64:" +
		base64.StdEncoding.EncodeToString(daveDER) + "\r\nEND:VCARD\r\n"
	pc := carddav.ParseVCard(daveCard)
	preparedCerts := carddavPreparedCerts(pc, []carddav.CardEmail{{AddrKey: "dave@example.com"}})
	require.Len(t, preparedCerts, 1)
	require.NoError(t, e.s.exec(ctx, upsertSMIMECertStmt(preparedCerts[0].addrKey, CertSourceCardDAV, preparedCerts[0].cert, time.Now().Unix())))

	// 3. Verified incoming signer cert and manual certificate file import + pinning + removal.
	aliceSigDER := makeCert("bob@example.com", "Bob Signed Mail", 105, -30*time.Minute)
	require.NoError(t, e.s.RecordSMIMESignerCert(ctx, "Bob <bob@example.com>", aliceSigDER))

	impDER := makeCert("bob@example.com", "Bob Manual File", 106, -15*time.Minute)
	impPath := filepath.Join(t.TempDir(), "bob.pem")
	require.NoError(t, os.WriteFile(impPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: impDER}), 0o600))

	// Importing with mismatched target address is rejected cleanly.
	_, err = e.s.ImportContactCertificateFile(ctx, "other@example.com", impPath)
	require.ErrorIs(t, err, ErrSMIMECertAddressMismatch)

	imported, err := e.s.ImportContactCertificateFile(ctx, "bob@example.com", impPath)
	require.NoError(t, err)
	require.Len(t, imported, 1)
	require.Equal(t, CertSourceImported, imported[0].Source)
	require.NotEmpty(t, imported[0].SerialNumber)
	require.Equal(t, "RSA (2048 bit)", imported[0].PublicKeyAlgo)
	require.Equal(t, []string{"bob@example.com"}, imported[0].Emails)
	require.Len(t, imported[0].SHA1, 40)

	statuses, err := e.s.ListContactCertificates(ctx, []string{"bob@example.com", "dave@example.com", "missing@example.com"})
	require.NoError(t, err)
	require.Len(t, statuses, 3)
	require.Len(t, statuses[0].Certs, 3) // mail_card, mail_sig, imported
	require.Len(t, statuses[1].Certs, 1)
	require.Equal(t, CertSourceCardDAV, statuses[1].Certs[0].Source)
	require.Equal(t, "rcpt_missing", statuses[2].ErrorCode)
	require.Empty(t, statuses[2].Error)

	// Selecting and clearing a preferred certificate persists smime.rcpt.<addr>.
	bobSigSHA := smime.CertSHA256(aliceSigDER)
	require.NoError(t, e.s.SelectContactCertificate(ctx, "bob@example.com", bobSigSHA))
	statuses, err = e.s.ListContactCertificates(ctx, []string{"bob@example.com"})
	require.NoError(t, err)
	var selectedCount int
	for _, c := range statuses[0].Certs {
		if c.Selected {
			selectedCount++
			require.Equal(t, bobSigSHA, c.SHA256)
		}
	}
	require.Equal(t, 1, selectedCount)

	// Removing an imported cert deletes it and clears selection if it had been selected.
	require.NoError(t, e.s.SelectContactCertificate(ctx, "bob@example.com", imported[0].SHA256))
	require.NoError(t, e.s.RemoveContactCertificate(ctx, "bob@example.com", imported[0].SHA256))
	statuses, err = e.s.ListContactCertificates(ctx, []string{"bob@example.com"})
	require.NoError(t, err)
	require.Len(t, statuses[0].Certs, 2)
	for _, c := range statuses[0].Certs {
		require.False(t, c.Selected)
	}

	// 4. Account SMIMECert setting + Draft S/MIME overrides + DeleteDraft cleanup.
	pinnedAccountCert := "deadbeef00112233"
	acc, err := e.s.UpdateAccount(ctx, e.acc.ID, AccountPatch{SMIMECert: &pinnedAccountCert})
	require.NoError(t, err)
	require.Equal(t, pinnedAccountCert, acc.SMIMECert)
	gotAcc, err := e.s.ListAccounts(ctx)
	require.NoError(t, err)
	require.Equal(t, pinnedAccountCert, gotAcc[0].SMIMECert)
	emptyCert := ""
	acc, err = e.s.UpdateAccount(ctx, e.acc.ID, AccountPatch{SMIMECert: &emptyCert})
	require.NoError(t, err)
	require.Empty(t, acc.SMIMECert)

	d, err := e.s.NewDraft(ctx, e.acc.ID, "new", 0)
	require.NoError(t, err)
	d.To = []string{"bob@example.com"}
	d, err = e.s.SaveDraft(ctx, d)
	require.NoError(t, err)

	signOn, encOn := true, true
	dst, err := e.s.SetDraftSMIME(ctx, d.ID, &signOn, &encOn, map[string]string{"bob@example.com": bobSigSHA})
	require.NoError(t, err)
	require.True(t, dst.Sign)
	require.True(t, dst.Encrypt)
	require.Len(t, dst.Recipients, 1)
	for _, c := range dst.Recipients[0].Certs {
		require.Equal(t, c.SHA256 == bobSigSHA, c.Selected)
	}

	require.NoError(t, e.s.DeleteDraft(ctx, d.ID))
	rows := e.rows(t, "SELECT value FROM settings WHERE key = ?", draftSMIMEKey(d.ID))
	require.Empty(t, rows)
}

func TestSMIMEAllowWeakKeyAccountAndFormat(t *testing.T) {
	e := newSendEnv(t, false)
	ctx := WithUISession(t.Context(), e.s)

	require.False(t, e.acc.SMIMEAllowWeakKey)
	allow, err := e.s.accountAllowsWeakSMIMEKey(ctx, e.acc.Email)
	require.NoError(t, err)
	require.False(t, allow)

	on := true
	updated, err := e.s.UpdateAccount(ctx, e.acc.ID, AccountPatch{SMIMEAllowWeakKey: &on})
	require.NoError(t, err)
	require.True(t, updated.SMIMEAllowWeakKey)

	accs, err := e.s.ListAccounts(ctx)
	require.NoError(t, err)
	require.Len(t, accs, 1)
	require.True(t, accs[0].SMIMEAllowWeakKey)

	allow, err = e.s.accountAllowsWeakSMIMEKey(ctx, e.acc.Email)
	require.NoError(t, err)
	require.True(t, allow)

	prevLang := i18n.Language()
	t.Cleanup(func() { i18n.SetLanguage(prevLang) })
	wk := &smime.WeakKeySizeError{Subject: "yczhang", KeyAlgo: "RSA", KeyBits: 1024, MinBits: 2048}

	i18n.SetLanguage("zh-Hans")
	require.Equal(t, "“yczhang”证书的密钥长度过短（RSA 1024 bit，系统要求至少 2048 位）", FormatWeakKeySizeError(wk))
	require.Equal(t, FormatWeakKeySizeError(wk), FormatSMIMEError(fmt.Errorf("wrapped: %w", wk)))
	require.Equal(t, "证书的密钥长度低于系统安全要求", FormatWeakKeySizeError(&smime.WeakKeySizeError{}))
	require.Equal(t, "other error", FormatSMIMEError(fmt.Errorf("other error")))

	i18n.SetLanguage("en")
	enMsg := FormatWeakKeySizeError(wk)
	require.Contains(t, enMsg, "2048-bit")
	require.NotContains(t, enMsg, "2,048")
	require.NotContains(t, enMsg, "broken key size")

	// Verify DraftSMIMEStatus, ListOwnSMIMECertificates, and protectOutgoing honor SMIMEAllowWeakKey on darwin.
	if smime.Supported() && runtime.GOOS == "darwin" {
		bobKey, err := rsa.GenerateKey(rand.Reader, 1024)
		require.NoError(t, err)
		bobTmpl := &x509.Certificate{
			SerialNumber:   big.NewInt(9001),
			Subject:        pkix.Name{CommonName: "Bob 1024"},
			EmailAddresses: []string{"bob@example.com"},
			NotBefore:      time.Now().Add(-time.Hour),
			NotAfter:       time.Now().Add(24 * time.Hour),
			KeyUsage:       x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
		}
		bob1024DER, err := x509.CreateCertificate(rand.Reader, bobTmpl, bobTmpl, &bobKey.PublicKey, bobKey)
		require.NoError(t, err)
		bob1024Cert, err := smime.ParseCertificate(bob1024DER)
		require.NoError(t, err)
		require.NoError(t, e.s.exec(ctx, upsertSMIMECertStmt("bob@example.com", CertSourceImported, bob1024Cert, time.Now().Unix())))

		d, err := e.s.NewDraft(ctx, e.acc.ID, "new", 0)
		require.NoError(t, err)
		d.To = []string{"bob@example.com"}
		d, err = e.s.SaveDraft(ctx, d)
		require.NoError(t, err)

		off := false
		accOff, err := e.s.UpdateAccount(ctx, e.acc.ID, AccountPatch{SMIMEAllowWeakKey: &off, SMIMEEncrypt: &on})
		require.NoError(t, err)
		i18n.SetLanguage("zh-Hans")
		stOff, err := e.s.DraftSMIMEStatus(ctx, d.ID)
		require.NoError(t, err)
		require.Len(t, stOff.Recipients, 1)
		require.False(t, stOff.Recipients[0].Ready)
		require.Contains(t, stOff.Recipients[0].Error, "密钥长度过短")

		raw := []byte("From: " + e.acc.Email + "\r\nTo: bob@example.com\r\nContent-Type: text/plain\r\n\r\nhi")
		_, err = e.s.protectOutgoing(ctx, accOff, d, []string{"bob@example.com"}, raw)
		require.ErrorIs(t, err, smime.ErrWeakKeySize)

		accOn, err := e.s.UpdateAccount(ctx, e.acc.ID, AccountPatch{SMIMEAllowWeakKey: &on})
		require.NoError(t, err)
		stOn, err := e.s.DraftSMIMEStatus(ctx, d.ID)
		require.NoError(t, err)
		require.Len(t, stOn.Recipients, 1)
		require.False(t, stOn.Recipients[0].Ready)
		require.NotContains(t, stOn.Recipients[0].Error, "密钥长度过短")

		_, err = e.s.ListOwnSMIMECertificates(ctx, e.acc.Email)
		require.NoError(t, err)

		_, err = e.s.protectOutgoing(ctx, accOn, d, []string{"bob@example.com"}, raw)
		require.Error(t, err)
		require.NotErrorIs(t, err, smime.ErrWeakKeySize)
	}

	// RemoveAccount removes smime.allow_weak_key.<id>.
	require.NoError(t, e.s.RemoveAccount(ctx, e.acc.ID))
	rows := e.rows(t, "SELECT value FROM settings WHERE key = ?", fmt.Sprintf("smime.allow_weak_key.%d", e.acc.ID))
	require.Empty(t, rows)
}

func TestSMIMEReplyQuotesDecryptedBodyAndInlineImages(t *testing.T) {
	const pngB64 = "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAIAAACQkWg2AAAAFklEQVR4nGPQKLpFEmIY1TCqYfhqAAASZ3QQWUKpQAAAAABJRU5ErkJggg=="
	pngBytes, err := base64.StdEncoding.DecodeString(pngB64)
	require.NoError(t, err)

	e := newSendEnv(t, false)
	encRaw := "Message-ID: <enc-reply@x>\r\nFrom: Bob <bob@example.com>\r\nTo: alice@example.com\r\nSubject: Secret Plan\r\n" +
		"Date: Mon, 05 Oct 2026 10:00:00 +0000\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: application/pkcs7-mime; smime-type=enveloped-data; name=\"smime.p7m\"\r\nContent-Transfer-Encoding: base64\r\n\r\nAAAA\r\n"
	e.put(t, "INBOX", encRaw)
	e.sync(t)
	encID := e.idOf(t, "enc-reply@x")

	// Non-UI context must not receive decrypted content.
	nonUI, err := e.s.NewDraft(t.Context(), e.acc.ID, "reply", encID)
	require.NoError(t, err)
	assert.NotContains(t, nonUI.HTML, "Secret Q4")
	assert.Empty(t, gomail.CIDs(nonUI.HTML))

	uiCtx := WithUISession(t.Context(), e.s)
	require.NoError(t, e.s.SetDecryptedBody(uiCtx, encID, DecryptedBody{
		HTML:      `<p>Secret Q4 details</p>`,
		QuoteHTML: `<style>.s { color: #2b579a; }</style><p class="s">Secret Q4 details</p><img src="cid:sec@x">`,
		Text:      "Secret Q4 details",
		InlineImages: []DecryptedInlineImage{
			{ContentID: "sec@x", ContentType: "image/png", Data: pngBytes},
		},
	}))

	d, err := e.s.NewDraft(uiCtx, e.acc.ID, "reply", encID)
	require.NoError(t, err)
	assert.Contains(t, d.HTML, "Secret Q4 details")
	assert.Contains(t, d.HTML, "color: #2b579a")
	cids := gomail.CIDs(d.HTML)
	require.Len(t, cids, 1)
	assert.True(t, strings.HasPrefix(cids[0], "quote-"))

	d.HTML = "<p>Acknowledged</p>" + d.HTML
	d, err = e.s.SaveDraft(uiCtx, d)
	require.NoError(t, err)
	require.NoError(t, e.s.Send(uiCtx, d.ID))
	e.clock.Advance(UndoSendWindow)
	e.sync(t)

	got := e.smtp.Messages()
	require.Len(t, got, 1)
	parsed, err := gomail.Parse(got[0].Data)
	require.NoError(t, err)
	assert.Contains(t, parsed.HTML, "Secret Q4 details")
	assert.Contains(t, parsed.HTML, "color: #2b579a")
	require.Len(t, parsed.Attachments, 1)
	assert.Equal(t, cids[0], parsed.Attachments[0].ContentID)
	assert.Equal(t, pngBytes, parsed.Attachments[0].Data)
}

func TestSMIMEForwardSkipsSMIMEParts(t *testing.T) {
	e := newSendEnv(t, false)
	raw := "Message-ID: <signed-fwd@x>\r\nFrom: Bob <bob@example.com>\r\nTo: alice@example.com\r\nSubject: Signed\r\n" +
		"Date: Mon, 05 Oct 2026 10:00:00 +0000\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"MX\"\r\n\r\n" +
		"--MX\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nBody text\r\n" +
		"--MX\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=\"report.pdf\"\r\nContent-Transfer-Encoding: base64\r\n\r\nJVBERi0xLjQK\r\n" +
		"--MX\r\nContent-Type: application/pkcs7-signature; name=\"smime.p7s\"\r\nContent-Disposition: attachment; filename=\"smime.p7s\"\r\nContent-Transfer-Encoding: base64\r\n\r\nAAAA\r\n" +
		"--MX--\r\n"
	e.put(t, "INBOX", raw)
	e.sync(t)

	d, err := e.s.NewDraft(bg, e.acc.ID, "forward", e.idOf(t, "signed-fwd@x"))
	require.NoError(t, err)
	require.Len(t, d.Attachments, 1)
	assert.Equal(t, "report.pdf", d.Attachments[0].Filename)
}

func TestInlineImagePrefetchCachesInlineAndRespectsBudget(t *testing.T) {
	e := newSendEnv(t, false)
	setFor(t, &smimePrefetchBudget, 10) // S/MIME budget already exhausted
	setFor(t, &inlinePrefetchBudget, 4096)
	setFor(t, &inlinePrefetchMaxItem, 2048)

	inlineImg := base64.StdEncoding.EncodeToString([]byte("inline-png-bytes"))
	attImg := base64.StdEncoding.EncodeToString([]byte("regular-att-png"))
	raw := "Message-ID: <inline-pref@x>\r\nFrom: bob@example.com\r\nTo: alice@example.com\r\nSubject: Poster\r\nDate: Mon, 05 Oct 2026 09:00:00 +0000\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"B\"\r\n\r\n" +
		"--B\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<img src=\"cid:poster@x\">\r\n" +
		"--B\r\nContent-Type: image/png\r\nContent-ID: <poster@x>\r\nContent-Disposition: inline; filename=\"poster.png\"\r\nContent-Transfer-Encoding: base64\r\n\r\n" + inlineImg + "\r\n" +
		"--B\r\nContent-Type: image/png\r\nContent-Disposition: attachment; filename=\"download.png\"\r\nContent-Transfer-Encoding: base64\r\n\r\n" + attImg + "\r\n" +
		"--B--\r\n"
	e.put(t, "INBOX", raw)
	e.sync(t)

	// Mark existing S/MIME budget as full? smimePrefetchBudget is 10 and inlinePrefetchBudget is 4096.
	// Also test visible/urgent priority via ListMessages / GetMessageLazyImages.
	pages, err := e.s.ListMessages(bg, e.inboxView(t), "", 10)
	require.NoError(t, err)
	require.Len(t, pages.Items, 1)

	beforeLogins := e.im.Logins()
	retryAfter := e.s.prefetchSMIMEAccount(t.Context(), e.acc.ID)
	require.Zero(t, retryAfter)
	require.Equal(t, beforeLogins+1, e.im.Logins())

	rows := e.rows(t, `SELECT filename, cache_path FROM attachments ORDER BY id`)
	got := map[string]string{}
	for _, r := range rows {
		got[store.Str(r[0])] = store.Str(r[1])
	}
	require.NotEmpty(t, got["poster.png"], "inline image should be prefetched")
	require.Empty(t, got["download.png"], "non-inline image attachment should not be prefetched")

	b, err := os.ReadFile(got["poster.png"])
	require.NoError(t, err)
	require.Equal(t, []byte("inline-png-bytes"), b)
}

func TestInlineImagePrefetchInflightDedup(t *testing.T) {
	e := newSendEnv(t, false)
	inlineImg := base64.StdEncoding.EncodeToString([]byte("dedup-png-bytes"))
	raw := "Message-ID: <inline-dedup@x>\r\nFrom: bob@example.com\r\nTo: alice@example.com\r\nSubject: Dedup\r\nDate: Mon, 05 Oct 2026 09:00:00 +0000\r\nMIME-Version: 1.0\r\nContent-Type: multipart/related; boundary=\"R\"\r\n\r\n" +
		"--R\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<img src=\"cid:dedup@x\">\r\n" +
		"--R\r\nContent-Type: image/png\r\nContent-ID: <dedup@x>\r\nContent-Disposition: inline; filename=\"dedup.png\"\r\nContent-Transfer-Encoding: base64\r\n\r\n" + inlineImg + "\r\n" +
		"--R--\r\n"
	e.put(t, "INBOX", raw)
	e.sync(t)

	rows := e.rows(t, `SELECT id FROM attachments WHERE filename = 'dedup.png'`)
	require.Len(t, rows, 1)
	attID := store.Int(rows[0][0])

	// Simulate an in-flight prefetch holding the inflight entry while interactive fetchInlineDirect arrives.
	existing, finish := e.s.smime.acquireInflight(attID)
	require.Nil(t, existing)

	type res struct {
		path    string
		handled bool
		err     error
	}
	ch := make(chan res, 1)
	go func() {
		fctx, end, berr := e.s.begin(t.Context(), 0)
		if berr != nil {
			ch <- res{err: berr}
			return
		}
		defer end()
		p, handled, _, err := e.s.fetchInlineDirect(fctx, attID)
		ch <- res{path: p, handled: handled, err: err}
	}()

	// Let fetchInlineDirect block on existing.done, then complete the simulated prefetch.
	time.Sleep(30 * time.Millisecond)
	beforeLogins := e.im.Logins()
	p, handled, _, err := e.s.fetchSMIMEPartForDedupTest(t.Context(), attID, e.acc.ID)
	require.NoError(t, err)
	require.True(t, handled)
	finish(p, nil)

	got := <-ch
	require.NoError(t, got.err)
	require.True(t, got.handled)
	require.Equal(t, p, got.path)
	require.Equal(t, beforeLogins+1, e.im.Logins(), "concurrent prefetch + interactive open should only fetch once")
}

func (s *Service) fetchSMIMEPartForDedupTest(ctx context.Context, attID, accID int64) (string, bool, bool, error) {
	a, err := s.loadAttachment(ctx, attID)
	if err != nil {
		return "", true, false, err
	}
	c := s.smime.borrowConn(accID, false)
	if c == nil {
		recv, cancel, derr := s.dialSMIMEConn(ctx, s.smime, accID, false)
		if derr != nil {
			return "", true, true, derr
		}
		c = &smimeConn{recv: recv, release: cancel}
	}
	data, err := fetchPart(ctx, c.recv, a)
	if err != nil {
		c.release()
		return "", true, false, err
	}
	s.smime.returnConn(accID, false, c)
	p, err := s.saveAttachmentChecked(ctx, a, data)
	return p, true, false, err
}

func TestFormatSMIMETrustErrorAndNULAddrCleanup(t *testing.T) {
	prevLang := i18n.Language()
	t.Cleanup(func() { i18n.SetLanguage(prevLang) })

	te := &smime.TrustError{Issues: []string{smime.CertIssueExpired, smime.CertIssueEmailMismatch, smime.CertIssueWeakSignature}}
	i18n.SetLanguage("zh-Hans")
	require.Equal(t, "证书已过期或尚未生效；证书邮箱与发件人不匹配；证书使用不受支持的签名哈希算法", FormatSMIMEError(te))
	i18n.SetLanguage("en")
	require.Equal(t, "Certificate has expired or is not yet valid; Certificate email does not match address; Certificate uses an unsupported signature hash algorithm", FormatSMIMEError(te))

	require.Empty(t, normalizeCertAddr("brhuo@tendyron.com\x00\x00"))
	require.Empty(t, normalizeCertAddr("brhuo@tendyron.com\n"))
	require.Equal(t, "brhuo@tendyron.com", normalizeCertAddr("  BRHUO@tendyron.com  "))

	e := newSendEnv(t, false)
	ctx := t.Context()
	require.NoError(t, e.s.ensureSMIMETables(ctx))

	// Simulate a pre-existing NUL-padded row in smime_certificates and verify startup cleanup removes it.
	require.NoError(t, e.s.exec(ctx, sqlite.Statement{
		SQL:  `INSERT INTO smime_certificates (sha256, addr_key, source, subject, issuer, not_before, not_after, der, added_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		Args: []any{"deadbeef", "bad@example.com\x00\x00", CertSourceCardDAV, "bad", "ca", 1, 2, []byte{1, 2, 3}, 1},
	}))
	require.NoError(t, e.s.exec(ctx, sqlite.Statement{
		SQL:  `INSERT INTO smime_certificates (sha256, addr_key, source, subject, issuer, not_before, not_after, der, added_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		Args: []any{"cafebabe", "good@example.com", CertSourceCardDAV, "good", "ca", 1, 2, []byte{1, 2, 3}, 1},
	}))
	e.s.smimeTablesOnce = sync.Once{}
	require.NoError(t, e.s.ensureSMIMETables(ctx))

	rows, err := e.s.db.Query(ctx, `SELECT addr_key FROM smime_certificates ORDER BY addr_key`)
	require.NoError(t, err)
	require.Len(t, rows.Values, 1)
	require.Equal(t, "good@example.com", store.Str(rows.Values[0][0]))
}
