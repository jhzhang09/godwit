package core

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"github.com/emmansun/gmsm/pkcs7"
	"github.com/godwit-email/godwit/core/store"
	"github.com/godwit-email/godwit/internal/carddav"
	"github.com/godwit-email/godwit/internal/smime"
	"io"
	"math/big"
	"net/mail"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

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
			require.ErrorContains(t, e.s.Send(t.Context(), d.ID), "手动发送")
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
