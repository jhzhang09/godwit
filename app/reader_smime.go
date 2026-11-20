package app

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/godwit-email/godwit/core"
	"github.com/godwit-email/godwit/core/mail"
	"github.com/godwit-email/godwit/internal/i18n"
	"github.com/godwit-email/godwit/internal/icons"
	"github.com/godwit-email/godwit/internal/kit"
	"github.com/godwit-email/godwit/internal/smime"
	"github.com/godwit-email/godwit/internal/theme"
)

type secureBody struct {
	html      string
	text      string
	truncated bool
}

type secureMessage struct {
	signer      string
	encrypted   bool
	attachments []mail.Attachment
}

type cachedSecure struct {
	id        int64
	result    secureMessage
	html      string
	modelHTML string
	text      string
	truncated bool
	modelAtts []core.AttachmentInfo
	syncModel bool
	size      int
}

func (c cachedSecure) decryptedBody() core.DecryptedBody {
	return core.DecryptedBody{
		HTML:        c.modelHTML,
		Text:        c.text,
		Truncated:   c.truncated,
		Attachments: slices.Clone(c.modelAtts),
	}
}

func buildModelAttachments(atts []mail.Attachment) []core.AttachmentInfo {
	var out []core.AttachmentInfo
	for _, att := range atts {
		if smime.IsPart(att.ContentType, att.Filename) {
			continue
		}
		out = append(out, core.AttachmentInfo{
			Filename:    att.Filename,
			ContentType: att.ContentType,
			Size:        att.Size,
			Inline:      att.Inline,
		})
	}
	return out
}

// 仅在阅读会话内存中保留最近解封的少量结果，不落盘，切换回看时无需再次访问硬件 Key。
func (r *reader) lookupSecure(id int64) (cachedSecure, bool) {
	for i, e := range r.openedSecure {
		if e.id == id {
			if i > 0 {
				r.openedSecure = slices.Insert(slices.Delete(r.openedSecure, i, i+1), 0, e)
			}
			return e, true
		}
	}
	return cachedSecure{}, false
}

func (r *reader) forgetSecure(id int64) {
	r.openedSecure = slices.DeleteFunc(r.openedSecure, func(e cachedSecure) bool { return e.id == id })
}

func (r *reader) rememberSecure(entry cachedSecure) {
	const (
		budget     = 24 << 20
		maxEntries = 64
	)
	if entry.size > budget {
		return
	}
	entries := slices.DeleteFunc(r.openedSecure, func(e cachedSecure) bool { return e.id == entry.id })
	for total, i := entry.size, 0; i < len(entries); i++ {
		total += entries[i].size
		if total > budget || i+1 >= maxEntries {
			clear(entries[i:])
			entries = entries[:i]
			break
		}
	}
	r.openedSecure = slices.Insert(entries, 0, entry)
}

func protectedMail(m core.Message) bool {
	return slices.ContainsFunc(m.Attachments, func(att core.AttachmentInfo) bool { return smime.IsPart(att.ContentType, att.Filename) })
}

func singleP7MAttachment(m core.Message) (core.AttachmentInfo, bool) {
	if len(m.Attachments) != 1 || m.HTML != "" || m.Text != "" {
		return core.AttachmentInfo{}, false
	}
	att := m.Attachments[0]
	return att, smime.IsCMSPart(att.ContentType, att.Filename)
}

func smimeText(key string, args ...any) string {
	lang := "en"
	switch i18n.Language() {
	case "zh-Hans", "zh-Hant":
		lang = i18n.Language()
	}
	texts := map[string]map[string]string{
		"zh-Hans": {
			"smime.sign":            "发送时数字签名",
			"smime.sign.help":       "使用此账户的硬件 Key，优先 SHA-256，旧卡可能需要 SHA-1。",
			"smime.encrypt":         "发送时加密",
			"smime.encrypt.help":    "从邮箱名片文件夹读取收件人证书。缺少可用证书时保留草稿。",
			"smime.decrypted":       "已解密",
			"smime.verified":        "签名已验证 · %s",
			"smime.save":            "保存 %s",
			"smime.badge.encrypted": "加密邮件",
			"smime.badge.signed":    "数字签名",
		},
		"zh-Hant": {
			"smime.sign":            "寄送時數位簽章",
			"smime.sign.help":       "使用此帳號的硬體金鑰，優先採用 SHA-256；舊卡可能需要 SHA-1。",
			"smime.encrypt":         "寄送時加密",
			"smime.encrypt.help":    "從「邮箱名片」資料夾讀取收件人憑證。缺少憑證時保留草稿。",
			"smime.decrypted":       "已解密",
			"smime.verified":        "已驗證簽章 · %s",
			"smime.save":            "儲存 %s",
			"smime.badge.encrypted": "加密郵件",
			"smime.badge.signed":    "數位簽章",
		},
		"en": {
			"smime.sign":            "Sign outgoing mail",
			"smime.sign.help":       "Use the hardware key for this account. Prefer SHA-256; older keys may require SHA-1.",
			"smime.encrypt":         "Encrypt outgoing mail",
			"smime.encrypt.help":    "Use recipient certificates from the 邮箱名片 mail folder. A missing certificate stops the send.",
			"smime.decrypted":       "Decrypted",
			"smime.verified":        "Signature verified · %s",
			"smime.save":            "Save %s",
			"smime.badge.encrypted": "Encrypted",
			"smime.badge.signed":    "Signed",
		},
	}
	msg := texts[lang][key]
	if msg == "" {
		msg = key
	}
	if len(args) > 0 {
		return fmt.Sprintf(msg, args...)
	}
	return msg
}

func smimeListIcon(c *ui.Context, kind string) {
	icon, labelKey := "", ""
	switch kind {
	case "encrypted":
		icon, labelKey = "lock", "smime.badge.encrypted"
	case "signed":
		icon, labelKey = "shield-check", "smime.badge.signed"
	default:
		return
	}
	ui.Icon(c, icons.Get(icon)).Size(theme.IconXs, theme.IconXs).TextColor(theme.Of(c).Muted).Label(smimeText(labelKey))
}

func (r *reader) smimeNotice(c *ui.Context, id int64, b *msgBody) {
	if r.p.a.cards == nil {
		return
	}
	if result := b.smimeResult; result != nil {
		var labels []string
		icon := "shield-check"
		if result.encrypted {
			icon = "lock"
			labels = append(labels, smimeText("smime.decrypted"))
		}
		if result.signer != "" {
			labels = append(labels, smimeText("smime.verified", result.signer))
		}
		if len(labels) == 0 {
			return
		}
		t, th := theme.Of(c), c.Theme()
		ui.Row(c).Gap(th.Space(1.5)).AlignItems(ui.Center).Children(func() {
			ui.Icon(c, icons.Get(icon)).Size(theme.IconXs, theme.IconXs).TextColor(t.Muted)
			ui.Text(c, strings.Join(labels, " · ")).Selectable()
		})
		return
	}
	if b.smimeRead.loading {
		kit.Spinner(c)
	} else if b.smimeErr != nil {
		kit.Alert(c, kit.Danger, humanize(b.smimeErr), func() {
			kit.AlertAction(c, kit.Danger, i18n.T("common.retry"), func() { r.openSMIME(id, b, true) })
		})
	}
}

func (r *reader) needsSMIMEDecrypt(id int64) bool {
	if r.p.a.cards == nil {
		return false
	}
	if b := r.bodies[id]; b != nil && b.smimeResult != nil && b.smimeSynced {
		return false
	}
	if i := slices.IndexFunc(r.msgs, func(m core.MessageSummary) bool { return m.ID == id }); i >= 0 && r.msgs[i].SMIME == "encrypted" {
		return true
	}
	if b := r.bodies[id]; b != nil && b.ready {
		if b.msg.SMIME == "encrypted" {
			return true
		}
		return slices.ContainsFunc(b.msg.Attachments, func(att core.AttachmentInfo) bool {
			return smime.IsCMSPart(att.ContentType, att.Filename)
		})
	}
	return false
}

// prepareSMIMEView 在创建正文 WebView 之前提前启动密文解封，使构建页面与硬件激活并行。
func (r *reader) prepareSMIMEView(id int64, b *msgBody) {
	if r.p.a.cards == nil || !protectedMail(b.msg) {
		return
	}
	if b.smimeResult == nil && !b.smimeRead.loading && b.smimeErr == nil {
		r.openSMIME(id, b, false)
	}
}

// flushSMIMEView 在 NewBodyView 绑定完成后交付提前解封好的正文。
func (r *reader) flushSMIMEView(id int64, b *msgBody) {
	if p := b.smimePending; p != nil {
		b.smimePending = nil
		b.translation = nil
		r.p.a.plat.ShowSecureBody(id, p.html, p.text, p.truncated)
		return
	}
	if r.p.a.cards != nil && protectedMail(b.msg) && b.smimeResult == nil && !b.smimeRead.loading && b.smimeErr == nil {
		r.openSMIME(id, b, false)
	}
}

func (r *reader) openSMIME(id int64, b *msgBody, retry bool) {
	a, session, customOpen := r.p.a, r.session, r.openCMS
	b.smimePending = nil
	if retry {
		r.forgetSecure(id)
	} else if cached, ok := r.lookupSecure(id); ok {
		res := cached.result
		b.smimeErr = nil
		b.smimeResult = &res
		b.translation = nil
		if b.view != nil {
			a.plat.ShowSecureBody(id, cached.html, cached.text, cached.truncated)
		} else {
			b.smimePending = &secureBody{html: cached.html, text: cached.text, truncated: cached.truncated}
		}
		if !cached.syncModel {
			b.smimeSynced = true
			return
		}
		b.smimeSynced = false
		body := cached.decryptedBody()
		b.smimeRead.Run(a, func(ctx context.Context) error {
			return a.svc.SetDecryptedBody(ctx, id, body)
		}, func(err error) {
			if !r.has(session) || !r.open[id] || r.bodies[id] != b {
				return
			}
			if err == nil {
				b.smimeSynced = true
				r.onSMIMEDecrypted(id)
			}
		})
		return
	}

	var result secureMessage
	var safe, modelHTML, text string
	var modelAtts []core.AttachmentInfo
	var truncated, syncModel, synced bool
	var cachedSize int
	msg := b.msg
	cmsAtt, useAttCache := singleP7MAttachment(msg)
	b.smimeErr = nil
	b.smimeSynced = false
	b.smimeRead.Run(a, func(ctx context.Context) error {
		t0 := time.Now()
		var attDur, readDur, openDur, parseDur time.Duration
		if retry {
			if err := a.cards.Retry(ctx); err != nil {
				return err
			}
		}
		var opened smime.Opened
		if useAttCache {
			tAtt := time.Now()
			path, _, err := a.svc.GetAttachment(ctx, cmsAtt.ID)
			attDur = time.Since(tAtt)
			if err != nil {
				return fmt.Errorf("读取加密邮件附件: %w", err)
			}
			tRead := time.Now()
			der, err := os.ReadFile(path)
			readDur = time.Since(tRead)
			if err != nil {
				return fmt.Errorf("读取加密邮件缓存: %w", err)
			}
			tOpen := time.Now()
			if customOpen != nil {
				entity, enc, signer, oerr := customOpen(ctx, msg.From, der)
				opened = smime.Opened{Entity: entity, Encrypted: enc, Signer: signer}
				err = oerr
			} else {
				opened, err = a.cards.OpenCMS(ctx, msg.From, der)
			}
			openDur = time.Since(tOpen)
			if err != nil {
				return err
			}
		} else {
			tAtt := time.Now()
			raw, err := rawMessage(ctx, a.svc, id)
			attDur = time.Since(tAtt)
			if err != nil {
				return fmt.Errorf("读取邮件原件: %w", err)
			}
			tOpen := time.Now()
			opened, err = a.cards.Open(ctx, raw)
			openDur = time.Since(tOpen)
			if err != nil {
				return err
			}
		}
		tParse := time.Now()
		parsed, err := mail.Parse(opened.Entity)
		if err != nil {
			return fmt.Errorf("解析已解密正文: %w", err)
		}
		result.signer, result.encrypted = opened.Signer, opened.Encrypted
		inline := map[string]mail.Attachment{}
		for _, att := range parsed.Attachments {
			if att.ContentID != "" {
				inline[att.ContentID] = att
			}
			if !att.Inline || att.Filename != "" {
				result.attachments = append(result.attachments, att)
				cachedSize += len(att.Data)
			}
		}
		safe, _, _ = mail.Sanitize(parsed.HTML, inline, false)
		text, truncated = parsed.Text, parsed.Truncated
		syncModel = result.encrypted || (msg.HTML == "" && msg.Text == "")
		if syncModel {
			modelHTML, _, _ = mail.Sanitize(parsed.HTML, nil, false)
			modelAtts = buildModelAttachments(result.attachments)
			if err := a.svc.SetDecryptedBody(ctx, id, core.DecryptedBody{
				HTML:        modelHTML,
				Text:        text,
				Truncated:   truncated,
				Attachments: modelAtts,
			}); err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				if readerTiming {
					log.Printf("smime timing: message %d SetDecryptedBody error: %v", id, err)
				}
			} else {
				synced = true
			}
		} else {
			synced = true
		}
		cachedSize += len(safe) + len(text)
		parseDur = time.Since(tParse)
		if readerTiming {
			log.Printf("smime timing: message %d useCache=%t total %s (att %s, read %s, open %s, parse %s)",
				id, useAttCache, time.Since(t0).Round(time.Millisecond),
				attDur.Round(time.Millisecond), readDur.Round(time.Millisecond),
				openDur.Round(time.Millisecond), parseDur.Round(time.Millisecond))
		}
		return nil
	}, func(err error) {
		if !r.has(session) || !r.open[id] || r.bodies[id] != b {
			return
		}
		if err != nil {
			b.smimeErr = err
			return
		}
		r.rememberSecure(cachedSecure{
			id:        id,
			result:    result,
			html:      safe,
			modelHTML: modelHTML,
			text:      text,
			truncated: truncated,
			modelAtts: modelAtts,
			syncModel: syncModel,
			size:      cachedSize,
		})
		b.smimeResult = &result
		b.smimeSynced = synced
		b.translation = nil
		if b.view != nil {
			a.plat.ShowSecureBody(id, safe, text, truncated)
		} else {
			b.smimePending = &secureBody{html: safe, text: text, truncated: truncated}
		}
		if syncModel && synced {
			r.onSMIMEDecrypted(id)
		}
	})
}

func (r *reader) secureAttachments(c *ui.Context, m *secureMessage) {
	a := r.p.a
	for _, att := range m.attachments {
		name := core.FileName(att.Filename, "attachment")
		if kit.Button(c, smimeText("smime.save", name), kit.ButtonOpts{Variant: kit.Outline, Icon: "download"}).Clicked() {
			a.do(func(ctx context.Context) error {
				dst, err := a.plat.SaveFile(name)
				if err != nil || dst == "" {
					return err
				}
				if err = writeAttachmentAtomic(dst, att.Data); err != nil {
					return err
				}
				_ = markFromInternet(dst)
				return nil
			}, a.toastErr)
		}
	}
}

func writeAttachmentAtomic(dst string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(dst), ".godwit-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Chmod(0o644); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		return err
	}
	cleanup = false
	return nil
}
