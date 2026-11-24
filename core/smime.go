package core

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/egoist/mygo/plugins/sqlite"
	"github.com/emmansun/gmsm/smx509"
	gomail "github.com/godwit-email/godwit/core/mail"
	"github.com/godwit-email/godwit/core/store"
	"github.com/godwit-email/godwit/internal/i18n"
	"github.com/godwit-email/godwit/internal/imagefetch"
	"github.com/godwit-email/godwit/internal/smime"
)

var (
	// ErrSMIMEBccEncrypt reports that encrypted outgoing mail cannot include Bcc with multiple recipients.
	ErrSMIMEBccEncrypt = errors.New("encrypted messages cannot use Bcc")
	// ErrSMIMEManualSend reports that S/MIME protected drafts cannot be sent by automated rules or background callers.
	ErrSMIMEManualSend = errors.New("S/MIME protected messages must be sent manually")
	// ErrSMIMEInvalidAddress reports an invalid email address passed to an S/MIME certificate operation.
	ErrSMIMEInvalidAddress = errors.New("invalid S/MIME email address")
	// ErrSMIMECertFileRequired reports an empty certificate file path.
	ErrSMIMECertFileRequired = errors.New("S/MIME certificate file required")
	// ErrSMIMECertFileTooLarge reports a certificate file exceeding the allowed size bounds.
	ErrSMIMECertFileTooLarge = errors.New("S/MIME certificate file too large")
	// ErrSMIMECertInvalid reports a file with no valid X.509 public certificate.
	ErrSMIMECertInvalid = errors.New("no valid X.509 public certificate in file")
	// ErrSMIMECertAddressMismatch reports an imported certificate whose emails do not match the selected recipient address.
	ErrSMIMECertAddressMismatch = errors.New("S/MIME certificate does not match email address")
	// ErrSMIMECertNoEmail reports an imported certificate with no mailbox address.
	ErrSMIMECertNoEmail = errors.New("S/MIME certificate contains no email address")
)

func (s *Service) lockForEnqueue(ctx context.Context, id int64) (func(), error) {
	release, err := s.stopDraftRuns(ctx, id)
	if err != nil {
		return nil, err
	}
	s.editMu.Lock()
	s.pluginsMu.RLock()
	return func() {
		s.pluginsMu.RUnlock()
		s.editMu.Unlock()
		release()
	}, nil
}

func (s *Service) protectOutgoing(ctx context.Context, a Account, d Draft, rcpts []string, raw []byte) ([]byte, error) {
	sign, encrypt, draftPins, err := s.effectiveDraftSMIME(ctx, a, d.ID)
	if err != nil {
		return nil, err
	}
	// 同一个信封会公开全部证书标识；不能让其它收件人看到密送者身份。
	if encrypt && len(d.Bcc) > 0 && len(rcpts) > 1 {
		return nil, ErrSMIMEBccEncrypt
	}
	pinned, err := s.preferredCertMap(ctx, rcpts)
	if err != nil {
		return nil, err
	}
	for k, v := range draftPins {
		pinned[k] = v
	}
	if a.SMIMEAllowWeakKey {
		ctx = smime.WithAllowWeakKeySize(ctx, true)
	}
	return smime.ProtectWith(ctx, raw, a.Email, rcpts, smime.ProtectOptions{
		Sign:         sign,
		Encrypt:      encrypt,
		OwnCertSHA:   a.SMIMECert,
		PinnedCerts:  pinned,
		AllowWeakKey: a.SMIMEAllowWeakKey,
	}, func(ctx context.Context, addresses []string) (map[string][]*smx509.Certificate, error) {
		return s.mailboxCertificates(ctx, a.ID, addresses)
	})
}

// FormatWeakKeySizeError formats a structured weak key-size error in the active UI language.
func FormatWeakKeySizeError(wk *smime.WeakKeySizeError) string {
	if wk != nil && wk.Subject != "" && wk.KeyAlgo != "" && wk.KeyBits > 0 && wk.MinBits > 0 {
		return i18n.Tf("smime.err.weak_key_size", wk.Subject, fmt.Sprintf("%s %d bit", wk.KeyAlgo, wk.KeyBits), strconv.Itoa(wk.MinBits))
	}
	return i18n.T("smime.err.weak_key_size_generic")
}

// FormatTrustIssues formats canonical S/MIME trust issue codes in the active UI language.
func FormatTrustIssues(issues []string) string {
	if len(issues) == 0 {
		return ""
	}
	sep := i18n.T("smime.issue.sep")
	if sep == "" || sep == "smime.issue.sep" {
		sep = "; "
	}
	parts := make([]string, 0, len(issues))
	for _, code := range issues {
		key := "smime.issue." + code
		txt := i18n.T(key)
		if txt == "" || txt == key {
			txt = smime.CertIssueMessage(code)
		}
		parts = append(parts, txt)
	}
	return strings.Join(parts, sep)
}

// FormatSMIMEError formats err for display, translating typed S/MIME errors into localized messages.
func FormatSMIMEError(err error) string {
	if err == nil {
		return ""
	}
	var wk *smime.WeakKeySizeError
	if errors.As(err, &wk) {
		return FormatWeakKeySizeError(wk)
	}
	var te *smime.TrustError
	if errors.As(err, &te) && len(te.Issues) > 0 {
		return FormatTrustIssues(te.Issues)
	}
	return err.Error()
}

// DecryptedInlineImage holds a validated inline image from a decrypted S/MIME
// message in memory for quoting when replying or forwarding.
type DecryptedInlineImage struct {
	ContentID   string
	ContentType string
	Data        []byte
}

// DecryptedBody holds reader-decrypted S/MIME content transiently in memory
// for the calling RoleUI session only.
type DecryptedBody struct {
	HTML         string
	QuoteHTML    string
	Text         string
	Truncated    bool
	Attachments  []AttachmentInfo
	InlineImages []DecryptedInlineImage
}

type decryptedEntry struct {
	id   int64
	body DecryptedBody
	size int
}

const hasRealAttachmentExpr = `EXISTS (SELECT 1 FROM attachments a WHERE a.message_id = messages.id AND NOT ` + smimePartPredicate + `)`

// repairSMIMEHasAttachments recomputes has_attachments for messages carrying
// S/MIME parts so S/MIME envelopes/signatures alone do not mark mail as having
// attachments.
func (s *Service) repairSMIMEHasAttachments(ctx context.Context) error {
	return s.exec(ctx, sqlite.Statement{
		SQL: `UPDATE messages
			SET has_attachments = ` + hasRealAttachmentExpr + `
			WHERE id IN (SELECT message_id FROM attachments a WHERE ` + smimePartPredicate + `)
			  AND COALESCE(has_attachments, 0) != ` + hasRealAttachmentExpr,
	})
}

func smimeKindFromScore(score int64) string {
	switch score {
	case 2:
		return "encrypted"
	case 1:
		return "signed"
	default:
		return ""
	}
}

func (s *Service) smimeScoresByID(ctx context.Context, rawIDs []int64, buildSQL func(ph string) string) (map[int64]int64, error) {
	seen := map[int64]bool{}
	var args []any
	for _, id := range rawIDs {
		if id != 0 && !seen[id] {
			seen[id] = true
			args = append(args, id)
		}
	}
	scores := map[int64]int64{}
	for c := range slices.Chunk(args, 200) {
		rows, err := s.db.Query(ctx, buildSQL(placeholders(len(c))), c...)
		if err != nil {
			return nil, err
		}
		for _, r := range rows.Values {
			id := store.Int(r[0])
			scores[id] = max(scores[id], store.Int(r[1]))
		}
	}
	return scores, nil
}

func (s *Service) fillThreadSMIME(ctx context.Context, items []ThreadSummary) error {
	if len(items) == 0 {
		return nil
	}
	ids := make([]int64, len(items))
	for i, it := range items {
		ids[i] = it.ID
	}
	scores, err := s.smimeScoresByID(ctx, ids, func(ph string) string {
		return `SELECT m.thread_id, MAX(CASE WHEN ` + smimeP7MPredicate + ` THEN 2 ELSE 1 END)
			FROM messages m
			JOIN attachments a ON a.message_id = m.id
			WHERE m.thread_id IN (` + ph + `) AND ` + notPurgedCond + ` AND ` + smimePartPredicate + `
			GROUP BY m.thread_id`
	})
	if err != nil {
		return err
	}
	for i := range items {
		items[i].SMIME = smimeKindFromScore(scores[items[i].ID])
	}
	return nil
}

func (s *Service) fillMessageSMIME(ctx context.Context, items []MessageSummary) error {
	if len(items) == 0 {
		return nil
	}
	ids := make([]int64, len(items))
	for i, it := range items {
		ids[i] = it.ID
	}
	scores, err := s.smimeScoresByID(ctx, ids, func(ph string) string {
		return `SELECT a.message_id, MAX(CASE WHEN ` + smimeP7MPredicate + ` THEN 2 ELSE 1 END)
			FROM attachments a
			WHERE a.message_id IN (` + ph + `) AND ` + smimePartPredicate + `
			GROUP BY a.message_id`
	})
	if err != nil {
		return err
	}
	for i := range items {
		items[i].SMIME = smimeKindFromScore(scores[items[i].ID])
	}
	return nil
}

// SetDecryptedBody stores the sanitized plaintext of a decrypted S/MIME message
// solely in memory for the calling RoleUI session so UI-initiated AI skills,
// translations, and Wit runs can read it without persisting plaintext to disk.
func (s *Service) SetDecryptedBody(ctx context.Context, messageID int64, body DecryptedBody) error {
	ctx, end, err := s.begin(ctx, 0)
	if err != nil {
		return err
	}
	defer end()
	if messageID <= 0 || uiSessionFromContext(ctx) == nil {
		return nil
	}
	id, err := s.resolveID(ctx, messageID)
	if err != nil {
		return err
	}
	if body.HTML != "" {
		body.HTML, _, _ = gomail.Sanitize(body.HTML, nil, false)
	}
	rawQuoteHTML := body.QuoteHTML
	var cleanImgs []DecryptedInlineImage
	if body.QuoteHTML != "" {
		rawInline := make(map[string]gomail.Attachment, len(body.InlineImages))
		for _, img := range body.InlineImages {
			cid := strings.TrimSpace(strings.Trim(strings.TrimSpace(img.ContentID), "<>"))
			if cid == "" || len(img.Data) == 0 || len(img.Data) > imagefetch.MaxImageBytes {
				continue
			}
			if _, ok := rawInline[cid]; !ok {
				rawInline[cid] = gomail.Attachment{ContentID: cid, ContentType: img.ContentType, Data: img.Data}
			}
		}
		var imgs []gomail.Attachment
		body.QuoteHTML, imgs = gomail.PrepareQuoteHTML(body.QuoteHTML, rawInline)
		for _, a := range imgs {
			cleanImgs = append(cleanImgs, DecryptedInlineImage{
				ContentID:   a.ContentID,
				ContentType: a.ContentType,
				Data:        a.Data,
			})
		}
	} else if len(body.InlineImages) > 0 {
		imgBudget := imagefetch.NewBudget()
		seen := make(map[string]bool)
		for _, img := range body.InlineImages {
			cid := strings.TrimSpace(strings.Trim(strings.TrimSpace(img.ContentID), "<>"))
			if cid == "" || seen[cid] || len(img.Data) == 0 || len(img.Data) > imagefetch.MaxImageBytes {
				continue
			}
			format, px, err := imagefetch.Config(img.Data)
			if err != nil || imgBudget.TakeInline(int64(len(img.Data)), px) != nil {
				continue
			}
			seen[cid] = true
			cleanImgs = append(cleanImgs, DecryptedInlineImage{
				ContentID:   cid,
				ContentType: "image/" + format,
				Data:        slices.Clone(img.Data),
			})
		}
	}

	var atts []AttachmentInfo
	baseSize := len(body.HTML) + len(body.QuoteHTML) + len(body.Text)
	for _, a := range body.Attachments {
		if smime.IsPart(a.ContentType, a.Filename) {
			continue
		}
		atts = append(atts, a)
		baseSize += len(a.Filename) + len(a.ContentType) + 32
	}
	body.Attachments = atts

	imgSize := 0
	for _, img := range cleanImgs {
		imgSize += len(img.ContentID) + len(img.ContentType) + len(img.Data) + 32
	}
	const (
		budget     = 24 << 20
		maxEntries = 64
	)
	if baseSize+imgSize > budget {
		cleanImgs = nil
		imgSize = 0
		if rawQuoteHTML != "" {
			body.QuoteHTML = gomail.StripMarkers(gomail.SanitizeCompose(gomail.InlineQuoteCSS(rawQuoteHTML)))
			baseSize = len(body.HTML) + len(body.QuoteHTML) + len(body.Text)
			for _, a := range body.Attachments {
				baseSize += len(a.Filename) + len(a.ContentType) + 32
			}
		}
	}
	body.InlineImages = cleanImgs
	size := baseSize + imgSize
	if size > budget {
		return nil
	}
	s.uiMu.Lock()
	defer s.uiMu.Unlock()
	sess := uiSessionFromContext(ctx)
	if _, ok := s.uiSessions[sess]; sess == nil || !ok {
		return nil
	}
	entries := slices.DeleteFunc(sess.decrypted, func(e decryptedEntry) bool { return e.id == id })
	for total, i := size, 0; i < len(entries); i++ {
		total += entries[i].size
		if total > budget || i+1 >= maxEntries {
			clear(entries[i:])
			entries = entries[:i]
			break
		}
	}
	sess.decrypted = slices.Insert(entries, 0, decryptedEntry{id: id, body: body, size: size})
	return nil
}

func (s *Service) decryptedBody(ctx context.Context, messageID int64) (DecryptedBody, bool) {
	sess := uiSessionFromContext(ctx)
	if sess == nil || messageID <= 0 {
		return DecryptedBody{}, false
	}
	s.uiMu.Lock()
	defer s.uiMu.Unlock()
	if _, ok := s.uiSessions[sess]; !ok {
		return DecryptedBody{}, false
	}
	for i, e := range sess.decrypted {
		if e.id == messageID {
			if i > 0 {
				sess.decrypted = slices.Insert(slices.Delete(sess.decrypted, i, i+1), 0, e)
			}
			out := e.body
			out.Attachments = slices.Clone(e.body.Attachments)
			out.InlineImages = slices.Clone(e.body.InlineImages)
			return out, true
		}
	}
	return DecryptedBody{}, false
}

func (s *Service) clearDecryptedBodies() {
	s.uiMu.Lock()
	defer s.uiMu.Unlock()
	for sess := range s.uiSessions {
		clear(sess.decrypted)
		sess.decrypted = nil
	}
}

// skipAICache reports whether AI outputs for any message in ids must bypass the
// on-disk ai_cache (encrypted S/MIME messages or messages carrying transient
// decrypted bodies in the current UI session).
func (s *Service) skipAICache(ctx context.Context, ids []int64) bool {
	seen := map[int64]bool{}
	var args []any
	for _, id := range ids {
		if id == 0 || seen[id] {
			continue
		}
		if _, ok := s.decryptedBody(ctx, id); ok {
			return true
		}
		seen[id] = true
		args = append(args, id)
	}
	for c := range slices.Chunk(args, 200) {
		rows, err := s.db.Query(ctx,
			`SELECT 1 FROM attachments a WHERE a.message_id IN (`+placeholders(len(c))+`) AND `+smimeP7MPredicate+` LIMIT 1`, c...)
		if err != nil || len(rows.Values) > 0 {
			return true
		}
	}
	return false
}
