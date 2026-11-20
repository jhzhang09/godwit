package core

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"

	"github.com/egoist/mygo/plugins/sqlite"
	"github.com/emmansun/gmsm/smx509"
	gomail "github.com/godwit-email/godwit/core/mail"
	"github.com/godwit-email/godwit/core/store"
	"github.com/godwit-email/godwit/internal/carddav"
	"github.com/godwit-email/godwit/internal/smime"
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
	// 同一个信封会公开全部证书标识；不能让其它收件人看到密送者身份。
	if a.SMIMEEncrypt && len(d.Bcc) > 0 && len(rcpts) > 1 {
		return nil, errors.New("加密邮件请向密送收件人分别发送，以保护密送名单")
	}
	return smime.Protect(ctx, raw, a.Email, rcpts, a.SMIMESign, a.SMIMEEncrypt, func(ctx context.Context, addresses []string) (map[string][]*smx509.Certificate, error) {
		return s.mailboxCertificates(ctx, a.ID, addresses)
	})
}

func (s *Service) mailboxCertificates(ctx context.Context, account int64, addresses []string) (map[string][]*smx509.Certificate, error) {
	rows, err := s.db.Query(ctx, `SELECT DISTINCT a.id FROM attachments a
 JOIN message_locations l ON l.message_id=a.message_id
 JOIN folders f ON f.id=l.folder_id
 WHERE f.account_id=? AND l.shown=1 AND (f.name='邮箱名片' OR (f.delim<>'' AND substr(f.name,-length(f.delim || '邮箱名片'))=f.delim || '邮箱名片'))
 AND (lower(a.filename) LIKE '%.vcf' OR lower(a.content_type) IN ('text/vcard','text/x-vcard')) AND a.size<=1048576 ORDER BY a.id DESC`, account)
	if err != nil {
		return nil, err
	}
	wanted := map[string]bool{}
	for _, addr := range addresses {
		wanted[strings.ToLower(addr)] = true
	}
	result := map[string][]*smx509.Certificate{}
	ids := make([]int64, 0, len(rows.Values))
	for _, r := range rows.Values {
		ids = append(ids, store.Int(r[0]))
	}
	err = s.FetchAttachments(ctx, ids, func(path string, _ AttachmentInfo) error {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if len(data) > 1<<20 {
			return nil
		}
		card := carddav.ParseVCard(string(data))
		for _, email := range card.Emails {
			if !wanted[email.AddrKey] {
				continue
			}
			for _, der := range card.Certificates {
				cert, err := smime.ParseCertificate(der)
				if err == nil && smime.MatchesMailbox(cert, email.AddrKey) {
					result[email.AddrKey] = append(result[email.AddrKey], cert)
				}
			}
		}
		return nil
	})
	return result, err
}

// DecryptedBody holds reader-decrypted S/MIME content transiently in memory
// for the calling RoleUI session only.
type DecryptedBody struct {
	HTML        string
	Text        string
	Truncated   bool
	Attachments []AttachmentInfo
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
	var atts []AttachmentInfo
	size := len(body.HTML) + len(body.Text)
	for _, a := range body.Attachments {
		if smime.IsPart(a.ContentType, a.Filename) {
			continue
		}
		atts = append(atts, a)
		size += len(a.Filename) + len(a.ContentType) + 32
	}
	body.Attachments = atts

	const (
		budget     = 24 << 20
		maxEntries = 64
	)
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
