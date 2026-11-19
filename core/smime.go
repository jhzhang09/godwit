package core

import (
	"context"
	"errors"
	"os"
	"strings"

	"github.com/emmansun/gmsm/smx509"
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
