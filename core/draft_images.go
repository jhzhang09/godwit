package core

import (
	"context"
	"encoding/base64"
	"strings"

	"github.com/egoist/mygo/plugins/sqlite"
	"github.com/godwit-email/godwit/core/mail"
	"github.com/godwit-email/godwit/core/store"
)

const (
	// draftImagesLimit bounds stored inline quote images per draft so user
	// attachments still fit under attachLimit.
	draftImagesLimit = 15 << 20
	// maxRPCInlineRawBytes bounds raw image bytes inlined as data: URLs over
	// JSON-RPC so encoded payloads stay well under rpc.MaxMessage (16 MiB).
	maxRPCInlineRawBytes = 8 << 20
)

func (s *Service) draftImages(ctx context.Context, draftID int64, data bool) (map[string]mail.Attachment, error) {
	if draftID <= 0 {
		return map[string]mail.Attachment{}, nil
	}
	q := "SELECT cid, content_type, NULL FROM draft_images WHERE draft_id = ?"
	if data {
		q = "SELECT cid, content_type, data FROM draft_images WHERE draft_id = ?"
	}
	rows, err := s.db.Query(ctx, q, draftID)
	if err != nil {
		return nil, err
	}
	out := make(map[string]mail.Attachment, len(rows.Values))
	for _, r := range rows.Values {
		b, _ := r[2].([]byte)
		id := store.Str(r[0])
		out[id] = mail.Attachment{ContentID: id, ContentType: store.Str(r[1]), Data: b, Size: len(b), Inline: true}
	}
	return out, nil
}

func (s *Service) draftAllowedCIDs(ctx context.Context, draftID int64, extra ...map[string]bool) (map[string]bool, error) {
	out, err := s.signatureCIDs(ctx)
	if err != nil {
		return nil, err
	}
	if draftID > 0 {
		dimgs, err := s.draftImages(ctx, draftID, false)
		if err != nil {
			return nil, err
		}
		for id := range dimgs {
			out[id] = true
		}
	}
	for _, m := range extra {
		for id, ok := range m {
			if ok {
				out[id] = true
			}
		}
	}
	return out, nil
}

func (s *Service) sanitizeDraftFor(ctx context.Context, draftID int64, html string, extra ...map[string]bool) (string, error) {
	cids, err := s.draftAllowedCIDs(ctx, draftID, extra...)
	if err != nil {
		return "", err
	}
	return mail.SanitizeDraft(html, cids), nil
}

func (s *Service) saveDraftImages(ctx context.Context, draftID int64, imgs []mail.Attachment) error {
	if draftID <= 0 || len(imgs) == 0 {
		return nil
	}
	rows, err := s.db.Query(ctx, "SELECT COALESCE(SUM(length(data)), 0) FROM draft_images WHERE draft_id = ?", draftID)
	if err != nil {
		return err
	}
	var total int64
	if len(rows.Values) > 0 {
		total = store.Int(rows.Values[0][0])
	}
	var stmts []sqlite.Statement
	for _, img := range imgs {
		if img.ContentID == "" || len(img.Data) == 0 {
			continue
		}
		if total+int64(len(img.Data)) > draftImagesLimit {
			continue
		}
		total += int64(len(img.Data))
		stmts = append(stmts, sqlite.Statement{
			SQL:  "INSERT OR IGNORE INTO draft_images(draft_id, cid, content_type, data) VALUES (?, ?, ?, ?)",
			Args: []any{draftID, img.ContentID, img.ContentType, img.Data},
		})
	}
	if len(stmts) == 0 {
		return nil
	}
	_, err = s.db.Transaction(ctx, stmts)
	return err
}

func (s *Service) inlineCIDMap(ctx context.Context, draftID int64, html string, maxRawBytes int) (string, error) {
	if len(mail.CIDs(html)) == 0 {
		return html, nil
	}
	sigImgs, err := s.signatureImages(ctx, true)
	if err != nil {
		return "", err
	}
	draftImgs, err := s.draftImages(ctx, draftID, true)
	if err != nil {
		return "", err
	}
	used := 0
	return mail.ReplaceImages(html, func(src string) string {
		if !strings.HasPrefix(src, "cid:") {
			return src
		}
		id := strings.TrimPrefix(src, "cid:")
		if a, ok := sigImgs[id]; ok {
			return "data:" + a.ContentType + ";base64," + base64.StdEncoding.EncodeToString(a.Data)
		}
		if a, ok := draftImgs[id]; ok {
			if maxRawBytes > 0 && used+len(a.Data) > maxRawBytes {
				return ""
			}
			used += len(a.Data)
			return "data:" + a.ContentType + ";base64," + base64.StdEncoding.EncodeToString(a.Data)
		}
		return src
	}), nil
}

// InlineDraftImages is html (sanitized compose HTML for draftID) with its
// signature images and stored draft images (up to maxRPCInlineRawBytes) as
// data: URLs, for showing only: never save it as a draft, as saving drops
// data: sources.
func (s *Service) InlineDraftImages(ctx context.Context, draftID int64, html string) (string, error) {
	return s.inlineCIDMap(ctx, draftID, html, maxRPCInlineRawBytes)
}

// QuoteShown is a draft's quote block (mail.SplitDraft's) as the compose page
// shows it, read-only: sanitized first (SanitizeDraft, keeping signature and
// draft images, markers dropped), then its images as data: URLs (draft images
// capped at maxRPCInlineRawBytes). "" for none.
func (s *Service) QuoteShown(ctx context.Context, draftID int64, block string) (string, error) {
	if strings.TrimSpace(block) == "" {
		return "", nil
	}
	clean, err := s.sanitizeDraftFor(ctx, draftID, mail.StripMarkers(block))
	if err != nil {
		return "", err
	}
	return s.inlineCIDMap(ctx, draftID, clean, maxRPCInlineRawBytes)
}
