package mail

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html"
	"net/mail"
	"strings"

	"github.com/godwit-email/godwit/internal/i18n"
	"github.com/godwit-email/godwit/internal/imagefetch"
)

// AddrKey is the lowercased bare address of an address string ("Bob <b@x>" → "b@x").
func AddrKey(s string) string {
	if a, err := mail.ParseAddress(s); err == nil {
		return strings.ToLower(a.Address)
	}
	return strings.ToLower(strings.TrimSpace(s))
}

// ReplyRecipients picks reply targets: Reply-To if set, else From. With all,
// the original To/Cc are added to cc. self and duplicates are dropped.
// A reply to the user's own mail (From is self, no other Reply-To) follows
// up with its recipients instead: the original To, plus Cc with all.
func ReplyRecipients(orig *Parsed, self string, all bool) (to, cc []string) {
	seen := map[string]bool{AddrKey(self): true}
	add := func(dst *[]string, in ...string) {
		for _, s := range in {
			if s = strings.TrimSpace(s); s != "" && !seen[AddrKey(s)] {
				seen[AddrKey(s)] = true
				*dst = append(*dst, s)
			}
		}
	}
	if FromSelf(orig.From, orig.ReplyTo, self) {
		add(&to, orig.To...)
		if all {
			add(&cc, orig.Cc...)
		}
		return
	}
	if orig.ReplyTo != "" {
		add(&to, orig.ReplyTo)
	} else {
		add(&to, orig.From)
	}
	if all {
		add(&cc, orig.To...)
		add(&cc, orig.Cc...)
	}
	return
}

// FromSelf reports whether a mail from from (with Reply-To replyTo, "" for
// none) is the user's own at self: a reply to it goes to its recipients.
func FromSelf(from, replyTo, self string) bool {
	key := AddrKey(self)
	return key != "" && AddrKey(from) == key && (replyTo == "" || AddrKey(replyTo) == key)
}

// QuoteHTML returns the "on {date}, {from} wrote:" line plus the original in a blockquote.
func QuoteHTML(orig *Parsed) string { return QuoteHTMLIn(orig, "") }

// QuoteHTMLIn formats QuoteHTML with the attribution line in lang ("" or zh-Hans defaults to Simplified Chinese).
func QuoteHTMLIn(orig *Parsed, lang string) string {
	body := StripMarkers(SanitizeCompose(InlineQuoteCSS(orig.HTML))) // the quoted mail's own markers are content
	if orig.HTML == "" {
		body = strings.ReplaceAll(html.EscapeString(strings.ReplaceAll(orig.Text, "\r\n", "\n")), "\n", "<br>")
	}
	date, from := i18n.FullDateIn(orig.Date, cmp.Or(lang, "zh-Hans"))+orig.Date.Format(" 15:04"), html.EscapeString(orig.From)
	return "<p>" + quoteLead(lang, date, from) + "</p><blockquote>" + body + "</blockquote>"
}

// QuoteHTMLWith formats the reply/forward quote with attribution in lang,
// inlining safe <style> rules and extracting valid cid: (from inline) and
// data:image/... images as content-addressed quote-<hash>@godwit attachments.
func QuoteHTMLWith(orig *Parsed, lang string, inline map[string]Attachment) (string, []Attachment) {
	var body string
	var images []Attachment
	if orig.HTML == "" {
		body = strings.ReplaceAll(html.EscapeString(strings.ReplaceAll(orig.Text, "\r\n", "\n")), "\n", "<br>")
	} else {
		body, images = PrepareQuoteHTML(orig.HTML, inline)
	}
	date, from := i18n.FullDateIn(orig.Date, cmp.Or(lang, "zh-Hans"))+orig.Date.Format(" 15:04"), html.EscapeString(orig.From)
	return "<p>" + quoteLead(lang, date, from) + "</p><blockquote>" + body + "</blockquote>", images
}

// PrepareQuoteHTML inlines safe <style> rules in htmlBody, converts valid cid:
// (resolved against inline) and data:image/... images into deduplicated
// content-addressed quote-<hash>@godwit inline attachments, and returns the
// sanitized compose-safe HTML body (without draft markers) and those images.
func PrepareQuoteHTML(htmlBody string, inline map[string]Attachment) (string, []Attachment) {
	if htmlBody == "" {
		return "", nil
	}
	lookup := make(map[string]Attachment, len(inline))
	lowerLookup := make(map[string]Attachment, len(inline))
	for k, a := range inline {
		cid := cleanID(k)
		if cid == "" {
			continue
		}
		if _, ok := lookup[cid]; !ok {
			lookup[cid] = a
		}
		lk := strings.ToLower(cid)
		if _, ok := lowerLookup[lk]; !ok {
			lowerLookup[lk] = a
		}
	}

	inlined := InlineQuoteCSS(htmlBody)
	budget := imagefetch.NewBudget()
	keepCIDs := make(map[string]bool)
	byCID := make(map[string]Attachment)
	var order []string

	addImage := func(data []byte) string {
		if len(data) == 0 || len(data) > imagefetch.MaxImageBytes {
			return ""
		}
		format, px, err := imagefetch.Config(data)
		if err != nil {
			return ""
		}
		sum := sha256.Sum256(data)
		qcid := "quote-" + hex.EncodeToString(sum[:16]) + "@godwit"
		if _, ok := byCID[qcid]; ok {
			return "cid:" + qcid
		}
		if err := budget.TakeInline(int64(len(data)), px); err != nil {
			return ""
		}
		byCID[qcid] = Attachment{
			ContentID:   qcid,
			ContentType: "image/" + format,
			Data:        data,
			Size:        len(data),
			Inline:      true,
		}
		keepCIDs[qcid] = true
		order = append(order, qcid)
		return "cid:" + qcid
	}

	rewritten := ReplaceImages(inlined, func(src string) string {
		s := strings.TrimSpace(src)
		lower := strings.ToLower(s)
		switch {
		case strings.HasPrefix(lower, "cid:"):
			key := cleanID(s[4:])
			if key == "" {
				return ""
			}
			if a, ok := lookup[key]; ok {
				return addImage(a.Data)
			}
			if a, ok := lowerLookup[strings.ToLower(key)]; ok {
				return addImage(a.Data)
			}
			return ""
		case strings.HasPrefix(lower, "data:"):
			data, err := imagefetch.DataURL(s)
			if err != nil {
				return ""
			}
			return addImage(data)
		default:
			return src
		}
	})

	body := StripMarkers(SanitizeDraft(rewritten, keepCIDs))
	if len(order) == 0 {
		return body, nil
	}
	used := make(map[string]bool)
	for _, cid := range CIDs(body) {
		used[cid] = true
	}
	var images []Attachment
	for _, cid := range order {
		if used[cid] {
			images = append(images, byCID[cid])
		}
	}
	return body, images
}

func quoteLead(lang, date, from string) string {
	t := strings.ToLower(strings.TrimSpace(lang))
	if strings.HasPrefix(t, "zh-tw") || strings.HasPrefix(t, "zh-hant") || strings.HasPrefix(t, "zh-hk") || strings.HasPrefix(t, "zh-mo") {
		return fmt.Sprintf("於 %s，%s 寫道：", date, from)
	}
	base, _, _ := strings.Cut(t, "-")
	switch base {
	case "", "zh":
		return fmt.Sprintf("于 %s，%s 写道：", date, from)
	case "ja":
		return fmt.Sprintf("%s、%s さんは書きました：", date, from)
	case "ko":
		return fmt.Sprintf("%s에 %s 님이 작성:", date, from)
	case "de":
		return fmt.Sprintf("Am %s schrieb %s:", date, from)
	case "fr":
		return fmt.Sprintf("Le %s, %s a écrit :", date, from)
	case "es":
		return fmt.Sprintf("El %s, %s escribió:", date, from)
	case "pt":
		return fmt.Sprintf("Em %s, %s escreveu:", date, from)
	case "it":
		return fmt.Sprintf("Il %s, %s ha scritto:", date, from)
	case "ru":
		return fmt.Sprintf("%s, %s пишет:", date, from)
	case "nl":
		return fmt.Sprintf("Op %s schreef %s:", date, from)
	case "pl":
		return fmt.Sprintf("%s, %s napisał(a):", date, from)
	case "tr":
		return fmt.Sprintf("%s tarihinde %s yazdı:", date, from)
	case "vi":
		return fmt.Sprintf("Vào %s, %s đã viết:", date, from)
	default:
		return fmt.Sprintf("On %s, %s wrote:", date, from)
	}
}

func hasPrefix(s string, prefixes ...string) bool {
	l := strings.ToLower(strings.TrimSpace(s))
	for _, p := range prefixes {
		if strings.HasPrefix(l, p+":") || strings.HasPrefix(l, p+"：") {
			return true
		}
	}
	return false
}

func ReplySubject(s string) string {
	if hasPrefix(s, "re", "aw", "res", "antw", "ynt", "odp", "回复", "答复", "回覆", "답장") {
		return s
	}
	return "Re: " + s
}

func ForwardSubject(s string) string {
	if IsForwardSubject(s) {
		return s
	}
	return "Fwd: " + s
}

// IsForwardSubject reports whether s starts with a forward prefix, as every
// subject from ForwardSubject does.
func IsForwardSubject(s string) bool {
	return hasPrefix(s, "fwd", "fw", "wg", "tr", "rv", "enc", "dr", "ilt", "pd", "转发", "轉寄", "轉發", "전달")
}
