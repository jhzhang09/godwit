package mail_test

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/godwit-email/godwit/core/mail"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReplyRecipients(t *testing.T) {
	o := &mail.Parsed{From: "A <a@x.com>", To: []string{"Me <me@x.com>", "b@x.com"}, Cc: []string{"c@x.com", "ME@X.com", "b@x.com"}}
	to, cc := mail.ReplyRecipients(o, "me@x.com", false)
	assert.Equal(t, []string{"A <a@x.com>"}, to)
	assert.Empty(t, cc)
	to, cc = mail.ReplyRecipients(o, "me@x.com", true)
	assert.Equal(t, []string{"A <a@x.com>"}, to)
	assert.Equal(t, []string{"b@x.com", "c@x.com"}, cc)
	o.ReplyTo = "r@x.com"
	to, _ = mail.ReplyRecipients(o, "me@x.com", false)
	assert.Equal(t, []string{"r@x.com"}, to)
}

func TestReplyRecipientsOwnMail(t *testing.T) {
	o := &mail.Parsed{From: "Me <ME@x.com>", To: []string{"J <j@x.com>", "k@x.com"}, Cc: []string{"c@x.com", "me@x.com"}}
	to, cc := mail.ReplyRecipients(o, "me@x.com", false)
	assert.Equal(t, []string{"J <j@x.com>", "k@x.com"}, to)
	assert.Empty(t, cc)
	to, cc = mail.ReplyRecipients(o, "me@x.com", true)
	assert.Equal(t, []string{"J <j@x.com>", "k@x.com"}, to)
	assert.Equal(t, []string{"c@x.com"}, cc)
	o.ReplyTo = "me@x.com"
	to, _ = mail.ReplyRecipients(o, "me@x.com", false)
	assert.Equal(t, []string{"J <j@x.com>", "k@x.com"}, to)
	// A Reply-To elsewhere still wins: the user asked for replies to go there.
	o.ReplyTo = "list@x.com"
	to, _ = mail.ReplyRecipients(o, "me@x.com", false)
	assert.Equal(t, []string{"list@x.com"}, to)
}

func TestFromSelf(t *testing.T) {
	assert.True(t, mail.FromSelf("Me <Me@X.com>", "", "me@x.com"))
	assert.True(t, mail.FromSelf("me@x.com", "Me <me@x.com>", "me@x.com"))
	assert.False(t, mail.FromSelf("me@x.com", "r@x.com", "me@x.com"))
	assert.False(t, mail.FromSelf("a@x.com", "", "me@x.com"))
	assert.False(t, mail.FromSelf("", "", ""))
}

func TestSubjects(t *testing.T) {
	assert.Equal(t, "Re: Q4", mail.ReplySubject("Re: Q4"))
	assert.Equal(t, "Re: 报销", mail.ReplySubject("报销"))
	assert.Equal(t, "回复：报销", mail.ReplySubject("回复：报销"))
	assert.Equal(t, "回覆：報銷", mail.ReplySubject("回覆：報銷"))
	assert.Equal(t, "AW: Angebot", mail.ReplySubject("AW: Angebot"))
	assert.Equal(t, "답장: 보고서", mail.ReplySubject("답장: 보고서"))
	assert.Equal(t, "Fwd: Q4", mail.ForwardSubject("Q4"))
	assert.True(t, mail.IsForwardSubject(mail.ForwardSubject("Re: Q4")))
	assert.False(t, mail.IsForwardSubject("Re: Fwd: Q4"))
	assert.Equal(t, "Fwd: Q4", mail.ForwardSubject("Fwd: Q4"))
	assert.Equal(t, "转发：Q4", mail.ForwardSubject("转发：Q4"))
	assert.Equal(t, "轉寄：Q4", mail.ForwardSubject("轉寄：Q4"))
	assert.Equal(t, "WG: Angebot", mail.ForwardSubject("WG: Angebot"))
	assert.Equal(t, "PD: Oferta", mail.ForwardSubject("PD: Oferta"))
	assert.Equal(t, "ODP: Oferta", mail.ReplySubject("ODP: Oferta"))
	assert.Equal(t, "TR: Facture", mail.ForwardSubject("TR: Facture"))
}

func TestQuoteHTML(t *testing.T) {
	d := time.Date(2026, 1, 2, 3, 4, 0, 0, time.UTC)
	q := mail.QuoteHTML(&mail.Parsed{From: "A <a@x.com>", Date: d, HTML: "<p>hi</p><script>x</script>"})
	assert.Contains(t, q, "2026/01/02 03:04")
	assert.Contains(t, q, `A &lt;<a href="mailto:a@x.com">a@x.com</a>&gt;`)
	assert.Contains(t, q, `<blockquote style="margin: 8px 0; padding-left: 12px; border-left: 2px solid rgba(127, 127, 127, 0.28)">`)
	assert.Contains(t, q, "<p>hi</p>")
	assert.NotContains(t, q, "script")
	assert.Contains(t, mail.SanitizeDraft(q, nil), "border-left: 2px solid rgba(127, 127, 127, 0.28)")
	safe, _, _ := mail.Sanitize(q, nil, false)
	assert.Contains(t, safe, "border-left: 2px solid rgba(127, 127, 127, 0.28)")
	q = mail.QuoteHTML(&mail.Parsed{From: "a@x.com", Date: d, Text: "<b>\nline2"})
	assert.Contains(t, q, "&lt;b&gt;<br>")
	assert.Contains(t, mail.QuoteHTMLIn(&mail.Parsed{From: "a@x.com", Date: d, Text: "hi"}, "en"), `On 1/02/2026 03:04, <a href="mailto:a@x.com">a@x.com</a> wrote:`)
	assert.Contains(t, mail.QuoteHTMLIn(&mail.Parsed{From: "a@x.com", Date: d, Text: "hi"}, "en-GB"), `On 02/01/2026 03:04, <a href="mailto:a@x.com">a@x.com</a> wrote:`)
	assert.Contains(t, mail.QuoteHTMLIn(&mail.Parsed{From: "a@x.com", Date: d, Text: "hi"}, "zh-Hant"), `於 2026/01/02 03:04，<a href="mailto:a@x.com">a@x.com</a> 寫道：`)
	assert.Contains(t, mail.QuoteHTMLIn(&mail.Parsed{From: "a@x.com", Date: d, Text: "hi"}, "de"), `Am 02.01.2026 03:04 schrieb <a href="mailto:a@x.com">a@x.com</a>:`)
	assert.Contains(t, mail.QuoteHTMLIn(&mail.Parsed{From: "a@x.com", Date: d, Text: "hi"}, "ja"), `2026/01/02 03:04、<a href="mailto:a@x.com">a@x.com</a> さんは書きました：`)
}

func TestQuoteHTMLOutlook(t *testing.T) {
	d := time.Date(2026, 1, 2, 3, 4, 0, 0, time.UTC)
	orig := &mail.Parsed{
		From:    "李明 <mli@tendyron.com>",
		To:      []string{"张红博 <hbzhang@tendyron.com>", "bob@example.com"},
		Cc:      []string{"carol@example.com"},
		Subject: "需求变更 <v2>",
		Date:    d,
		HTML:    "<p>原邮件内容</p><script>x</script>",
	}
	q := mail.QuoteHTMLInStyle(orig, "zh-Hans", mail.QuoteStyleOutlook)
	assert.NotContains(t, q, "<blockquote")
	assert.NotContains(t, q, "[mailto:")
	assert.Contains(t, q, `<div style="border-top: 1.0pt solid #e1e1e1; padding-top: 8px; margin-top: 12px"><p style="margin: 0">`)
	assert.Contains(t, q, `<b>发件人:</b> 李明 &lt;<a href="mailto:mli@tendyron.com">mli@tendyron.com</a>&gt;`)
	assert.Contains(t, q, "<b>发送时间:</b> 2026/01/02 03:04")
	assert.Contains(t, q, `<b>收件人:</b> 张红博 &lt;<a href="mailto:hbzhang@tendyron.com">hbzhang@tendyron.com</a>&gt;; <a href="mailto:bob@example.com">bob@example.com</a>`)
	assert.Contains(t, q, `<b>抄送:</b> <a href="mailto:carol@example.com">carol@example.com</a>`)
	assert.Contains(t, q, "<b>主题:</b> 需求变更 &lt;v2&gt;")
	assert.Contains(t, q, `<div style="margin-top: 12px"><p>原邮件内容</p></div>`)
	assert.NotContains(t, q, "script")

	// Draft and reader sanitizers preserve the Outlook divider rule, compact margins, and mailto links.
	draftSafe := mail.SanitizeDraft(q, nil)
	assert.Contains(t, draftSafe, "border-top: 1.0pt solid #e1e1e1")
	assert.Contains(t, draftSafe, "margin: 0")
	assert.Contains(t, draftSafe, `href="mailto:mli@tendyron.com"`)
	readSafe, _, _ := mail.Sanitize(q, nil, false)
	assert.Contains(t, readSafe, "border-top: 1.0pt solid #e1e1e1")
	assert.Contains(t, readSafe, "margin: 0")
	assert.Contains(t, readSafe, `data-href="mailto:mli@tendyron.com"`)

	// Unquoted display name with dot still links the address; unsafe/non-address values stay plain text.
	edge := mail.QuoteHTMLInStyle(&mail.Parsed{
		From: "A. B. <ab@x.com>",
		To:   []string{"Undisclosed", "bad?x=1@x.com"},
		Date: d,
		Text: "hi",
	}, "en", mail.QuoteStyleOutlook)
	assert.Contains(t, edge, `<b>From:</b> A. B. &lt;<a href="mailto:ab@x.com">ab@x.com</a>&gt;`)
	assert.Contains(t, edge, "<b>To:</b> Undisclosed; bad?x=1@x.com")
	assert.NotContains(t, edge, "mailto:bad")

	// Empty Cc is omitted; localized labels adapt to language.
	noCc := &mail.Parsed{From: "a@x.com", To: []string{"b@x.com"}, Subject: "Hi", Date: d, Text: "hello"}
	zhHant := mail.QuoteHTMLInStyle(noCc, "zh-Hant", mail.QuoteStyleOutlook)
	assert.Contains(t, zhHant, `<b>寄件者:</b> <a href="mailto:a@x.com">a@x.com</a>`)
	assert.Contains(t, zhHant, "<b>傳送時間:</b> 2026/01/02 03:04")
	assert.NotContains(t, zhHant, "副本:")
	en := mail.QuoteHTMLInStyle(noCc, "en", mail.QuoteStyleOutlook)
	assert.Contains(t, en, `<b>From:</b> <a href="mailto:a@x.com">a@x.com</a>`)
	assert.Contains(t, en, "<b>Sent:</b> 1/02/2026 03:04")
	assert.Contains(t, en, "<b>Subject:</b> Hi")
	assert.NotContains(t, en, "<b>Cc:</b>")
	de := mail.QuoteHTMLInStyle(noCc, "de", mail.QuoteStyleOutlook)
	assert.Contains(t, de, `<b>Von:</b> <a href="mailto:a@x.com">a@x.com</a>`)
	assert.Contains(t, de, "<b>Betreff:</b> Hi")
	ja := mail.QuoteHTMLInStyle(noCc, "ja", mail.QuoteStyleOutlook)
	assert.Contains(t, ja, `<b>差出人:</b> <a href="mailto:a@x.com">a@x.com</a>`)
	assert.Contains(t, ja, "<b>件名:</b> Hi")

	// QuoteHTMLWithStyle carries inline images with Outlook header formatting.
	const png1B64 = "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAIAAACQkWg2AAAAFklEQVR4nGPQKLpFEmIY1TCqYfhqAAASZ3QQWUKpQAAAAABJRU5ErkJggg=="
	png1, err := base64.StdEncoding.DecodeString(png1B64)
	require.NoError(t, err)
	qWith, imgs := mail.QuoteHTMLWithStyle(&mail.Parsed{
		From:    "Alice <alice@example.com>",
		Subject: "Pic",
		Date:    d,
		HTML:    `<p>Body</p><img src="cid:logo@example">`,
	}, "en", mail.QuoteStyleOutlook, map[string]mail.Attachment{
		"logo@example": {ContentID: "logo@example", ContentType: "image/png", Data: png1, Inline: true},
	})
	assert.Contains(t, qWith, `<b>From:</b> Alice &lt;<a href="mailto:alice@example.com">alice@example.com</a>&gt;`)
	require.Len(t, imgs, 1)
	assert.Contains(t, qWith, `src="cid:`+imgs[0].ContentID+`"`)
}

func TestQuoteHTMLWithImagesAndStyles(t *testing.T) {
	const png1B64 = "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAIAAACQkWg2AAAAFklEQVR4nGPQKLpFEmIY1TCqYfhqAAASZ3QQWUKpQAAAAABJRU5ErkJggg=="
	const png2B64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
	png1, err := base64.StdEncoding.DecodeString(png1B64)
	require.NoError(t, err)

	d := time.Date(2026, 8, 4, 14, 3, 0, 0, time.UTC)
	orig := &mail.Parsed{
		From: "Alice <alice@example.com>",
		Date: d,
		HTML: `<style>.hdr { color: #223344; font-family: '微软雅黑', sans-serif; }</style>` +
			`<p class="hdr" data-godwit="quote">Hello</p>` +
			`<img src="cid:LOGO@EXAMPLE" alt="logo">` +
			`<img src="cid:logo@example" alt="dup">` +
			`<img src="data:image/png;base64,` + png2B64 + `" alt="data">` +
			`<img src="https://evil.example/track.png" width="1" height="1">` +
			`<img src="data:image/svg+xml;base64,PHN2Zy8+">`,
	}
	inline := map[string]mail.Attachment{
		"logo@example": {ContentID: "logo@example", ContentType: "image/png", Data: png1, Inline: true},
	}
	q, imgs := mail.QuoteHTMLWith(orig, "zh-Hans", inline)
	assert.Contains(t, q, "color: #223344")
	assert.Contains(t, q, "微软雅黑")
	assert.NotContains(t, q, `data-godwit="quote"`)
	assert.NotContains(t, q, "evil.example")
	assert.NotContains(t, q, "svg+xml")
	assert.NotContains(t, q, "data:image/png")
	require.Len(t, imgs, 2)
	for _, img := range imgs {
		assert.Contains(t, q, `src="cid:`+img.ContentID+`"`)
		assert.True(t, len(img.Data) > 0)
	}
}
