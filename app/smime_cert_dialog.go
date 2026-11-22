package app

import (
	"cmp"
	"strconv"
	"strings"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/godwit-email/godwit/core"
	"github.com/godwit-email/godwit/internal/i18n"
	"github.com/godwit-email/godwit/internal/icons"
	"github.com/godwit-email/godwit/internal/kit"
	"github.com/godwit-email/godwit/internal/smime"
	"github.com/godwit-email/godwit/internal/theme"
)

type smimeCertView struct {
	smime.CertDetails
	Chain       []smime.CertChainNode
	SourceLabel string
	Verified    bool
	Trusted     bool
	StatusError string
}

type smimeEncryptView struct {
	Subject           string
	HasSignature      bool
	ContentCipher     string
	KeyEncryptionAlgo string
	RecipientCount    int
	AttachmentCount   int
	Hardware          bool
	DecryptCert       *smime.CertDetails
}

type smimeSigView struct {
	Subject       string
	Verified      bool
	Signer        string
	StatusError   string
	Format        string
	DigestAlgo    string
	SignatureAlgo string
	SigningTime   time.Time
	ClaimedFrom   string
	CryptOK       bool
	TrustOK       bool
	SenderMatched bool
	WeakKeyCompat bool
	SignerCert    *smime.CertDetails
	Chain         []smime.CertChainNode
}

func (a *App) closeSMIMEDialogs() {
	a.smimeCertOpen = false
	a.smimeEncryptOpen = false
	a.smimeSigOpen = false
}

func (a *App) openSMIMECertDialog(v smimeCertView) {
	a.closeSMIMEDialogs()
	a.smimeCert = v
	a.smimeCertOpen = true
}

func (a *App) openSMIMEEncryptDialog(v smimeEncryptView) {
	a.closeSMIMEDialogs()
	a.smimeEncrypt = v
	a.smimeEncryptOpen = true
}

func (a *App) openSMIMESigDialog(v smimeSigView) {
	a.closeSMIMEDialogs()
	a.smimeSig = v
	a.smimeSigOpen = true
}

func smimeSourceLabel(src string) string {
	switch src {
	case core.CertSourceCardDAV:
		return i18n.T("smime.source.carddav")
	case core.CertSourceMailCard:
		return i18n.T("smime.source.mail_card")
	case core.CertSourceMailSig:
		return i18n.T("smime.source.mail_sig")
	case core.CertSourceSystem:
		return i18n.T("smime.source.system")
	case core.CertSourceImported:
		return i18n.T("smime.source.imported")
	default:
		return src
	}
}

func smimeChainFromCore(nodes []core.SMIMECertChainNode) []smime.CertChainNode {
	if len(nodes) == 0 {
		return nil
	}
	out := make([]smime.CertChainNode, len(nodes))
	for i, n := range nodes {
		out[i] = smime.CertChainNode{
			Subject:       n.Subject,
			Issuer:        n.Issuer,
			PublicKeyAlgo: n.PublicKeyAlgo,
			NotBefore:     n.NotBefore,
			NotAfter:      n.NotAfter,
			SHA256:        n.SHA256,
			Role:          n.Role,
			SelfSigned:    n.SelfSigned,
		}
	}
	return out
}

func certChainRoleLabel(role string) string {
	switch role {
	case "root":
		return i18n.T("smime.cert.role_root")
	case "intermediate":
		return i18n.T("smime.cert.role_intermediate")
	case "leaf":
		return i18n.T("smime.cert.role_leaf")
	default:
		return role
	}
}

func certViewFromDetails(d smime.CertDetails, verified, trusted bool, source, statusErr string, chain []smime.CertChainNode) smimeCertView {
	return smimeCertView{
		CertDetails: d,
		Chain:       chain,
		SourceLabel: smimeSourceLabel(source),
		Verified:    verified,
		Trusted:     trusted,
		StatusError: statusErr,
	}
}

func certViewFromCoreCert(c core.SMIMECertificate) smimeCertView {
	return certViewFromDetails(smime.CertDetails{
		Subject:       c.Subject,
		SubjectDN:     c.SubjectDN,
		Issuer:        c.Issuer,
		IssuerDN:      c.IssuerDN,
		Emails:        c.Emails,
		SerialNumber:  c.SerialNumber,
		NotBefore:     c.NotBefore,
		NotAfter:      c.NotAfter,
		PublicKeyAlgo: c.PublicKeyAlgo,
		SignatureAlgo: c.SignatureAlgo,
		KeyUsages:     c.KeyUsages,
		ExtKeyUsages:  c.ExtKeyUsages,
		SHA256:        c.SHA256,
		SHA1:          c.SHA1,
	}, false, c.Trusted, c.Source, c.TrustErr, smimeChainFromCore(c.Chain))
}

func certViewFromIdentity(id core.SMIMEIdentity) smimeCertView {
	src := i18n.T("smime.cert.software")
	if id.Hardware {
		src = i18n.T("smime.cert.hardware")
	}
	return smimeCertView{
		CertDetails: smime.CertDetails{
			Subject:       id.Subject,
			SubjectDN:     id.SubjectDN,
			Issuer:        id.Issuer,
			IssuerDN:      id.IssuerDN,
			Emails:        id.Emails,
			SerialNumber:  id.SerialNumber,
			NotBefore:     id.NotBefore,
			NotAfter:      id.NotAfter,
			PublicKeyAlgo: id.PublicKeyAlgo,
			SignatureAlgo: id.SignatureAlgo,
			KeyUsages:     id.KeyUsages,
			ExtKeyUsages:  id.ExtKeyUsages,
			SHA256:        id.SHA256,
			SHA1:          id.SHA1,
		},
		Chain:       smimeChainFromCore(id.Chain),
		SourceLabel: src,
		Trusted:     id.CanSign || id.CanEncrypt,
	}
}

func formatFingerprintHex(hexStr string) string {
	clean := strings.ToUpper(strings.TrimSpace(hexStr))
	if clean == "" {
		return ""
	}
	if strings.Contains(clean, ":") {
		return clean
	}
	var sb strings.Builder
	for i := 0; i+1 < len(clean); i += 2 {
		if sb.Len() > 0 {
			sb.WriteByte(':')
		}
		sb.WriteString(clean[i : i+2])
	}
	if len(clean)%2 != 0 {
		if sb.Len() > 0 {
			sb.WriteByte(':')
		}
		sb.WriteByte(clean[len(clean)-1])
	}
	return sb.String()
}

func formatCertUsages(keyUsages, extKeyUsages []string) string {
	parts := make([]string, 0, len(keyUsages)+len(extKeyUsages))
	for _, u := range keyUsages {
		k := "smime.usage." + u
		if v := i18n.T(k); v != k {
			parts = append(parts, v)
		} else {
			parts = append(parts, u)
		}
	}
	for _, u := range extKeyUsages {
		k := "smime.usage." + u
		if v := i18n.T(k); v != k {
			parts = append(parts, v)
		} else {
			parts = append(parts, u)
		}
	}
	return strings.Join(parts, " · ")
}

func certDetailRow(c *ui.Context, label, val, sub string, mono bool) {
	if val == "" {
		return
	}
	t, th := theme.Of(c), c.Theme()
	ui.Column(c).FillWidth().Gap(th.Space(0.5)).Children(func() {
		kit.Text(c, label, t.Text.Xs).TextColor(t.Muted)
		txt := kit.Text(c, val, t.Text.Xs).FontWeight(500).Selectable()
		if mono {
			txt.Font(theme.Mono)
		}
		if sub != "" && sub != val {
			kit.Text(c, sub, t.Text.Xs).TextColor(t.Muted).Selectable()
		}
	})
}

func formatCertValidity(notBefore, notAfter time.Time) string {
	if !notBefore.IsZero() && !notAfter.IsZero() {
		return notBefore.Local().Format("2006-01-02 15:04") + " – " + notAfter.Local().Format("2006-01-02 15:04")
	}
	if !notAfter.IsZero() {
		return notAfter.Local().Format("2006-01-02 15:04")
	}
	return ""
}

func (a *App) smimeCertDialog(c *ui.Context) {
	if !a.smimeCertOpen {
		return
	}
	v := a.smimeCert
	t, th := theme.Of(c), c.Theme()
	firstEmail := ""
	if len(v.Emails) > 0 {
		firstEmail = v.Emails[0]
	}
	desc := cmp.Or(v.Subject, firstEmail)

	kit.Dialog(c, &a.smimeCertOpen, i18n.T("smime.cert.detail_title"), kit.DialogOpts{
		Size:  kit.DialogMd,
		Desc:  desc,
		Close: i18n.T("common.close"),
	}, func() {
		ui.Column(c).FillWidth().Gap(th.Space(3)).Children(func() {
			tone, icon, statusColor, statusKey := kit.ToneWarning, "triangle-alert", t.WarningText, "smime.cert.status_untrusted"
			if v.Verified {
				tone, icon, statusColor, statusKey = kit.ToneSuccess, "circle-check", t.SuccessText, "smime.cert.status_verified"
			} else if v.Trusted {
				tone, icon, statusColor, statusKey = kit.ToneSuccess, "circle-check", t.SuccessText, "smime.cert.status_trusted"
			}
			expired := !v.NotAfter.IsZero() && time.Now().After(v.NotAfter)

			kit.Block(c, ui.Column(c), tone).FillWidth().Padding(th.Space(2.5), th.Space(3)).Gap(th.Space(1)).Children(func() {
				ui.Row(c).FillWidth().Gap(th.Space(2)).AlignItems(ui.Center).Children(func() {
					ui.Icon(c, icons.Get(icon)).Size(theme.IconSm, theme.IconSm).TextColor(statusColor)
					kit.Text(c, i18n.T(statusKey), t.Text.Sm).FontWeight(500).TextColor(statusColor).Grow(1).Shrink(1)
					if expired {
						kit.BadgeWith(c, i18n.T("smime.cert.status_expired"), kit.BadgeOpts{Tone: kit.BadgeDanger})
					}
				})
				if (v.Verified || v.Trusted) && len(v.Chain) > 1 && v.Chain[0].Role == "root" {
					kit.Text(c, i18n.Tf("smime.cert.trusted_via_root", cmp.Or(v.Chain[0].Subject, v.Chain[0].Issuer)), t.Text.Xs).TextColor(statusColor).Selectable()
				}
				if v.StatusError != "" && !v.Verified && !v.Trusted {
					kit.Text(c, v.StatusError, t.Text.Xs).TextColor(statusColor).Selectable()
				}
			})

			kit.Block(c, ui.Column(c), kit.ToneOutline).FillWidth().Padding(th.Space(2.5), th.Space(3)).Gap(th.Space(2.5)).Children(func() {
				certDetailRow(c, i18n.T("smime.cert.field_subject"), cmp.Or(v.Subject, firstEmail), v.SubjectDN, false)
				if len(v.Emails) > 0 {
					certDetailRow(c, i18n.T("smime.cert.field_email"), strings.Join(v.Emails, ", "), "", false)
				}
				certDetailRow(c, i18n.T("smime.cert.field_issuer"), v.Issuer, v.IssuerDN, false)
				certDetailRow(c, i18n.T("smime.cert.field_validity"), formatCertValidity(v.NotBefore, v.NotAfter), "", false)
				certDetailRow(c, i18n.T("smime.cert.field_source"), v.SourceLabel, "", false)
			})

			if len(v.Chain) > 1 {
				kit.Block(c, ui.Column(c), kit.ToneOutline).FillWidth().Padding(th.Space(2.5), th.Space(3)).Gap(th.Space(2)).Children(func() {
					kit.Text(c, i18n.T("smime.cert.chain"), t.Text.Xs).TextColor(t.Muted)
					for i, node := range v.Chain {
						indent := float32(i) * th.Space(3)
						ui.Column(c).FillWidth().Padding(0, 0, 0, indent).Gap(th.Space(0.5)).Children(func() {
							ui.Row(c).FillWidth().Wrap().Gap(th.Space(1.5)).AlignItems(ui.Center).Children(func() {
								prefix := ""
								if i > 0 {
									prefix = "└─ "
								}
								name := cmp.Or(node.Subject, node.Issuer)
								kit.Text(c, prefix+name, t.Text.Xs).FontWeight(500).Selectable()
								kit.BadgeWith(c, certChainRoleLabel(node.Role), kit.BadgeOpts{Tone: kit.BadgeOutline, Muted: true})
								if i == 0 && node.Role == "root" && (v.Verified || v.Trusted) {
									kit.BadgeWith(c, i18n.T("smime.cert.root_trusted"), kit.BadgeOpts{Tone: kit.BadgeSuccess})
								}
							})
							if node.PublicKeyAlgo != "" {
								subPad := float32(0)
								if i > 0 {
									subPad = th.Space(3)
								}
								kit.Text(c, node.PublicKeyAlgo, t.Text.Xs).TextColor(t.Muted).Padding(0, 0, 0, subPad)
							}
						})
					}
				})
			}

			sha256Colon := formatFingerprintHex(v.SHA256)
			sha1Colon := formatFingerprintHex(v.SHA1)
			usages := formatCertUsages(v.KeyUsages, v.ExtKeyUsages)
			if v.SerialNumber != "" || v.PublicKeyAlgo != "" || v.SignatureAlgo != "" || usages != "" || sha256Colon != "" || sha1Colon != "" {
				kit.Block(c, ui.Column(c), kit.ToneOutline).FillWidth().Padding(th.Space(2.5), th.Space(3)).Gap(th.Space(2.5)).Children(func() {
					certDetailRow(c, i18n.T("smime.cert.field_serial"), v.SerialNumber, "", true)
					certDetailRow(c, i18n.T("smime.cert.field_pubkey"), v.PublicKeyAlgo, "", false)
					certDetailRow(c, i18n.T("smime.cert.field_sigalg"), v.SignatureAlgo, "", false)
					certDetailRow(c, i18n.T("smime.cert.field_usage"), usages, "", false)
					if sha256Colon != "" {
						ui.Column(c).FillWidth().Gap(th.Space(0.5)).Children(func() {
							ui.Row(c).FillWidth().AlignItems(ui.Center).Children(func() {
								kit.Text(c, i18n.T("smime.cert.field_sha256"), t.Text.Xs).TextColor(t.Muted).Grow(1)
								if kit.Button(c, i18n.T("smime.cert.copy_fp"), kit.ButtonOpts{Variant: kit.Ghost, Size: kit.SizeXs, Icon: "copy"}).Clicked() {
									c.WriteClipboard(sha256Colon)
									a.toastAs(kit.ToastSuccess, i18n.T("smime.cert.copied"))
								}
							})
							kit.Text(c, sha256Colon, t.Text.Xs).Font(theme.Mono).Selectable()
						})
					}
					certDetailRow(c, i18n.T("smime.cert.field_sha1"), sha1Colon, "", true)
				})
			}
		})
	}, func() {
		if kit.Button(c, i18n.T("common.close"), kit.ButtonOpts{}).AutoFocus().Clicked() {
			a.smimeCertOpen = false
		}
	})
}

func (a *App) smimeEncryptDialog(c *ui.Context) {
	if !a.smimeEncryptOpen {
		return
	}
	v := a.smimeEncrypt
	t, th := theme.Of(c), c.Theme()

	kit.Dialog(c, &a.smimeEncryptOpen, i18n.T("smime.encrypt_detail.title"), kit.DialogOpts{
		Size:  kit.DialogMd,
		Desc:  v.Subject,
		Close: i18n.T("common.close"),
	}, func() {
		ui.Column(c).FillWidth().Gap(th.Space(3)).Children(func() {
			subKey := "smime.encrypt_detail.no_sig"
			structKey := "smime.encrypt_detail.structure_enc_only"
			if v.HasSignature {
				subKey = "smime.encrypt_detail.with_sig"
				structKey = "smime.encrypt_detail.structure_signed_enc"
			}
			kit.Block(c, ui.Column(c), kit.ToneSuccess).FillWidth().Padding(th.Space(2.5), th.Space(3)).Gap(th.Space(1)).Children(func() {
				ui.Row(c).FillWidth().Gap(th.Space(2)).AlignItems(ui.Center).Children(func() {
					ui.Icon(c, icons.Get("lock")).Size(theme.IconSm, theme.IconSm).TextColor(t.SuccessText)
					kit.Text(c, i18n.T("smime.encrypt_detail.status_ok"), t.Text.Sm).FontWeight(500).TextColor(t.SuccessText).Grow(1).Shrink(1)
				})
				kit.Text(c, i18n.T(subKey), t.Text.Xs).TextColor(t.SuccessText)
			})

			methodLabel := i18n.T("smime.encrypt_detail.method_local")
			if v.Hardware {
				methodLabel = i18n.T("smime.encrypt_detail.method_hardware")
			} else if v.DecryptCert != nil {
				methodLabel = i18n.T("smime.encrypt_detail.method_software")
			}

			kit.Block(c, ui.Column(c), kit.ToneOutline).FillWidth().Padding(th.Space(2.5), th.Space(3)).Gap(th.Space(2.5)).Children(func() {
				certDetailRow(c, i18n.T("smime.encrypt_detail.method"), methodLabel, "", false)
				certDetailRow(c, i18n.T("smime.encrypt_detail.structure"), i18n.T(structKey), "", false)
				certDetailRow(c, i18n.T("smime.encrypt_detail.cipher"), v.ContentCipher, "", true)
				certDetailRow(c, i18n.T("smime.encrypt_detail.key_algo"), v.KeyEncryptionAlgo, "", false)
				if v.RecipientCount > 0 {
					certDetailRow(c, i18n.T("smime.encrypt_detail.recipients"), i18n.Tf("smime.encrypt_detail.recipients_count", strconv.Itoa(v.RecipientCount)), "", false)
				}
				if v.AttachmentCount > 0 {
					certDetailRow(c, i18n.T("smime.encrypt_detail.attachments"), i18n.Tf("smime.encrypt_detail.attachments_count", strconv.Itoa(v.AttachmentCount)), "", false)
				}
			})

			if v.DecryptCert != nil {
				dc := *v.DecryptCert
				src := i18n.T("smime.cert.software")
				if v.Hardware {
					src = i18n.T("smime.cert.hardware")
				}
				kit.Block(c, ui.Column(c), kit.ToneOutline).FillWidth().Padding(th.Space(2.5), th.Space(3)).Gap(th.Space(2)).Children(func() {
					kit.Text(c, i18n.T("smime.encrypt_detail.cert_heading"), t.Text.Xs).TextColor(t.Muted)
					firstEmail := ""
					if len(dc.Emails) > 0 {
						firstEmail = dc.Emails[0]
					}
					certDetailRow(c, i18n.T("smime.cert.field_subject"), cmp.Or(dc.Subject, firstEmail), "", false)
					if len(dc.Emails) > 0 {
						certDetailRow(c, i18n.T("smime.cert.field_email"), strings.Join(dc.Emails, ", "), "", false)
					}
					certDetailRow(c, i18n.T("smime.cert.field_issuer"), dc.Issuer, "", false)
					certDetailRow(c, i18n.T("smime.cert.field_validity"), formatCertValidity(dc.NotBefore, dc.NotAfter), "", false)
					ui.Row(c).Children(func() {
						if kit.Button(c, i18n.T("smime.encrypt_detail.view_cert"), kit.ButtonOpts{Variant: kit.Outline, Size: kit.SizeSm}).Clicked() {
							a.openSMIMECertDialog(certViewFromDetails(dc, false, true, src, "", nil))
						}
					})
				})
			}
		})
	}, func() {
		if kit.Button(c, i18n.T("common.close"), kit.ButtonOpts{}).AutoFocus().Clicked() {
			a.smimeEncryptOpen = false
		}
	})
}

func sigFormatLabel(format string) string {
	switch format {
	case "detached":
		return i18n.T("smime.sig_detail.format_detached")
	case "opaque":
		return i18n.T("smime.sig_detail.format_opaque")
	case "enveloped":
		return i18n.T("smime.sig_detail.format_enveloped")
	default:
		return format
	}
}

func (a *App) smimeSigDialog(c *ui.Context) {
	if !a.smimeSigOpen {
		return
	}
	v := a.smimeSig
	t, th := theme.Of(c), c.Theme()
	desc := cmp.Or(v.Signer, v.ClaimedFrom, v.Subject)

	kit.Dialog(c, &a.smimeSigOpen, i18n.T("smime.sig_detail.title"), kit.DialogOpts{
		Size:  kit.DialogMd,
		Desc:  desc,
		Close: i18n.T("common.close"),
	}, func() {
		ui.Column(c).FillWidth().Gap(th.Space(3)).Children(func() {
			tone, icon, statusColor, statusKey := kit.ToneWarning, "triangle-alert", t.WarningText, "smime.sig_detail.status_fail"
			if v.Verified {
				tone, icon, statusColor, statusKey = kit.ToneSuccess, "circle-check", t.SuccessText, "smime.sig_detail.status_ok"
			}
			kit.Block(c, ui.Column(c), tone).FillWidth().Padding(th.Space(2.5), th.Space(3)).Gap(th.Space(1)).Children(func() {
				ui.Row(c).FillWidth().Gap(th.Space(2)).AlignItems(ui.Center).Children(func() {
					ui.Icon(c, icons.Get(icon)).Size(theme.IconSm, theme.IconSm).TextColor(statusColor)
					kit.Text(c, i18n.T(statusKey), t.Text.Sm).FontWeight(500).TextColor(statusColor).Grow(1).Shrink(1)
				})
				if v.Verified && len(v.Chain) > 1 && v.Chain[0].Role == "root" {
					kit.Text(c, i18n.Tf("smime.cert.trusted_via_root", cmp.Or(v.Chain[0].Subject, v.Chain[0].Issuer)), t.Text.Xs).TextColor(statusColor).Selectable()
				}
				if !v.Verified && v.StatusError != "" {
					kit.Text(c, v.StatusError, t.Text.Xs).TextColor(statusColor).Selectable()
				}
			})

			checkRow := func(title string, badgeTone kit.BadgeTone, badgeKey, detail string) {
				ui.Column(c).FillWidth().Gap(th.Space(0.5)).Children(func() {
					ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(th.Space(2)).Children(func() {
						kit.Text(c, title, t.Text.Xs).FontWeight(500).Grow(1).Shrink(1)
						kit.BadgeWith(c, i18n.T(badgeKey), kit.BadgeOpts{Tone: badgeTone})
					})
					kit.Text(c, detail, t.Text.Xs).TextColor(t.Muted).Selectable()
				})
			}

			kit.Block(c, ui.Column(c), kit.ToneOutline).FillWidth().Padding(th.Space(2.5), th.Space(3)).Gap(th.Space(2)).Children(func() {
				kit.Text(c, i18n.T("smime.sig_detail.checks"), t.Text.Xs).TextColor(t.Muted)
				if v.CryptOK {
					checkRow(i18n.T("smime.sig_detail.check_integrity"), kit.BadgeSuccess, "smime.sig_detail.badge_pass", i18n.T("smime.sig_detail.check_integrity_ok"))
				} else {
					checkRow(i18n.T("smime.sig_detail.check_integrity"), kit.BadgeDanger, "smime.sig_detail.badge_fail", i18n.T("smime.sig_detail.check_integrity_fail"))
				}

				switch {
				case v.ClaimedFrom == "":
					checkRow(i18n.T("smime.sig_detail.check_sender"), kit.BadgeOutline, "smime.sig_detail.badge_unverified", i18n.T("smime.sig_detail.check_sender_unknown"))
				case v.SenderMatched:
					checkRow(i18n.T("smime.sig_detail.check_sender"), kit.BadgeSuccess, "smime.sig_detail.badge_pass", i18n.Tf("smime.sig_detail.check_sender_ok", v.ClaimedFrom))
				case !v.CryptOK && v.SignerCert == nil:
					checkRow(i18n.T("smime.sig_detail.check_sender"), kit.BadgeOutline, "smime.sig_detail.badge_unverified", i18n.T("smime.sig_detail.check_sender_unknown"))
				default:
					checkRow(i18n.T("smime.sig_detail.check_sender"), kit.BadgeDanger, "smime.sig_detail.badge_fail", i18n.Tf("smime.sig_detail.check_sender_fail", v.ClaimedFrom))
				}

				switch {
				case v.TrustOK:
					checkRow(i18n.T("smime.sig_detail.check_trust"), kit.BadgeSuccess, "smime.sig_detail.badge_pass", i18n.T("smime.sig_detail.check_trust_ok"))
				case !v.CryptOK && v.SignerCert == nil:
					checkRow(i18n.T("smime.sig_detail.check_trust"), kit.BadgeOutline, "smime.sig_detail.badge_unverified", i18n.T("smime.sig_detail.check_trust_fail"))
				default:
					checkRow(i18n.T("smime.sig_detail.check_trust"), kit.BadgeDanger, "smime.sig_detail.badge_fail", i18n.T("smime.sig_detail.check_trust_fail"))
				}

				policyText := i18n.T("smime.sig_detail.policy_standard")
				if v.WeakKeyCompat {
					policyText = i18n.T("smime.sig_detail.policy_weak_compat")
				}
				certDetailRow(c, i18n.T("smime.sig_detail.policy"), policyText, "", false)
			})

			sigTimeStr := ""
			if !v.SigningTime.IsZero() {
				sigTimeStr = v.SigningTime.Local().Format("2006-01-02 15:04:05")
			}
			formatStr := sigFormatLabel(v.Format)
			if v.Signer != "" || formatStr != "" || v.DigestAlgo != "" || v.SignatureAlgo != "" || sigTimeStr != "" {
				kit.Block(c, ui.Column(c), kit.ToneOutline).FillWidth().Padding(th.Space(2.5), th.Space(3)).Gap(th.Space(2.5)).Children(func() {
					certDetailRow(c, i18n.T("smime.sig_detail.field_signer"), v.Signer, "", false)
					certDetailRow(c, i18n.T("smime.sig_detail.field_format"), formatStr, "", false)
					certDetailRow(c, i18n.T("smime.sig_detail.field_digest"), v.DigestAlgo, "", true)
					certDetailRow(c, i18n.T("smime.sig_detail.field_sigalg"), v.SignatureAlgo, "", true)
					certDetailRow(c, i18n.T("smime.sig_detail.field_time"), sigTimeStr, "", false)
				})
			}
		})
	}, func() {
		if v.SignerCert != nil {
			cert := *v.SignerCert
			if kit.Button(c, i18n.T("smime.cert.view"), kit.ButtonOpts{Variant: kit.Outline}).Clicked() {
				a.openSMIMECertDialog(certViewFromDetails(cert, v.Verified, v.Verified, "", v.StatusError, v.Chain))
			}
		}
		if kit.Button(c, i18n.T("common.close"), kit.ButtonOpts{}).AutoFocus().Clicked() {
			a.smimeSigOpen = false
		}
	})
}
