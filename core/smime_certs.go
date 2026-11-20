package core

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net/mail"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/egoist/mygo/plugins/sqlite"
	"github.com/emmansun/gmsm/smx509"
	gomail "github.com/godwit-email/godwit/core/mail"
	"github.com/godwit-email/godwit/core/store"
	"github.com/godwit-email/godwit/internal/carddav"
	"github.com/godwit-email/godwit/internal/smime"
)

// Certificate sources stored in smime_certificates or resolved live from the OS.
const (
	CertSourceCardDAV  = "carddav"
	CertSourceMailCard = "mail_card"
	CertSourceMailSig  = "mail_sig"
	CertSourceSystem   = "system"
	CertSourceImported = "imported"
)

// SMIMEIdentity describes one personal S/MIME certificate from the local OS store or security key.
type SMIMEIdentity struct {
	SHA256        string
	Subject       string
	SubjectDN     string
	Issuer        string
	IssuerDN      string
	Emails        []string
	SerialNumber  string
	NotBefore     time.Time
	NotAfter      time.Time
	PublicKeyAlgo string
	SignatureAlgo string
	KeyUsages     []string
	ExtKeyUsages  []string
	SHA1          string
	Hardware      bool
	CanSign       bool
	CanEncrypt    bool
}

// SMIMECertificate describes one recipient S/MIME public certificate resolved from standard sources.
type SMIMECertificate struct {
	SHA256        string
	Address       string
	Source        string
	Subject       string
	SubjectDN     string
	Issuer        string
	IssuerDN      string
	Emails        []string
	SerialNumber  string
	NotBefore     time.Time
	NotAfter      time.Time
	PublicKeyAlgo string
	SignatureAlgo string
	KeyUsages     []string
	ExtKeyUsages  []string
	SHA1          string
	Trusted       bool
	TrustErr      string
	Selected      bool
	DER           []byte `json:"-"`
}

// RecipientSMIMEStatus summarizes available and selected certificates for a single recipient address.
type RecipientSMIMEStatus struct {
	Address   string
	Ready     bool
	Selected  string
	Error     string
	ErrorCode string
	Certs     []SMIMECertificate
}

// DraftSMIMEStatus summarizes S/MIME settings, own identity readiness, and recipient readiness for a draft.
type DraftSMIMEStatus struct {
	DraftID          int64
	AccountID        int64
	From             string
	Supported        bool
	Sign             bool
	Encrypt          bool
	OwnCertSHA       string
	OwnReady         bool
	OwnError         string
	OwnErrorCode     string
	OwnCerts         []SMIMEIdentity
	Recipients       []RecipientSMIMEStatus
	CanSendSigned    bool
	CanSendEncrypted bool
}

type draftSMIMEPref struct {
	Sign        *bool             `json:"sign,omitempty"`
	Encrypt     *bool             `json:"encrypt,omitempty"`
	PinnedCerts map[string]string `json:"pinned_certs,omitempty"`
}

func (s *Service) ensureSMIMETables(ctx context.Context) error {
	s.smimeTablesOnce.Do(func() {
		_, err := s.db.Transaction(ctx, []sqlite.Statement{
			{SQL: `CREATE TABLE IF NOT EXISTS smime_certificates (
				sha256     TEXT NOT NULL,
				addr_key   TEXT NOT NULL,
				source     TEXT NOT NULL,
				subject    TEXT NOT NULL,
				issuer     TEXT NOT NULL,
				not_before INTEGER NOT NULL,
				not_after  INTEGER NOT NULL,
				der        BLOB NOT NULL,
				added_at   INTEGER NOT NULL,
				PRIMARY KEY (sha256, addr_key)
			)`},
			{SQL: `CREATE INDEX IF NOT EXISTS idx_smime_certs_addr ON smime_certificates(addr_key, not_before DESC)`},
			{SQL: `CREATE TABLE IF NOT EXISTS smime_scanned_parts (
				part_key   TEXT PRIMARY KEY,
				scanned_at INTEGER NOT NULL
			)`},
		})
		s.smimeTablesErr = err
	})
	return s.smimeTablesErr
}

func normalizeCertAddr(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if p, err := mail.ParseAddress(raw); err == nil && p.Address != "" {
		return strings.ToLower(strings.TrimSpace(p.Address))
	}
	if k := gomail.AddrKey(raw); k != "" {
		return k
	}
	return strings.ToLower(raw)
}

func draftSMIMEKey(draftID int64) string {
	return "smime.draft." + strconv.FormatInt(draftID, 10)
}

func recipientPrefKey(addr string) string {
	return "smime.rcpt." + normalizeCertAddr(addr)
}

func certIssuerName(cert *smx509.Certificate) string {
	return smime.InspectCertificate(cert).Issuer
}

func buildSMIMECertificate(sha, addr, source string, cert *smx509.Certificate, trusted bool, trustErr string, selected bool) SMIMECertificate {
	meta := smime.InspectCertificate(cert)
	return SMIMECertificate{
		SHA256:        sha,
		Address:       addr,
		Source:        source,
		Subject:       meta.Subject,
		SubjectDN:     meta.SubjectDN,
		Issuer:        meta.Issuer,
		IssuerDN:      meta.IssuerDN,
		Emails:        meta.Emails,
		SerialNumber:  meta.SerialNumber,
		NotBefore:     meta.NotBefore,
		NotAfter:      meta.NotAfter,
		PublicKeyAlgo: meta.PublicKeyAlgo,
		SignatureAlgo: meta.SignatureAlgo,
		KeyUsages:     meta.KeyUsages,
		ExtKeyUsages:  meta.ExtKeyUsages,
		SHA1:          meta.SHA1,
		Trusted:       trusted,
		TrustErr:      trustErr,
		Selected:      selected,
		DER:           slices.Clone(cert.Raw),
	}
}

func upsertSMIMECertStmt(addrKey, source string, cert *smx509.Certificate, now int64) sqlite.Statement {
	sha := smime.CertSHA256(cert.Raw)
	// Explicit manual import or direct signer verification supersedes passive attachment discovery if duplicated.
	return sqlite.Statement{
		SQL: `INSERT INTO smime_certificates (sha256, addr_key, source, subject, issuer, not_before, not_after, der, added_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(sha256, addr_key) DO UPDATE SET
				source = CASE
					WHEN excluded.source = 'imported' THEN 'imported'
					WHEN smime_certificates.source = 'imported' THEN smime_certificates.source
					ELSE excluded.source
				END,
				subject = excluded.subject,
				issuer = excluded.issuer,
				not_before = excluded.not_before,
				not_after = excluded.not_after,
				der = excluded.der`,
		Args: []any{
			sha,
			normalizeCertAddr(addrKey),
			source,
			smime.CertDisplaySubject(cert),
			certIssuerName(cert),
			cert.NotBefore.Unix(),
			cert.NotAfter.Unix(),
			cert.Raw,
			now,
		},
	}
}

func extractCertsFromVCard(raw string) ([]*smx509.Certificate, []string) {
	pc := carddav.ParseVCard(raw)
	var emails []string
	seenEmail := map[string]bool{}
	for _, em := range pc.Emails {
		if k := normalizeCertAddr(em.Address); k != "" && !seenEmail[k] {
			seenEmail[k] = true
			emails = append(emails, k)
		}
	}
	var certs []*smx509.Certificate
	for _, der := range pc.Certificates {
		if c, err := smime.ParseCertificate(der); err == nil {
			certs = append(certs, c)
		}
	}
	return certs, emails
}

type parsedMailCert struct {
	addrKey string
	cert    *smx509.Certificate
}

func extractMailAttachmentCerts(filename, contentType, fromHeader string, data []byte) []parsedMailCert {
	if len(data) == 0 || len(data) > 1<<20 {
		return nil
	}
	ext := strings.ToLower(filepath.Ext(strings.TrimSpace(filename)))
	ct := strings.ToLower(strings.TrimSpace(contentType))

	var certs []*smx509.Certificate
	var vcardEmails []string
	isVCard := ext == ".vcf" || ct == "text/vcard" || ct == "text/x-vcard" || strings.Contains(string(data), "BEGIN:VCARD")
	if isVCard {
		certs, vcardEmails = extractCertsFromVCard(string(data))
	} else {
		certs, _ = smime.ParseCertificateBundle(data)
	}
	if len(certs) == 0 {
		return nil
	}

	fromAddr := normalizeCertAddr(fromHeader)
	isSig := ext == ".p7s" || ct == "application/pkcs7-signature" || ct == "application/x-pkcs7-signature"

	var out []parsedMailCert
	seen := map[string]bool{}
	add := func(addr string, c *smx509.Certificate) {
		addr = normalizeCertAddr(addr)
		if addr == "" || !smime.MatchesMailbox(c, addr) {
			return
		}
		key := smime.CertSHA256(c.Raw) + "\x00" + addr
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, parsedMailCert{addrKey: addr, cert: c})
	}
	for _, c := range certs {
		if isSig && fromAddr != "" {
			add(fromAddr, c)
			continue
		}
		for _, em := range vcardEmails {
			add(em, c)
		}
		for _, em := range smime.CertEmails(c) {
			add(em, c)
		}
		if fromAddr != "" {
			add(fromAddr, c)
		}
	}
	return out
}

func carddavPreparedCerts(pc carddav.ParsedCard, emails []carddav.CardEmail) []preparedCardCert {
	if len(pc.Certificates) == 0 || len(emails) == 0 {
		return nil
	}
	var out []preparedCardCert
	seen := map[string]bool{}
	for _, der := range pc.Certificates {
		cert, err := smime.ParseCertificate(der)
		if err != nil {
			continue
		}
		for _, em := range emails {
			if em.AddrKey == "" || !smime.MatchesMailbox(cert, em.AddrKey) {
				continue
			}
			key := smime.CertSHA256(cert.Raw) + "\x00" + em.AddrKey
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, preparedCardCert{addrKey: em.AddrKey, cert: cert})
		}
	}
	return out
}

type preparedCardCert struct {
	addrKey string
	cert    *smx509.Certificate
}

const (
	smimeCertAttachmentPred = `(
		lower(a.filename) LIKE '%.vcf' OR lower(a.content_type) IN ('text/vcard','text/x-vcard')
		OR lower(a.filename) LIKE '%.cer' OR lower(a.filename) LIKE '%.crt'
		OR lower(a.filename) LIKE '%.der' OR lower(a.filename) LIKE '%.pem'
		OR lower(a.filename) LIKE '%.p7b' OR lower(a.filename) LIKE '%.p7c'
		OR lower(a.filename) LIKE '%.p7s'
		OR lower(a.content_type) IN (
			'application/pkix-cert','application/x-x509-ca-cert','application/x-x509-user-cert',
			'application/pkcs-x509','application/pkcs7-signature','application/x-pkcs7-signature'
		)
	)`
	smimeCardAttachmentPred = `(
		lower(a.filename) LIKE '%.vcf' OR lower(a.content_type) IN ('text/vcard','text/x-vcard')
		OR lower(a.filename) LIKE '%.cer' OR lower(a.filename) LIKE '%.crt'
		OR lower(a.filename) LIKE '%.der' OR lower(a.filename) LIKE '%.pem'
		OR lower(a.filename) LIKE '%.p7b' OR lower(a.filename) LIKE '%.p7c'
		OR lower(a.content_type) IN (
			'application/pkix-cert','application/x-x509-ca-cert','application/x-x509-user-cert',
			'application/pkcs-x509'
		)
	)`
)

// scanCachedMailCertificates quickly indexes already-downloaded certificate/vCard attachments
// from disk without touching IMAP connections or account locks.
func (s *Service) scanCachedMailCertificates(ctx context.Context) {
	if err := s.ensureSMIMETables(ctx); err != nil {
		return
	}
	rows, err := s.db.Query(ctx, `SELECT a.id, COALESCE(a.filename,''), COALESCE(a.content_type,''), COALESCE(m.from_addr,''), COALESCE(a.cache_path,'')
		FROM attachments a
		JOIN messages m ON m.id = a.message_id
		JOIN message_locations l ON l.message_id = a.message_id AND l.shown = 1
		JOIN folders f ON f.id = l.folder_id
		WHERE `+notPurgedCond+`
		  AND COALESCE(f.role,'') NOT IN ('trash','junk')
		  AND COALESCE(a.cache_path,'') <> ''
		  AND COALESCE(a.size, 1) <= 1048576
		  AND `+smimeCertAttachmentPred+`
		  AND NOT EXISTS (SELECT 1 FROM smime_scanned_parts p WHERE p.part_key = 'att:' || a.id)
		GROUP BY a.id
		ORDER BY a.id DESC
		LIMIT 200`)
	if err != nil || len(rows.Values) == 0 {
		return
	}
	now := s.clk().Now().Unix()
	var stmts []sqlite.Statement
	for _, r := range rows.Values {
		id := store.Int(r[0])
		filename := store.Str(r[1])
		ct := store.Str(r[2])
		from := store.Str(r[3])
		cachePath := store.Str(r[4])
		data, err := os.ReadFile(cachePath)
		if err != nil {
			continue
		}
		lowerName := strings.ToLower(filename)
		lowerCT := strings.ToLower(ct)
		src := CertSourceMailCard
		if strings.HasSuffix(lowerName, ".p7s") || lowerCT == "application/pkcs7-signature" || lowerCT == "application/x-pkcs7-signature" {
			src = CertSourceMailSig
		}
		stmts = append(stmts, sqlite.Statement{
			SQL:  `INSERT OR REPLACE INTO smime_scanned_parts (part_key, scanned_at) VALUES (?, ?)`,
			Args: []any{"att:" + strconv.FormatInt(id, 10), now},
		})
		for _, pc := range extractMailAttachmentCerts(filename, ct, from, data) {
			stmts = append(stmts, upsertSMIMECertStmt(pc.addrKey, src, pc.cert, now))
		}
	}
	if len(stmts) > 0 {
		_, _ = s.db.Transaction(ctx, stmts)
	}
}

// scanRemoteMailCertificatesBatch downloads up to limit uncached certificate/vCard attachments
// over the mail backend and indexes them into smime_certificates.
func (s *Service) scanRemoteMailCertificatesBatch(ctx context.Context, addresses []string, limit int) (more bool) {
	if err := s.ensureSMIMETables(ctx); err != nil {
		return false
	}
	if limit <= 0 {
		limit = 200
	}
	seenAddr := map[string]bool{}
	for _, a := range addresses {
		if k := normalizeCertAddr(a); k != "" {
			seenAddr[k] = true
		}
	}
	pred := smimeCardAttachmentPred
	if len(seenAddr) > 0 {
		pred = smimeCertAttachmentPred
	}
	rows, err := s.db.Query(ctx, `SELECT a.id, COALESCE(a.filename,''), COALESCE(a.content_type,''), COALESCE(m.from_addr,'')
		FROM attachments a
		JOIN messages m ON m.id = a.message_id
		JOIN message_locations l ON l.message_id = a.message_id AND l.shown = 1
		JOIN folders f ON f.id = l.folder_id
		WHERE `+notPurgedCond+`
		  AND COALESCE(f.role,'') NOT IN ('trash','junk')
		  AND COALESCE(a.size, 1) <= 1048576
		  AND `+pred+`
		  AND NOT EXISTS (SELECT 1 FROM smime_scanned_parts p WHERE p.part_key = 'att:' || a.id)
		GROUP BY a.id
		ORDER BY a.id DESC
		LIMIT ?`, limit+1)
	if err != nil || len(rows.Values) == 0 {
		return false
	}
	if len(rows.Values) > limit {
		more = true
		rows.Values = rows.Values[:limit]
	}

	type partMeta struct {
		from   string
		source string
	}
	ids := make([]int64, 0, len(rows.Values))
	meta := make(map[int64]partMeta, len(rows.Values))
	for _, r := range rows.Values {
		id := store.Int(r[0])
		name := strings.ToLower(store.Str(r[1]))
		ct := strings.ToLower(store.Str(r[2]))
		from := store.Str(r[3])
		// Only fetch heavy p7s signature parts when the sender matches one of the requested addresses.
		isSig := strings.HasSuffix(name, ".p7s") || ct == "application/pkcs7-signature" || ct == "application/x-pkcs7-signature"
		if isSig && (len(seenAddr) == 0 || !seenAddr[normalizeCertAddr(from)]) {
			continue
		}
		src := CertSourceMailCard
		if isSig {
			src = CertSourceMailSig
		}
		ids = append(ids, id)
		meta[id] = partMeta{from: from, source: src}
	}
	if len(ids) == 0 {
		return false
	}

	now := s.clk().Now().Unix()
	var stmts []sqlite.Statement
	flush := func() {
		if len(stmts) == 0 {
			return
		}
		_, _ = s.db.Transaction(ctx, stmts)
		stmts = nil
	}
	defer flush()

	err = s.FetchAttachments(ctx, ids, func(path string, info AttachmentInfo) error {
		pm := meta[info.ID]
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		stmts = append(stmts, sqlite.Statement{
			SQL:  `INSERT OR REPLACE INTO smime_scanned_parts (part_key, scanned_at) VALUES (?, ?)`,
			Args: []any{"att:" + strconv.FormatInt(info.ID, 10), now},
		})
		for _, pc := range extractMailAttachmentCerts(info.Filename, info.ContentType, pm.from, data) {
			stmts = append(stmts, upsertSMIMECertStmt(pc.addrKey, pm.source, pc.cert, now))
		}
		if len(stmts) >= 25 {
			flush()
		}
		return nil
	})
	return more && err == nil
}

func (s *Service) startSMIMECertIndexer() {
	st := s.smime
	if st == nil {
		return
	}
	st.mu.Lock()
	if st.closed || st.certStop != nil {
		st.mu.Unlock()
		return
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	st.certStop = stop
	st.certDone = done
	st.mu.Unlock()

	go func() {
		defer close(done)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			select {
			case <-stop:
				cancel()
			case <-done:
			}
		}()
		// Brief startup grace period so initial UI/folder loads take priority.
		timer := time.NewTimer(2 * time.Second)
		select {
		case <-stop:
			timer.Stop()
			return
		case <-st.certWake:
			timer.Stop()
		case <-timer.C:
		}
		for {
			s.scanCachedMailCertificates(ctx)
			more := s.scanRemoteMailCertificatesBatch(ctx, nil, 10)
			wait := 30 * time.Second
			if more {
				wait = 2 * time.Second
			}
			t := time.NewTimer(wait)
			select {
			case <-stop:
				t.Stop()
				return
			case <-st.certWake:
				t.Stop()
			case <-t.C:
			}
		}
	}()
}

func (s *Service) wakeSMIMECertIndexer() {
	st := s.smime
	if st == nil || st.certWake == nil {
		return
	}
	select {
	case st.certWake <- struct{}{}:
	default:
	}
}

func sourcePriority(src string) int {
	switch src {
	case CertSourceImported:
		return 5
	case CertSourceCardDAV:
		return 4
	case CertSourceSystem:
		return 3
	case CertSourceMailCard:
		return 2
	case CertSourceMailSig:
		return 1
	default:
		return 0
	}
}

func (s *Service) preferredCertMap(ctx context.Context, addrs []string) (map[string]string, error) {
	out := make(map[string]string, len(addrs))
	if len(addrs) == 0 {
		return out, nil
	}
	var keys []any
	seen := map[string]bool{}
	for _, a := range addrs {
		norm := normalizeCertAddr(a)
		if norm == "" || seen[norm] {
			continue
		}
		seen[norm] = true
		keys = append(keys, recipientPrefKey(norm))
	}
	for c := range slices.Chunk(keys, 200) {
		rows, err := s.db.Query(ctx, `SELECT key, value FROM settings WHERE key IN (`+placeholders(len(c))+`)`, c...)
		if err != nil {
			return nil, err
		}
		for _, r := range rows.Values {
			k := strings.TrimPrefix(store.Str(r[0]), "smime.rcpt.")
			v := strings.ToLower(strings.TrimSpace(store.Str(r[1])))
			if k != "" && v != "" {
				out[k] = v
			}
		}
	}
	return out, nil
}

func (s *Service) collectCertificatesFor(ctx context.Context, addresses []string, allowNetwork bool) (map[string][]SMIMECertificate, error) {
	if err := s.ensureSMIMETables(ctx); err != nil {
		return nil, err
	}
	var normAddrs []string
	seenAddr := map[string]bool{}
	for _, a := range addresses {
		if k := normalizeCertAddr(a); k != "" && !seenAddr[k] {
			seenAddr[k] = true
			normAddrs = append(normAddrs, k)
		}
	}
	out := make(map[string][]SMIMECertificate, len(normAddrs))
	if len(normAddrs) == 0 {
		return out, nil
	}

	// Index locally cached cert/vCard attachments without network I/O; optionally fetch remote parts on send.
	s.scanCachedMailCertificates(ctx)
	if allowNetwork {
		s.scanRemoteMailCertificatesBatch(ctx, normAddrs, 200)
	} else {
		s.wakeSMIMECertIndexer()
	}

	prefs, err := s.preferredCertMap(ctx, normAddrs)
	if err != nil {
		return nil, err
	}

	type rawEntry struct {
		source string
		cert   *smx509.Certificate
	}
	byAddr := make(map[string]map[string]rawEntry, len(normAddrs))
	addEntry := func(addr, source string, cert *smx509.Certificate) {
		if cert == nil || !smime.MatchesMailbox(cert, addr) {
			return
		}
		sha := smime.CertSHA256(cert.Raw)
		m := byAddr[addr]
		if m == nil {
			m = map[string]rawEntry{}
			byAddr[addr] = m
		}
		if prev, ok := m[sha]; !ok || sourcePriority(source) > sourcePriority(prev.source) {
			m[sha] = rawEntry{source: source, cert: cert}
		}
	}

	// 1. Persisted certs from CardDAV, mail attachments, verified mail signatures, and manual imports.
	args := make([]any, len(normAddrs))
	for i, a := range normAddrs {
		args[i] = a
	}
	for c := range slices.Chunk(args, 200) {
		rows, err := s.db.Query(ctx, `SELECT addr_key, source, der FROM smime_certificates WHERE addr_key IN (`+placeholders(len(c))+`)`, c...)
		if err != nil {
			return nil, err
		}
		for _, r := range rows.Values {
			addr := store.Str(r[0])
			src := store.Str(r[1])
			der, _ := r[2].([]byte)
			if cert, err := smime.ParseCertificate(der); err == nil {
				addEntry(addr, src, cert)
			}
		}
	}

	// 2. OS system certificate store (Keychain on macOS, AddressBook + MY on Windows).
	for _, addr := range normAddrs {
		sysCerts, _ := smime.FindSystemCertificates(ctx, addr)
		for _, cert := range sysCerts {
			addEntry(addr, CertSourceSystem, cert)
		}
	}

	for _, addr := range normAddrs {
		m := byAddr[addr]
		if len(m) == 0 {
			continue
		}
		prefSHA := prefs[addr]
		list := make([]SMIMECertificate, 0, len(m))
		for sha, e := range m {
			trustErr := ""
			trusted := true
			if err := smime.VerifyTrust(ctx, "encrypt", addr, e.cert); err != nil {
				trusted = false
				trustErr = FormatSMIMEError(err)
			}
			list = append(list, buildSMIMECertificate(sha, addr, e.source, e.cert, trusted, trustErr, prefSHA != "" && sha == prefSHA))
		}
		slices.SortFunc(list, func(a, b SMIMECertificate) int {
			if a.Selected != b.Selected {
				if a.Selected {
					return -1
				}
				return 1
			}
			if a.Trusted != b.Trusted {
				if a.Trusted {
					return -1
				}
				return 1
			}
			if c := b.NotBefore.Compare(a.NotBefore); c != 0 {
				return c
			}
			return cmp.Compare(a.SHA256, b.SHA256)
		})
		out[addr] = list
	}
	return out, nil
}

// mailboxCertificates supplies candidate X.509 certificates for smime.ProtectWith across all standard sources.
func (s *Service) mailboxCertificates(ctx context.Context, _ int64, addresses []string) (map[string][]*smx509.Certificate, error) {
	resolved, err := s.collectCertificatesFor(ctx, addresses, false)
	if err != nil {
		return nil, err
	}
	var missing []string
	for _, raw := range addresses {
		addr := normalizeCertAddr(raw)
		if addr == "" {
			continue
		}
		hasTrusted := false
		for _, c := range resolved[addr] {
			if c.Trusted {
				hasTrusted = true
				break
			}
		}
		if !hasTrusted {
			missing = append(missing, addr)
		}
	}
	if len(missing) > 0 {
		if remote, err := s.collectCertificatesFor(ctx, missing, true); err == nil {
			for k, v := range remote {
				resolved[k] = v
			}
		}
	}
	result := make(map[string][]*smx509.Certificate, len(resolved))
	for addr, certs := range resolved {
		for _, item := range certs {
			if cert, err := smime.ParseCertificate(item.DER); err == nil {
				result[addr] = append(result[addr], cert)
			}
		}
	}
	return result, nil
}

func (s *Service) accountAllowsWeakSMIMEKey(ctx context.Context, email string) (bool, error) {
	if email == "" {
		return false, nil
	}
	rows, err := s.db.Query(ctx,
		`SELECT 1 FROM accounts a JOIN settings st ON st.key = 'smime.allow_weak_key.' || a.id WHERE lower(a.email) = ? LIMIT 1`,
		email)
	if err != nil {
		return false, err
	}
	return len(rows.Values) > 0, nil
}

// ListOwnSMIMECertificates returns personal S/MIME identities matching email (or all identities if empty).
func (s *Service) ListOwnSMIMECertificates(ctx context.Context, email string) ([]SMIMEIdentity, error) {
	if !smime.Supported() {
		return nil, nil
	}
	addr := normalizeCertAddr(email)
	if !smime.AllowWeakKeySize(ctx) && addr != "" {
		if allow, err := s.accountAllowsWeakSMIMEKey(ctx, addr); err == nil && allow {
			ctx = smime.WithAllowWeakKeySize(ctx, true)
		}
	}
	items, err := smime.ListIdentities(ctx, addr)
	if err != nil {
		return nil, err
	}
	out := make([]SMIMEIdentity, len(items))
	for i, it := range items {
		out[i] = SMIMEIdentity{
			SHA256:        it.SHA256,
			Subject:       it.Subject,
			SubjectDN:     it.SubjectDN,
			Issuer:        it.Issuer,
			IssuerDN:      it.IssuerDN,
			Emails:        it.Emails,
			SerialNumber:  it.SerialNumber,
			NotBefore:     it.NotBefore,
			NotAfter:      it.NotAfter,
			PublicKeyAlgo: it.PublicKeyAlgo,
			SignatureAlgo: it.SignatureAlgo,
			KeyUsages:     it.KeyUsages,
			ExtKeyUsages:  it.ExtKeyUsages,
			SHA1:          it.SHA1,
			Hardware:      it.Hardware,
			CanSign:       it.CanSign,
			CanEncrypt:    it.CanEncrypt,
		}
	}
	return out, nil
}

// ListContactCertificates resolves S/MIME encryption certificates and readiness for each address.
func (s *Service) ListContactCertificates(ctx context.Context, addresses []string) ([]RecipientSMIMEStatus, error) {
	var order []string
	seen := map[string]bool{}
	for _, a := range addresses {
		if k := normalizeCertAddr(a); k != "" && !seen[k] {
			seen[k] = true
			order = append(order, k)
		}
	}
	if len(order) == 0 {
		return nil, nil
	}
	resolved, err := s.collectCertificatesFor(ctx, order, false)
	if err != nil {
		return nil, err
	}
	return buildRecipientStatuses(order, resolved, nil), nil
}

func buildRecipientStatuses(order []string, resolved map[string][]SMIMECertificate, draftPinned map[string]string) []RecipientSMIMEStatus {
	out := make([]RecipientSMIMEStatus, 0, len(order))
	for _, addr := range order {
		certs := slices.Clone(resolved[addr])
		pin := strings.ToLower(strings.TrimSpace(draftPinned[addr]))
		if pin != "" {
			for i := range certs {
				certs[i].Selected = certs[i].SHA256 == pin
			}
			slices.SortFunc(certs, func(a, b SMIMECertificate) int {
				if a.Selected != b.Selected {
					if a.Selected {
						return -1
					}
					return 1
				}
				if a.Trusted != b.Trusted {
					if a.Trusted {
						return -1
					}
					return 1
				}
				if c := b.NotBefore.Compare(a.NotBefore); c != 0 {
					return c
				}
				return cmp.Compare(a.SHA256, b.SHA256)
			})
		}

		status := RecipientSMIMEStatus{Address: addr, Certs: certs}
		var active *SMIMECertificate
		var lastTrustErr string
		for i := range certs {
			if pin != "" && certs[i].SHA256 != pin {
				continue
			}
			if certs[i].Selected && !certs[i].Trusted && certs[i].TrustErr != "" {
				lastTrustErr = certs[i].TrustErr
			}
			if certs[i].Trusted {
				active = &certs[i]
				break
			}
			if lastTrustErr == "" && certs[i].TrustErr != "" {
				lastTrustErr = certs[i].TrustErr
			}
		}
		if active != nil {
			status.Ready = true
			status.Selected = active.SHA256
		} else if len(certs) == 0 {
			status.ErrorCode = "rcpt_missing"
		} else if pin != "" {
			if lastTrustErr != "" {
				status.ErrorCode = "rcpt_untrusted"
				status.Error = lastTrustErr
			} else {
				status.ErrorCode = "rcpt_selected_missing"
			}
		} else if lastTrustErr != "" {
			status.ErrorCode = "rcpt_untrusted"
			status.Error = lastTrustErr
		} else {
			status.ErrorCode = "rcpt_untrusted"
		}
		out = append(out, status)
	}
	return out
}

// SelectContactCertificate persists a preferred S/MIME certificate SHA-256 for an email address
// (or clears the preference when sha256 is empty).
func (s *Service) SelectContactCertificate(ctx context.Context, address, sha256 string) error {
	addr := normalizeCertAddr(address)
	if addr == "" {
		return ErrSMIMEInvalidAddress
	}
	key := recipientPrefKey(addr)
	sha := strings.ToLower(strings.TrimSpace(sha256))
	if sha == "" {
		return s.exec(ctx, sqlite.Statement{SQL: "DELETE FROM settings WHERE key = ?", Args: []any{key}})
	}
	return s.exec(ctx, sqlite.Statement{SQL: "INSERT OR REPLACE INTO settings(key, value) VALUES (?, ?)", Args: []any{key, sha}})
}

// ImportContactCertificateFile imports certificates from a local .cer/.crt/.der/.pem/.p7b/.vcf file.
func (s *Service) ImportContactCertificateFile(ctx context.Context, address, path string) ([]SMIMECertificate, error) {
	if err := s.ensureSMIMETables(ctx); err != nil {
		return nil, err
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, ErrSMIMECertFileRequired
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() <= 0 || info.Size() > 2<<20 {
		return nil, ErrSMIMECertFileTooLarge
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	targetAddr := normalizeCertAddr(address)

	var certs []*smx509.Certificate
	var vcardEmails []string
	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".vcf" || strings.Contains(string(data), "BEGIN:VCARD") {
		certs, vcardEmails = extractCertsFromVCard(string(data))
	} else {
		certs, err = smime.ParseCertificateBundle(data)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrSMIMECertInvalid, err)
		}
	}
	if len(certs) == 0 {
		return nil, ErrSMIMECertInvalid
	}

	now := s.clk().Now().Unix()
	var stmts []sqlite.Statement
	var imported []SMIMECertificate
	seen := map[string]bool{}
	for _, cert := range certs {
		var matched []string
		if targetAddr != "" {
			if smime.MatchesMailbox(cert, targetAddr) {
				matched = []string{targetAddr}
			}
		} else {
			for _, em := range vcardEmails {
				if smime.MatchesMailbox(cert, em) {
					matched = append(matched, em)
				}
			}
			for _, em := range smime.CertEmails(cert) {
				if smime.MatchesMailbox(cert, em) {
					matched = append(matched, em)
				}
			}
		}
		for _, addr := range matched {
			addr = normalizeCertAddr(addr)
			sha := smime.CertSHA256(cert.Raw)
			key := sha + "\x00" + addr
			if seen[key] {
				continue
			}
			seen[key] = true
			stmts = append(stmts, upsertSMIMECertStmt(addr, CertSourceImported, cert, now))
			trustErr := ""
			trusted := true
			if terr := smime.VerifyTrust(ctx, "encrypt", addr, cert); terr != nil {
				trusted = false
				trustErr = FormatSMIMEError(terr)
			}
			imported = append(imported, buildSMIMECertificate(sha, addr, CertSourceImported, cert, trusted, trustErr, false))
		}
	}
	if len(imported) == 0 {
		if targetAddr != "" {
			return nil, fmt.Errorf("%w (%s)", ErrSMIMECertAddressMismatch, targetAddr)
		}
		return nil, ErrSMIMECertNoEmail
	}
	if len(imported) == 1 && imported[0].Trusted {
		stmts = append(stmts, sqlite.Statement{
			SQL:  "INSERT OR REPLACE INTO settings(key, value) VALUES (?, ?)",
			Args: []any{recipientPrefKey(imported[0].Address), imported[0].SHA256},
		})
		imported[0].Selected = true
	}
	if _, err := s.db.Transaction(ctx, stmts); err != nil {
		return nil, err
	}
	return imported, nil
}

// RemoveContactCertificate deletes a manually imported certificate for address and clears its preference if selected.
func (s *Service) RemoveContactCertificate(ctx context.Context, address, sha256 string) error {
	if err := s.ensureSMIMETables(ctx); err != nil {
		return err
	}
	addr := normalizeCertAddr(address)
	sha := strings.ToLower(strings.TrimSpace(sha256))
	if addr == "" {
		return ErrSMIMEInvalidAddress
	}
	if sha == "" {
		return ErrSMIMECertInvalid
	}
	_, err := s.db.Transaction(ctx, []sqlite.Statement{
		{
			SQL:  `DELETE FROM smime_certificates WHERE sha256 = ? AND addr_key = ? AND source = ?`,
			Args: []any{sha, addr, CertSourceImported},
		},
		{
			SQL:  `DELETE FROM settings WHERE key = ? AND lower(value) = ?`,
			Args: []any{recipientPrefKey(addr), sha},
		},
	})
	return err
}

// RecordSMIMESignerCert stores a verified sender leaf certificate extracted from an incoming signed message.
func (s *Service) RecordSMIMESignerCert(ctx context.Context, address string, der []byte) error {
	if len(der) == 0 {
		return nil
	}
	addr := normalizeCertAddr(address)
	if addr == "" {
		return nil
	}
	cert, err := smime.ParseCertificate(der)
	if err != nil || !smime.MatchesMailbox(cert, addr) {
		return nil
	}
	if err := s.ensureSMIMETables(ctx); err != nil {
		return err
	}
	return s.exec(ctx, upsertSMIMECertStmt(addr, CertSourceMailSig, cert, s.clk().Now().Unix()))
}

func (s *Service) loadDraftSMIMEPref(ctx context.Context, draftID int64) (draftSMIMEPref, error) {
	rows, err := s.db.Query(ctx, "SELECT value FROM settings WHERE key = ?", draftSMIMEKey(draftID))
	if err != nil {
		return draftSMIMEPref{}, err
	}
	if len(rows.Values) == 0 {
		return draftSMIMEPref{}, nil
	}
	var pref draftSMIMEPref
	_ = json.Unmarshal([]byte(store.Str(rows.Values[0][0])), &pref)
	if len(pref.PinnedCerts) > 0 {
		clean := make(map[string]string, len(pref.PinnedCerts))
		for k, v := range pref.PinnedCerts {
			nk := normalizeCertAddr(k)
			nv := strings.ToLower(strings.TrimSpace(v))
			if nk != "" && nv != "" {
				clean[nk] = nv
			}
		}
		pref.PinnedCerts = clean
	}
	return pref, nil
}

func (s *Service) effectiveDraftSMIME(ctx context.Context, acc Account, draftID int64) (sign, encrypt bool, pinned map[string]string, err error) {
	pref, err := s.loadDraftSMIMEPref(ctx, draftID)
	if err != nil {
		return false, false, nil, err
	}
	sign = acc.SMIMESign
	if pref.Sign != nil {
		sign = *pref.Sign
	}
	encrypt = acc.SMIMEEncrypt
	if pref.Encrypt != nil {
		encrypt = *pref.Encrypt
	}
	return sign, encrypt, pref.PinnedCerts, nil
}

// DraftSMIMEStatus computes live S/MIME sign/encrypt readiness and certificate selections for draftID.
func (s *Service) DraftSMIMEStatus(ctx context.Context, draftID int64) (DraftSMIMEStatus, error) {
	d, err := s.GetDraft(ctx, draftID)
	if err != nil {
		return DraftSMIMEStatus{}, err
	}
	acc, err := s.account(ctx, d.AccountID)
	if err != nil {
		return DraftSMIMEStatus{}, err
	}
	if acc.SMIMEAllowWeakKey {
		ctx = smime.WithAllowWeakKeySize(ctx, true)
	}
	sign, encrypt, pinned, err := s.effectiveDraftSMIME(ctx, acc, draftID)
	if err != nil {
		return DraftSMIMEStatus{}, err
	}
	out := DraftSMIMEStatus{
		DraftID:    draftID,
		AccountID:  acc.ID,
		From:       normalizeCertAddr(acc.Email),
		Supported:  smime.Supported(),
		Sign:       sign,
		Encrypt:    encrypt,
		OwnCertSHA: acc.SMIMECert,
	}
	if !out.Supported {
		out.OwnErrorCode = "unsupported"
		return out, nil
	}

	ownCerts, ownErr := s.ListOwnSMIMECertificates(ctx, out.From)
	out.OwnCerts = ownCerts
	if ownErr != nil {
		out.OwnError = ownErr.Error()
	}

	var ownSignReady, ownEncReady bool
	for _, c := range ownCerts {
		if acc.SMIMECert != "" && c.SHA256 != acc.SMIMECert {
			continue
		}
		if c.CanSign {
			ownSignReady = true
		}
		if c.CanEncrypt {
			ownEncReady = true
		}
	}
	if ownErr == nil {
		if len(ownCerts) == 0 {
			out.OwnErrorCode = "own_missing"
		} else if acc.SMIMECert != "" && !ownSignReady && !ownEncReady {
			out.OwnErrorCode = "own_selected_unavailable"
		} else if !ownSignReady && !ownEncReady {
			out.OwnErrorCode = "own_untrusted"
		} else if !ownSignReady && sign {
			out.OwnErrorCode = "own_no_sign"
		} else if !ownEncReady && encrypt {
			out.OwnErrorCode = "own_no_encrypt"
		}
	}
	out.OwnReady = ownSignReady || ownEncReady

	// Collect unique external recipients (ignoring own address since ownCert covers self).
	var rcpts []string
	seen := map[string]bool{}
	for _, list := range [][]string{d.To, d.Cc, d.Bcc} {
		for _, raw := range list {
			addr := normalizeCertAddr(raw)
			if addr == "" || addr == out.From || seen[addr] {
				continue
			}
			seen[addr] = true
			rcpts = append(rcpts, addr)
		}
	}
	resolved, err := s.collectCertificatesFor(ctx, rcpts, false)
	if err != nil {
		return DraftSMIMEStatus{}, err
	}
	mergedPins, err := s.preferredCertMap(ctx, rcpts)
	if err != nil {
		return DraftSMIMEStatus{}, err
	}
	for k, v := range pinned {
		mergedPins[k] = v
	}
	out.Recipients = buildRecipientStatuses(rcpts, resolved, mergedPins)
	out.CanSendSigned = ownSignReady
	allRcptReady := true
	for _, r := range out.Recipients {
		if !r.Ready {
			allRcptReady = false
			break
		}
	}
	out.CanSendEncrypted = ownEncReady && allRcptReady
	return out, nil
}

// SetDraftSMIME updates per-draft S/MIME sign/encrypt overrides and/or pinned recipient certificate SHA-256s.
func (s *Service) SetDraftSMIME(ctx context.Context, draftID int64, sign, encrypt *bool, pinnedCerts map[string]string) (DraftSMIMEStatus, error) {
	if _, err := s.GetDraft(ctx, draftID); err != nil {
		return DraftSMIMEStatus{}, err
	}
	pref, err := s.loadDraftSMIMEPref(ctx, draftID)
	if err != nil {
		return DraftSMIMEStatus{}, err
	}
	if sign != nil {
		v := *sign
		pref.Sign = &v
	}
	if encrypt != nil {
		v := *encrypt
		pref.Encrypt = &v
	}
	if pinnedCerts != nil {
		if pref.PinnedCerts == nil {
			pref.PinnedCerts = map[string]string{}
		}
		for addr, sha := range pinnedCerts {
			k := normalizeCertAddr(addr)
			v := strings.ToLower(strings.TrimSpace(sha))
			if k == "" {
				continue
			}
			if v == "" {
				delete(pref.PinnedCerts, k)
			} else {
				pref.PinnedCerts[k] = v
			}
		}
	}
	raw, err := json.Marshal(pref)
	if err != nil {
		return DraftSMIMEStatus{}, err
	}
	if err := s.exec(ctx, sqlite.Statement{
		SQL:  "INSERT OR REPLACE INTO settings(key, value) VALUES (?, ?)",
		Args: []any{draftSMIMEKey(draftID), string(raw)},
	}); err != nil {
		return DraftSMIMEStatus{}, err
	}
	return s.DraftSMIMEStatus(ctx, draftID)
}
