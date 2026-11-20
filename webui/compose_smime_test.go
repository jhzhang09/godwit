package webui

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/godwit-email/godwit/core"
	"github.com/godwit-email/godwit/internal/smime"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestComposeSMIMEStatusTogglePinAndImport(t *testing.T) {
	f := newFixture(t)
	second := f.e.AddAccount(t, "sender2@example.com")
	signTrue := true
	_, err := f.e.Svc.UpdateAccount(t.Context(), second.ID, core.AccountPatch{SMIMESign: &signTrue})
	require.NoError(t, err)

	d := f.draft(t, "new", 0)
	f.c.Attach(1, d.ID)

	st, err := f.page.Load(f.ctx(1))
	require.NoError(t, err)
	require.NotNil(t, st.SMIME)
	assert.Equal(t, smime.Supported(), st.SMIME.Supported)
	assert.False(t, st.SMIME.Sign)
	assert.False(t, st.SMIME.Encrypt)

	// Save recipient bob@example.com
	saveRes, err := f.page.Save(f.ctx(1), ComposeEdit{
		To:       []string{"bob@example.com"},
		Subject:  "Encrypted Subject",
		Body:     "<p>secret</p>",
		Revision: st.Revision,
	})
	require.NoError(t, err)

	// Import a certificate for bob@example.com via PickFiles
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(501),
		Subject:        pkix.Name{CommonName: "Bob Compose Cert"},
		EmailAddresses: []string{"bob@example.com"},
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(24 * time.Hour),
		KeyUsage:       x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	certPath := filepath.Join(t.TempDir(), "bob.pem")
	require.NoError(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	f.pick = func() ([]string, error) { return []string{certPath}, nil }

	afterImport, err := f.page.ImportSMIMECertificate(f.ctx(1), "bob@example.com")
	require.NoError(t, err)
	require.Len(t, afterImport.Recipients, 1)
	require.Equal(t, "bob@example.com", afterImport.Recipients[0].Address)
	require.Len(t, afterImport.Recipients[0].Certs, 1)
	importedSHA := afterImport.Recipients[0].Certs[0].SHA256
	assert.Equal(t, smime.CertSHA256(der), importedSHA)

	// Toggle Sign + Encrypt and pin recipient cert on draft
	on := true
	updated, err := f.page.SetSMIME(f.ctx(1), &on, &on, map[string]string{"bob@example.com": importedSHA})
	require.NoError(t, err)
	assert.True(t, updated.Sign)
	assert.True(t, updated.Encrypt)
	assert.True(t, updated.Recipients[0].Certs[0].Selected)

	// Live SMIMEStatus returns the same state
	cur, err := f.page.SMIMEStatus(f.ctx(1))
	require.NoError(t, err)
	assert.True(t, cur.Sign)
	assert.True(t, cur.Encrypt)
	assert.Equal(t, importedSHA, cur.Recipients[0].Certs[0].SHA256)

	// Clear Sign toggle via SetSMIME; Switch account refreshes Change.SMIME
	off := false
	cleared, err := f.page.SetSMIME(f.ctx(1), &off, nil, nil)
	require.NoError(t, err)
	assert.False(t, cleared.Sign)
	assert.True(t, cleared.Encrypt)

	ch, err := f.page.SetAccount(f.ctx(1), second.ID, saveRes.Revision)
	require.NoError(t, err)
	require.NotNil(t, ch.SMIME)
	assert.Equal(t, "sender2@example.com", ch.SMIME.From)
}
