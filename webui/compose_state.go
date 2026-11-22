package webui

// Account is a sender the page can pick.
type Account struct {
	// ID and Email identify the account.
	ID    int64  `json:"id"`
	Email string `json:"email"`
}

// ComposeSMIMECertChainNode summarizes one certificate in a resolved X.509 trust chain,
// ordered top-down from root/highest CA to leaf.
type ComposeSMIMECertChainNode struct {
	Subject       string `json:"subject"`
	Issuer        string `json:"issuer"`
	PublicKeyAlgo string `json:"publicKeyAlgo,omitempty"`
	NotBefore     int64  `json:"notBefore"`
	NotAfter      int64  `json:"notAfter"`
	SHA256        string `json:"sha256"`
	Role          string `json:"role"`
	SelfSigned    bool   `json:"selfSigned"`
}

// ComposeSMIMEIdentity describes one personal S/MIME certificate for the sender account.
type ComposeSMIMEIdentity struct {
	SHA256        string                      `json:"sha256"`
	Subject       string                      `json:"subject"`
	SubjectDN     string                      `json:"subjectDn,omitempty"`
	Issuer        string                      `json:"issuer"`
	IssuerDN      string                      `json:"issuerDn,omitempty"`
	Emails        []string                    `json:"emails"`
	SerialNumber  string                      `json:"serialNumber,omitempty"`
	NotBefore     int64                       `json:"notBefore"`
	NotAfter      int64                       `json:"notAfter"`
	PublicKeyAlgo string                      `json:"publicKeyAlgo,omitempty"`
	SignatureAlgo string                      `json:"signatureAlgo,omitempty"`
	KeyUsages     []string                    `json:"keyUsages"`
	ExtKeyUsages  []string                    `json:"extKeyUsages"`
	SHA1          string                      `json:"sha1,omitempty"`
	Hardware      bool                        `json:"hardware"`
	CanSign       bool                        `json:"canSign"`
	CanEncrypt    bool                        `json:"canEncrypt"`
	Chain         []ComposeSMIMECertChainNode `json:"chain,omitempty"`
}

// ComposeSMIMECert describes one candidate S/MIME encryption certificate for a recipient.
type ComposeSMIMECert struct {
	SHA256        string                      `json:"sha256"`
	Address       string                      `json:"address"`
	Source        string                      `json:"source"`
	Subject       string                      `json:"subject"`
	SubjectDN     string                      `json:"subjectDn,omitempty"`
	Issuer        string                      `json:"issuer"`
	IssuerDN      string                      `json:"issuerDn,omitempty"`
	Emails        []string                    `json:"emails"`
	SerialNumber  string                      `json:"serialNumber,omitempty"`
	NotBefore     int64                       `json:"notBefore"`
	NotAfter      int64                       `json:"notAfter"`
	PublicKeyAlgo string                      `json:"publicKeyAlgo,omitempty"`
	SignatureAlgo string                      `json:"signatureAlgo,omitempty"`
	KeyUsages     []string                    `json:"keyUsages"`
	ExtKeyUsages  []string                    `json:"extKeyUsages"`
	SHA1          string                      `json:"sha1,omitempty"`
	Trusted       bool                        `json:"trusted"`
	TrustErr      string                      `json:"trustErr,omitempty"`
	Selected      bool                        `json:"selected"`
	Chain         []ComposeSMIMECertChainNode `json:"chain,omitempty"`
}

// ComposeRecipientSMIME describes S/MIME encryption certificate readiness for one recipient.
type ComposeRecipientSMIME struct {
	Address   string             `json:"address"`
	Ready     bool               `json:"ready"`
	Selected  string             `json:"selected,omitempty"`
	Error     string             `json:"error,omitempty"`
	ErrorCode string             `json:"errorCode,omitempty"`
	Certs     []ComposeSMIMECert `json:"certs"`
}

// ComposeSMIME is the S/MIME signing, encryption, and certificate state for a compose draft.
type ComposeSMIME struct {
	Supported        bool                    `json:"supported"`
	From             string                  `json:"from"`
	Sign             bool                    `json:"sign"`
	Encrypt          bool                    `json:"encrypt"`
	OwnCertSHA       string                  `json:"ownCertSha,omitempty"`
	OwnReady         bool                    `json:"ownReady"`
	OwnError         string                  `json:"ownError,omitempty"`
	OwnErrorCode     string                  `json:"ownErrorCode,omitempty"`
	OwnCerts         []ComposeSMIMEIdentity  `json:"ownCerts"`
	Recipients       []ComposeRecipientSMIME `json:"recipients"`
	CanSendSigned    bool                    `json:"canSendSigned"`
	CanSendEncrypted bool                    `json:"canSendEncrypted"`
}

// Attachment is a file attached to the draft.
type Attachment struct {
	// ID names it to RemoveAttachment; Size is in bytes.
	ID       int64  `json:"id"`
	Filename string `json:"filename"`
	Size     int    `json:"size"`
}

// ComposeState is what a compose page shows when it opens.
type ComposeState struct {
	// DraftID is the window's draft; Accounts are the senders to pick from.
	DraftID  int64     `json:"draftId"`
	Accounts []Account `json:"accounts"`
	// From is the sending account's ID.
	From int64 `json:"from"`
	// To, Cc, Bcc, ReplyTo and Subject are the header fields as stored.
	To      []string `json:"to"`
	Cc      []string `json:"cc"`
	Bcc     []string `json:"bcc"`
	ReplyTo string   `json:"replyTo"`
	Subject string   `json:"subject"`
	// Body is the editable part as sanitized HTML.
	Body string `json:"body"`
	// Quote is read-only plain text. SignatureHTML is the signature as
	// sanitized HTML, its images as data: URLs (core.SignatureShown), ""
	// for none: the page shows it as is, read-only.
	Quote         string `json:"quote"`
	SignatureHTML string `json:"signatureHtml"`
	// Attachments are the draft's files.
	Attachments []Attachment `json:"attachments"`
	// Revision is what the next save must pass; Theme styles the page.
	Revision int64 `json:"revision"`
	Theme    Theme `json:"theme"`
	// UpdatedAt is when the draft was last stored, in Unix milliseconds.
	UpdatedAt int64 `json:"updatedAt"`
	// Locale selects the shared catalog bundled with the page.
	Locale string `json:"locale"`
	// Wit is what the Wit panel offers, as WitInfo.
	Wit WitInfo `json:"wit"`
	// FromProgram is core.Draft.FromProgram: a program wrote or changed the
	// draft, so the page asks the user to check it before sending (ADR 0043).
	FromProgram bool `json:"fromProgram"`
	// SMIME is the draft's S/MIME sign/encrypt policy and certificate readiness.
	SMIME *ComposeSMIME `json:"smime,omitempty"`
}

// ComposeEdit is what the page saves: the fields it edits, and the revision
// they were made against.
type ComposeEdit struct {
	// To, Cc, Bcc, ReplyTo, Subject and Body (HTML) are the edited fields, as
	// in ComposeState; Revision is the one they were made against.
	To       []string `json:"to"`
	Cc       []string `json:"cc"`
	Bcc      []string `json:"bcc"`
	ReplyTo  string   `json:"replyTo"`
	Subject  string   `json:"subject"`
	Body     string   `json:"body"`
	Revision int64    `json:"revision"`
}

// SaveResult is the outcome of a save.
type SaveResult struct {
	// Revision is the draft's new revision, to pass to the next save.
	Revision int64 `json:"revision"`
	// Conflict means the draft changed elsewhere: nothing was saved.
	Conflict bool `json:"conflict"`
}

// Change is the outcome of an account switch or an attachment change.
type Change struct {
	// Revision and Attachments are the draft's after the change.
	Revision    int64        `json:"revision"`
	Attachments []Attachment `json:"attachments"`
	// Conflict means the draft changed elsewhere: nothing was done.
	Conflict bool `json:"conflict"`
	// SignatureHTML is the draft's signature as ComposeState has it.
	SignatureHTML string `json:"signatureHtml"`
	// UpdatedAt is when the draft was last stored, in Unix milliseconds.
	UpdatedAt int64 `json:"updatedAt"`
	// SMIME refreshes S/MIME state when the sender account changes.
	SMIME *ComposeSMIME `json:"smime,omitempty"`
}

// AttachResult is the outcome of adding files: a partial success is no error.
type AttachResult struct {
	Change
	// TooLarge are the files over the size limit; Failed those that failed
	// for another reason (logged).
	TooLarge []string `json:"tooLarge"`
	Failed   []string `json:"failed"`
}

// SendWarning is a plugin's word about the draft.
type SendWarning struct {
	// Plugin is its name; Message what it said.
	Plugin  string `json:"plugin"`
	Message string `json:"message"`
}

// SendResult is the outcome of a send.
type SendResult struct {
	// Sent means it is in the outbox and the window closes.
	Sent bool `json:"sent"`
	// Conflict means the draft is not at the revision sent: nothing was sent.
	Conflict bool `json:"conflict"`
	// Warnings, with Digest, need the user's go-ahead: Send again with Digest.
	Warnings []SendWarning `json:"warnings"`
	Digest   string        `json:"digest"`
	// Blocked is the plugin that refused the draft, and its message.
	Blocked *SendWarning `json:"blocked"`
}
