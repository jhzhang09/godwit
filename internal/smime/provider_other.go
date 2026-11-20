//go:build !darwin && !windows

package smime

import (
	"context"
	"crypto"
	"errors"
)

var errUnsupportedPlatform = errors.New("S/MIME certificates and security keys are not supported on this platform")

func platformSupported() bool { return false }

func newPlatformProvider(bool) provider { return unsupportedProvider{} }

type unsupportedProvider struct{}

func (unsupportedProvider) Identities(context.Context) ([]RawIdentity, error) {
	return nil, errUnsupportedPlatform
}
func (unsupportedProvider) FindCertificates(context.Context, string) ([][]byte, error) {
	return nil, nil
}
func (unsupportedProvider) Prepare(context.Context, []byte, []byte) error {
	return errUnsupportedPlatform
}
func (unsupportedProvider) DigestAlgorithm(context.Context, []byte) (crypto.Hash, error) {
	return 0, errUnsupportedPlatform
}
func (unsupportedProvider) Sign(context.Context, []byte, crypto.Hash, []byte) ([]byte, error) {
	return nil, errUnsupportedPlatform
}
func (unsupportedProvider) Decrypt(context.Context, []byte, []byte) ([]byte, error) {
	return nil, errUnsupportedPlatform
}
func (unsupportedProvider) VerifyTrust(context.Context, string, string, [][]byte) error {
	return errUnsupportedPlatform
}
func (unsupportedProvider) VerifyCMS(context.Context, string, []byte, []byte) (cmsVerifyResult, error) {
	return cmsVerifyResult{}, errUnsupportedPlatform
}
func (unsupportedProvider) Retry(context.Context) error { return nil }
func (unsupportedProvider) Close() error                { return nil }
