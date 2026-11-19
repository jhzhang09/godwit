//go:build !darwin && !windows

package smime

import (
	"context"
	"crypto"
	"errors"
)

var errUnsupportedPlatform = errors.New("当前平台暂不支持 S/MIME 硬件 Key")

func platformSupported() bool { return false }

func newPlatformProvider(bool) provider { return unsupportedProvider{} }

type unsupportedProvider struct{}

func (unsupportedProvider) Identities(context.Context) ([][]byte, error) {
	return nil, errUnsupportedPlatform
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
func (unsupportedProvider) VerifyCMS(context.Context, string, []byte, []byte) ([]byte, error) {
	return nil, errUnsupportedPlatform
}
func (unsupportedProvider) Retry(context.Context) error { return nil }
func (unsupportedProvider) Close() error                { return nil }
