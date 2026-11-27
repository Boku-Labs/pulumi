// Copyright 2026, Pulumi Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cloud

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"sync/atomic"

	"gocloud.dev/secrets/gcpkms"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pulumi/pulumi/sdk/v3/go/common/resource/config"
	"github.com/pulumi/pulumi/sdk/v3/go/common/workspace"
)

const (
	gcpConfigCiphertextPrefix = "v2:"
	gcpConfigBatchConcurrency = 8
	gcmNonceSize              = 12
	gcmTagSize                = 16
)

type dataKeyWrapper interface {
	Encrypt(context.Context, []byte) ([]byte, error)
}

type dataKeyUnwrapper interface {
	Decrypt(context.Context, []byte) ([]byte, error)
}

// ConfigKMSKeeper wraps and unwraps data keys for GCP KMS configuration values.
type ConfigKMSKeeper interface {
	dataKeyWrapper
	dataKeyUnwrapper
}

func parseGCPKMSProvider(rawURL string) *url.URL {
	provider, err := url.Parse(rawURL)
	if err != nil || provider.Scheme != gcpkms.Scheme {
		return nil
	}
	return provider
}

// NewConfigEncrypter returns a writer for an initialized GCP KMS stack. It
// returns nil when the caller should use the regular secrets manager.
// A nil opener uses the default KMS client.
func NewConfigEncrypter(
	ctx context.Context, ps *workspace.ProjectStack, open func(context.Context, string) (ConfigKMSKeeper, error),
) (config.Encrypter, error) {
	provider := ps.SecretsProvider
	if ps.EncryptedKey == "" || parseGCPKMSProvider(provider) == nil ||
		effectiveCloudSecretsProvider(provider) != provider {
		return nil, nil
	}
	stackKey, err := base64.StdEncoding.DecodeString(ps.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("decoding wrapped stack key: %w", err)
	}
	if len(stackKey) == 0 {
		return nil, errors.New("missing wrapped stack key")
	}

	var keeper ConfigKMSKeeper
	if open == nil {
		keeper, err = openKeeper(ctx, provider)
	} else {
		keeper, err = open(ctx, provider)
	}
	if err != nil {
		return nil, err
	}
	return &gcpConfigEncrypter{keeper: keeper, stackKey: stackKey}, nil
}

func newWrappedDataKey(ctx context.Context, keeper dataKeyWrapper) (key, wrapped []byte, err error) {
	key = make([]byte, config.SymmetricCrypterKeyBytes)
	if _, err := rand.Read(key); err != nil {
		return nil, nil, err
	}
	wrapped, err = keeper.Encrypt(ctx, key)
	if err != nil {
		return nil, nil, err
	}
	return key, wrapped, nil
}

// The envelope stores a KMS-wrapped data key and a nonce-prefixed AES-GCM
// ciphertext. The wrapped stack key binds the value to its stack's encryption key.
type gcpConfigEncrypter struct {
	keeper    ConfigKMSKeeper
	stackKey  []byte
	useLegacy atomic.Bool
	legacyMu  sync.Mutex
	legacy    config.Encrypter
}

func (e *gcpConfigEncrypter) EncryptValue(ctx context.Context, plaintext string) (string, error) {
	var encryptErr error
	if !e.useLegacy.Load() {
		ciphertext, err := e.encryptEnvelope(ctx, plaintext)
		code := status.Code(err)
		// A disabled primary can prevent new wraps while an older version can still unwrap the stack key.
		if code != codes.PermissionDenied && code != codes.FailedPrecondition {
			return ciphertext, err
		}
		encryptErr = err
	}

	legacy, err := e.legacyEncrypter(ctx)
	if err != nil {
		if encryptErr != nil {
			return "", fmt.Errorf("KMS Encrypt failed (%w) and the stack key could not be decrypted: %w", encryptErr, err)
		}
		return "", err
	}
	e.useLegacy.Store(true)
	return legacy.EncryptValue(ctx, plaintext)
}

func (e *gcpConfigEncrypter) legacyEncrypter(ctx context.Context) (config.Encrypter, error) {
	e.legacyMu.Lock()
	defer e.legacyMu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if e.legacy != nil {
		return e.legacy, nil
	}
	key, err := e.keeper.Decrypt(ctx, e.stackKey)
	if err != nil {
		return nil, err
	}
	if len(key) != config.SymmetricCrypterKeyBytes {
		return nil, errors.New("invalid stack data key length")
	}
	e.legacy = config.NewSymmetricCrypter(key)
	return e.legacy, nil
}

func (e *gcpConfigEncrypter) encryptEnvelope(ctx context.Context, plaintext string) (string, error) {
	key, wrapped, err := newWrappedDataKey(ctx, e.keeper)
	if err != nil {
		return "", fmt.Errorf("wrapping config secret data key: %w", err)
	}
	aead, err := newConfigAEAD(key)
	if err != nil {
		return "", err
	}
	ciphertext := aead.Seal(nil, nil, []byte(plaintext), e.stackKey) //nolint:gosec // The AEAD generates a random nonce.
	return gcpConfigCiphertextPrefix + base64.StdEncoding.EncodeToString(wrapped) + ":" +
		base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (e *gcpConfigEncrypter) BatchEncrypt(ctx context.Context, plaintexts []string) ([]string, error) {
	return transformConfigBatch(ctx, plaintexts, e.EncryptValue)
}

type gcpConfigDecrypter struct {
	legacy   config.Decrypter
	keeper   dataKeyUnwrapper
	stackKey []byte
}

func (d gcpConfigDecrypter) DecryptValue(ctx context.Context, ciphertext string) (string, error) {
	envelope, ok := strings.CutPrefix(ciphertext, gcpConfigCiphertextPrefix)
	if !ok {
		return d.legacy.DecryptValue(ctx, ciphertext)
	}
	wrappedText, payloadText, ok := strings.Cut(envelope, ":")
	if !ok || wrappedText == "" || payloadText == "" {
		return "", errors.New("invalid GCP KMS config ciphertext")
	}
	wrapped, err := base64.StdEncoding.DecodeString(wrappedText)
	if err != nil {
		return "", fmt.Errorf("decoding wrapped config secret data key: %w", err)
	}
	payload, err := base64.StdEncoding.DecodeString(payloadText)
	if err != nil {
		return "", fmt.Errorf("decoding config secret ciphertext: %w", err)
	}
	if len(wrapped) == 0 || len(payload) < gcmNonceSize+gcmTagSize {
		return "", errors.New("invalid GCP KMS config ciphertext length")
	}
	key, err := d.keeper.Decrypt(ctx, wrapped)
	if err != nil {
		return "", fmt.Errorf("unwrapping config secret data key: %w", err)
	}
	aead, err := newConfigAEAD(key)
	if err != nil {
		return "", err
	}
	value, err := aead.Open(nil, nil, payload, d.stackKey)
	if err != nil {
		return "", fmt.Errorf("decrypting config secret: %w", err)
	}
	return string(value), nil
}

func (d gcpConfigDecrypter) BatchDecrypt(ctx context.Context, ciphertexts []string) ([]string, error) {
	if len(ciphertexts) == 0 {
		return nil, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for _, ciphertext := range ciphertexts {
		if strings.HasPrefix(ciphertext, gcpConfigCiphertextPrefix) {
			return transformConfigBatch(ctx, ciphertexts, d.DecryptValue)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	plaintexts, err := d.legacy.BatchDecrypt(ctx, ciphertexts)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return plaintexts, nil
}

// transformConfigBatch limits concurrent KMS requests and preserves input order.
func transformConfigBatch(
	ctx context.Context, values []string, transform func(context.Context, string) (string, error),
) ([]string, error) {
	switch len(values) {
	case 0:
		return nil, nil
	case 1:
		value, err := transform(ctx, values[0])
		if err != nil {
			return nil, err
		}
		return []string{value}, nil
	}

	result := make([]string, len(values))
	group, batchCtx := errgroup.WithContext(ctx)
	group.SetLimit(gcpConfigBatchConcurrency)
	for i, value := range values {
		if batchCtx.Err() != nil {
			break
		}
		group.Go(func() error {
			if err := batchCtx.Err(); err != nil {
				return err
			}
			var err error
			result[i], err = transform(batchCtx, value)
			return err
		})
	}
	if err := group.Wait(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func newConfigAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != config.SymmetricCrypterKeyBytes {
		return nil, errors.New("invalid config secret data key length")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}

// effectiveCloudSecretsProvider preserves the configured URL for equivalent GCP KMS overrides.
func effectiveCloudSecretsProvider(provider string) string {
	override := os.Getenv("PULUMI_CLOUD_SECRET_OVERRIDE")
	if override == "" || override == provider {
		return provider
	}
	configuredName, configuredAAD, configuredOK := gcpKMSProviderIdentity(provider)
	replacementName, replacementAAD, replacementOK := gcpKMSProviderIdentity(override)
	if configuredOK && replacementOK && configuredName == replacementName && configuredAAD == replacementAAD {
		return provider
	}
	return override
}

func gcpKMSProviderIdentity(provider string) (name, aad string, ok bool) {
	u := parseGCPKMSProvider(provider)
	if u == nil {
		return "", "", false
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return "", "", false
	}
	for key := range query {
		if key != "additional_authenticated_data" {
			return "", "", false
		}
	}
	data, err := base64.URLEncoding.DecodeString(query.Get("additional_authenticated_data"))
	if err != nil {
		return "", "", false
	}
	// The Cloud KMS driver joins the host and path to form the resource name.
	return path.Join(u.Host, u.Path), string(data), true
}
