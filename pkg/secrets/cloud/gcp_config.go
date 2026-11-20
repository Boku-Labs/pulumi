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
	"os"
	"strings"

	"github.com/pulumi/pulumi/sdk/v3/go/common/resource/config"
	"github.com/pulumi/pulumi/sdk/v3/go/common/workspace"
)

const (
	gcpKMSScheme              = "gcpkms://"
	gcpConfigCiphertextPrefix = "v2:"
)

type dataKeyWrapper interface {
	Encrypt(context.Context, []byte) ([]byte, error)
}

type dataKeyUnwrapper interface {
	Decrypt(context.Context, []byte) ([]byte, error)
}

// NewConfigEncrypter returns an encrypt-only config writer for a GCP KMS stack.
// It returns nil for stacks that use the regular secrets manager.
func NewConfigEncrypter(ctx context.Context, ps *workspace.ProjectStack) (config.Encrypter, error) {
	if !strings.HasPrefix(ps.SecretsProvider, gcpKMSScheme) || os.Getenv("PULUMI_CLOUD_SECRET_OVERRIDE") != "" {
		return nil, nil
	}
	keeper, err := openKeeper(ctx, ps.SecretsProvider)
	if err != nil {
		return nil, err
	}
	return newGCPConfigEncrypter(ctx, ps, keeper)
}

func newGCPConfigEncrypter(
	ctx context.Context, ps *workspace.ProjectStack, keeper dataKeyWrapper,
) (config.Encrypter, error) {
	stackKey, err := base64.StdEncoding.DecodeString(ps.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("decoding wrapped stack key: %w", err)
	}
	if ps.EncryptedKey == "" {
		_, stackKey, err = newWrappedDataKey(ctx, keeper)
		if err != nil {
			return nil, fmt.Errorf("wrapping stack key: %w", err)
		}
		ps.EncryptedKey = base64.StdEncoding.EncodeToString(stackKey)
	}
	if len(stackKey) == 0 {
		return nil, errors.New("missing wrapped stack key")
	}
	ps.EncryptionSalt = ""
	return gcpConfigEncrypter{keeper: keeper, stackKey: stackKey}, nil
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
	keeper   dataKeyWrapper
	stackKey []byte
}

func (e gcpConfigEncrypter) EncryptValue(ctx context.Context, plaintext string) (string, error) {
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

func (e gcpConfigEncrypter) BatchEncrypt(ctx context.Context, plaintexts []string) ([]string, error) {
	return config.DefaultBatchEncrypt(ctx, e, plaintexts)
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
	return config.DefaultBatchDecrypt(ctx, d, ciphertexts)
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
