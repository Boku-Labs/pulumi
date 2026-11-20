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
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/pulumi/pulumi/sdk/v3/go/common/resource/config"
	"github.com/pulumi/pulumi/sdk/v3/go/common/workspace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testGCPKMSURL = "gcpkms://projects/example/locations/global/keyRings/test/cryptoKeys/test"

func TestGCPConfigEncryptOnly(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	keeper := newConfigTestKeeper(t)
	_, wrappedStackKey, err := newWrappedDataKey(ctx, keeper)
	require.NoError(t, err)

	encodedStackKey := base64.StdEncoding.EncodeToString(wrappedStackKey)
	ps := &workspace.ProjectStack{SecretsProvider: testGCPKMSURL, EncryptedKey: encodedStackKey}
	enc, err := newGCPConfigEncrypter(ctx, ps, keeper)
	require.NoError(t, err)
	// The value is too large for a direct Cloud KMS Encrypt call.
	value := strings.Repeat("value", 14_000)
	ciphertexts, err := enc.BatchEncrypt(ctx, []string{value, value})
	require.NoError(t, err)
	require.Len(t, ciphertexts, 2)
	assert.NotEqual(t, ciphertexts[0], ciphertexts[1])
	assert.Equal(t, encodedStackKey, ps.EncryptedKey)
	assert.Equal(t, 3, keeper.encrypts)
	assert.Zero(t, keeper.decrypts)

	keeper.allowDecrypt = true
	manager, err := newCloudSecretsManagerWithKeeper(testGCPKMSURL, wrappedStackKey, keeper)
	require.NoError(t, err)
	legacy, err := manager.Encrypter().EncryptValue(ctx, "legacy")
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(legacy, "v1:"))
	require.True(t, strings.HasPrefix(ciphertexts[0], gcpConfigCiphertextPrefix))

	// Read both versions in a fresh manager, without relying on its plaintext cache.
	reader, err := newCloudSecretsManagerWithKeeper(testGCPKMSURL, wrappedStackKey, keeper)
	require.NoError(t, err)
	plaintexts, err := reader.Decrypter().BatchDecrypt(ctx, []string{legacy, ciphertexts[0]})
	require.NoError(t, err)
	require.Len(t, plaintexts, 2)
	assert.Equal(t, "legacy", plaintexts[0])
	assert.True(t, plaintexts[1] == value)
	assert.JSONEq(t, `{"url":"`+testGCPKMSURL+`","encryptedkey":"`+encodedStackKey+`"}`, string(reader.State()))

	_, otherStackKey, err := newWrappedDataKey(ctx, keeper)
	require.NoError(t, err)
	otherStack, err := newCloudSecretsManagerWithKeeper(testGCPKMSURL, otherStackKey, keeper)
	require.NoError(t, err)
	_, err = otherStack.Decrypter().DecryptValue(ctx, ciphertexts[0])
	require.ErrorContains(t, err, "message authentication failed")
}

func TestGCPConfigInitializesStackKeyWithoutDecryption(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	keeper := newConfigTestKeeper(t)
	ps := &workspace.ProjectStack{SecretsProvider: testGCPKMSURL}
	enc, err := newGCPConfigEncrypter(ctx, ps, keeper)
	require.NoError(t, err)
	require.NotEmpty(t, ps.EncryptedKey)
	ciphertext, err := enc.EncryptValue(ctx, "first secret")
	require.NoError(t, err)
	assert.Equal(t, 2, keeper.encrypts)
	assert.Zero(t, keeper.decrypts)

	keeper.allowDecrypt = true
	stackKey, err := base64.StdEncoding.DecodeString(ps.EncryptedKey)
	require.NoError(t, err)
	reader, err := newCloudSecretsManagerWithKeeper(testGCPKMSURL, stackKey, keeper)
	require.NoError(t, err)
	plaintext, err := reader.Decrypter().DecryptValue(ctx, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, "first secret", plaintext)
	_, err = reader.Decrypter().DecryptValue(ctx, "v2:_:_")
	require.ErrorContains(t, err, "decoding wrapped config secret data key")
}

type configTestKeeper struct {
	aead         cipher.AEAD
	allowDecrypt bool
	encrypts     int
	decrypts     int
}

func newConfigTestKeeper(t *testing.T) *configTestKeeper {
	t.Helper()
	aead, err := newConfigAEAD(make([]byte, config.SymmetricCrypterKeyBytes))
	require.NoError(t, err)
	return &configTestKeeper{aead: aead}
}

func (k *configTestKeeper) Encrypt(_ context.Context, plaintext []byte) ([]byte, error) {
	k.encrypts++
	if len(plaintext) != config.SymmetricCrypterKeyBytes {
		return nil, errors.New("the KMS client expected only a data key")
	}
	return k.aead.Seal(nil, nil, plaintext, nil), nil //nolint:gosec // The AEAD generates a random nonce.
}

func (k *configTestKeeper) Decrypt(_ context.Context, ciphertext []byte) ([]byte, error) {
	k.decrypts++
	if !k.allowDecrypt {
		return nil, errors.New("KMS decryption permission denied")
	}
	return k.aead.Open(nil, nil, ciphertext, nil)
}
