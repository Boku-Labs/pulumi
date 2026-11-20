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
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

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
	assert.EqualValues(t, 3, keeper.encrypts.Load())
	assert.Zero(t, keeper.decrypts.Load())

	keeper.allowDecrypt = true
	manager, err := newCloudSecretsManagerWithKeeper(testGCPKMSURL, wrappedStackKey, keeper)
	require.NoError(t, err)
	legacy, err := manager.Encrypter().EncryptValue(ctx, "legacy")
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(legacy, "v1:"))
	require.True(t, strings.HasPrefix(ciphertexts[0], gcpConfigCiphertextPrefix))

	// Read both versions in a fresh manager, without relying on its plaintext cache.
	mixedCaseURL := strings.Replace(testGCPKMSURL, "gcpkms", "GcpKms", 1)
	reader, err := newCloudSecretsManagerWithKeeper(mixedCaseURL, wrappedStackKey, keeper)
	require.NoError(t, err)
	plaintexts, err := reader.Decrypter().BatchDecrypt(ctx, []string{legacy, ciphertexts[0]})
	require.NoError(t, err)
	require.Len(t, plaintexts, 2)
	assert.Equal(t, "legacy", plaintexts[0])
	assert.True(t, plaintexts[1] == value)
	assert.JSONEq(t, `{"url":"`+mixedCaseURL+`","encryptedkey":"`+encodedStackKey+`"}`, string(reader.State()))

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
	assert.EqualValues(t, 2, keeper.encrypts.Load())
	assert.Zero(t, keeper.decrypts.Load())

	keeper.allowDecrypt = true
	stackKey, err := base64.StdEncoding.DecodeString(ps.EncryptedKey)
	require.NoError(t, err)
	reader, err := newCloudSecretsManagerWithKeeper(testGCPKMSURL, stackKey, keeper)
	require.NoError(t, err)
	plaintext, err := reader.Decrypter().DecryptValue(ctx, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, "first secret", plaintext)
	decrypts := keeper.decrypts.Load()
	_, err = reader.Decrypter().DecryptValue(ctx, "v2:_:_")
	require.ErrorContains(t, err, "decoding wrapped config secret data key")
	_, err = reader.Decrypter().DecryptValue(ctx, "v2:YQ==:Yg==")
	require.ErrorContains(t, err, "invalid GCP KMS config ciphertext length")
	assert.Equal(t, decrypts, keeper.decrypts.Load())
}

func TestGCPConfigDecryptOnlyWriter(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	keeper := newConfigTestKeeper(t)
	keeper.allowDecrypt = true

	_, wrappedStackKey, err := newWrappedDataKey(ctx, keeper)
	require.NoError(t, err)
	ps := &workspace.ProjectStack{
		SecretsProvider: testGCPKMSURL,
		EncryptedKey:    base64.StdEncoding.EncodeToString(wrappedStackKey),
	}
	enc, err := newGCPConfigEncrypter(ctx, ps, keeper)
	require.NoError(t, err)
	keeper.encryptErr = status.Error(codes.Unavailable, "KMS unavailable")
	_, err = enc.EncryptValue(ctx, "transient failure")
	require.Equal(t, codes.Unavailable, status.Code(err))
	assert.Zero(t, keeper.decrypts.Load())

	keeper.encryptErr = status.Error(codes.PermissionDenied, "KMS Encrypt denied")
	ciphertext, err := enc.EncryptValue(ctx, "first value")
	require.NoError(t, err)
	more, err := enc.BatchEncrypt(ctx, []string{"second value", "third value"})
	require.NoError(t, err)
	assert.EqualValues(t, 3, keeper.encrypts.Load())
	assert.EqualValues(t, 1, keeper.decrypts.Load())

	key, err := keeper.Decrypt(ctx, wrappedStackKey)
	require.NoError(t, err)
	plaintexts, err := config.NewSymmetricCrypter(key).BatchDecrypt(ctx, append([]string{ciphertext}, more...))
	require.NoError(t, err)
	assert.Equal(t, []string{"first value", "second value", "third value"}, plaintexts)
}

func TestGCPConfigBatchCancelsInFlightRequests(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	values := make([]string, gcpConfigBatchConcurrency*2)
	started := make(chan struct{}, len(values))
	result := make(chan error, 1)
	go func() {
		_, err := transformConfigBatch(ctx, values, func(ctx context.Context, _ string) (string, error) {
			started <- struct{}{}
			<-ctx.Done()
			return "", ctx.Err()
		})
		result <- err
	}()

	for range gcpConfigBatchConcurrency {
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("expected concurrent KMS requests")
		}
	}
	cancel()
	select {
	case err := <-result:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("KMS requests did not stop after cancellation")
	}
	require.Empty(t, started, "cancellation should prevent further KMS requests")
}

type configTestKeeper struct {
	aead         cipher.AEAD
	allowDecrypt bool
	encryptErr   error
	encrypts     atomic.Int32
	decrypts     atomic.Int32
}

func newConfigTestKeeper(t *testing.T) *configTestKeeper {
	t.Helper()
	aead, err := newConfigAEAD(make([]byte, config.SymmetricCrypterKeyBytes))
	require.NoError(t, err)
	return &configTestKeeper{aead: aead}
}

func (k *configTestKeeper) Encrypt(_ context.Context, plaintext []byte) ([]byte, error) {
	k.encrypts.Add(1)
	if k.encryptErr != nil {
		return nil, k.encryptErr
	}
	if len(plaintext) != config.SymmetricCrypterKeyBytes {
		return nil, errors.New("the KMS client expected only a data key")
	}
	return k.aead.Seal(nil, nil, plaintext, nil), nil //nolint:gosec // The AEAD generates a random nonce.
}

func (k *configTestKeeper) Decrypt(_ context.Context, ciphertext []byte) ([]byte, error) {
	k.decrypts.Add(1)
	if !k.allowDecrypt {
		return nil, errors.New("KMS decryption permission denied")
	}
	return k.aead.Open(nil, nil, ciphertext, nil)
}
