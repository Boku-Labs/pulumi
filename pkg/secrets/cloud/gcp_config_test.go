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
	"crypto/rand"
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
	t.Setenv("PULUMI_CLOUD_SECRET_OVERRIDE", "")
	ctx := t.Context()
	keeper := newConfigTestKeeper(t)
	wrappedStackKey := wrapTestDataKey(t, keeper)

	encodedStackKey := base64.StdEncoding.EncodeToString(wrappedStackKey)
	ps := &workspace.ProjectStack{SecretsProvider: testGCPKMSURL, EncryptedKey: encodedStackKey}
	enc, err := openTestGCPConfigEncrypter(ctx, ps, keeper)
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
	manager, err := newCloudSecretsManagerWithKeeper(ctx, testGCPKMSURL, wrappedStackKey, keeper)
	require.NoError(t, err)
	legacy, err := manager.Encrypter().EncryptValue(ctx, "legacy")
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(legacy, "v1:"))
	require.True(t, strings.HasPrefix(ciphertexts[0], gcpConfigCiphertextPrefix))

	// Read both versions in a fresh manager, without relying on its plaintext cache.
	mixedCaseURL := strings.Replace(testGCPKMSURL, "gcpkms", "GcpKms", 1)
	reader, err := newCloudSecretsManagerWithKeeper(ctx, mixedCaseURL, wrappedStackKey, keeper)
	require.NoError(t, err)
	plaintexts, err := reader.Decrypter().BatchDecrypt(ctx, []string{legacy, ciphertexts[0]})
	require.NoError(t, err)
	require.Len(t, plaintexts, 2)
	assert.Equal(t, "legacy", plaintexts[0])
	assert.True(t, plaintexts[1] == value)
	assert.JSONEq(t, `{"url":"`+mixedCaseURL+`","encryptedkey":"`+encodedStackKey+`"}`, string(reader.State()))

	otherStackKey := wrapTestDataKey(t, keeper)
	otherStack, err := newCloudSecretsManagerWithKeeper(ctx, testGCPKMSURL, otherStackKey, keeper)
	require.NoError(t, err)
	_, err = otherStack.Decrypter().DecryptValue(ctx, ciphertexts[0])
	require.ErrorContains(t, err, "message authentication failed")
}

func TestGCPConfigRequiresInitializedStack(t *testing.T) {
	t.Setenv("PULUMI_CLOUD_SECRET_OVERRIDE", "")
	ctx := t.Context()
	ps := &workspace.ProjectStack{SecretsProvider: testGCPKMSURL}
	open := func(context.Context, string) (ConfigKMSKeeper, error) {
		t.Fatal("configuration without a valid wrapped stack key must not open a KMS client")
		return nil, nil
	}

	enc, err := NewConfigEncrypter(ctx, ps, open)
	require.NoError(t, err)
	assert.Nil(t, enc)
	assert.Empty(t, ps.EncryptedKey)

	ps.EncryptedKey = "invalid base64"
	enc, err = NewConfigEncrypter(ctx, ps, open)
	require.ErrorContains(t, err, "decoding wrapped stack key")
	assert.Nil(t, enc)
	assert.Equal(t, "invalid base64", ps.EncryptedKey)

	ps.EncryptedKey = "\n"
	enc, err = NewConfigEncrypter(ctx, ps, open)
	require.ErrorContains(t, err, "missing wrapped stack key")
	assert.Nil(t, enc)
}

func TestGCPConfigRejectsMalformedEnvelopeBeforeKMSCall(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	keeper := newConfigTestKeeper(t)
	reader := gcpConfigDecrypter{keeper: keeper}
	_, err := reader.DecryptValue(ctx, "v2:_:_")
	require.ErrorContains(t, err, "decoding wrapped config secret data key")
	_, err = reader.DecryptValue(ctx, "v2:YQ==:Yg==")
	require.ErrorContains(t, err, "invalid GCP KMS config ciphertext length")
	for _, size := range []int{maxGCPConfigWrappedKeySize + 1, maxGCPConfigWrappedKeySize + 3} {
		wrapped := base64.StdEncoding.EncodeToString(make([]byte, size))
		_, err = reader.DecryptValue(ctx, "v2:"+wrapped+":invalid payload")
		require.ErrorContains(t, err, "wrapped config secret data key exceeds the size limit")
	}
	assert.Zero(t, keeper.decrypts.Load())
}

func openTestGCPConfigEncrypter(
	ctx context.Context, ps *workspace.ProjectStack, keeper ConfigKMSKeeper,
) (config.Encrypter, error) {
	return NewConfigEncrypter(ctx, ps, func(context.Context, string) (ConfigKMSKeeper, error) {
		return keeper, nil
	})
}

func TestGCPConfigDecryptOnlyWriter(t *testing.T) {
	t.Setenv("PULUMI_CLOUD_SECRET_OVERRIDE", "")

	ctx := t.Context()
	keeper := newConfigTestKeeper(t)
	keeper.allowDecrypt = true

	wrappedStackKey := wrapTestDataKey(t, keeper)
	ps := &workspace.ProjectStack{
		SecretsProvider: testGCPKMSURL,
		EncryptedKey:    base64.StdEncoding.EncodeToString(wrappedStackKey),
	}
	enc, err := openTestGCPConfigEncrypter(ctx, ps, keeper)
	require.NoError(t, err)
	keeper.encryptErr = status.Error(codes.Unavailable, "KMS unavailable")
	ciphertext, err := enc.EncryptValue(ctx, "first value")
	require.NoError(t, err)

	keeper.encryptErr = status.Error(codes.PermissionDenied, "KMS Encrypt denied")
	more, err := enc.BatchEncrypt(ctx, []string{"second value", "third value"})
	require.NoError(t, err)
	assert.EqualValues(t, 4, keeper.encrypts.Load())
	assert.EqualValues(t, 3, keeper.decrypts.Load())

	key, err := keeper.Decrypt(ctx, wrappedStackKey)
	require.NoError(t, err)
	plaintexts, err := config.NewSymmetricCrypter(key).BatchDecrypt(ctx, append([]string{ciphertext}, more...))
	require.NoError(t, err)
	assert.Equal(t, []string{"first value", "second value", "third value"}, plaintexts)

	keeper.encryptErr = nil
	ciphertext, err = enc.EncryptValue(ctx, "KMS recovered")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(ciphertext, gcpConfigCiphertextPrefix))
	assert.EqualValues(t, 5, keeper.encrypts.Load())
	assert.EqualValues(t, 4, keeper.decrypts.Load())
}

func TestGCPConfigWriterUsesExistingStackKeyWhenPrimaryIsDisabled(t *testing.T) {
	t.Setenv("PULUMI_CLOUD_SECRET_OVERRIDE", "")

	ctx := t.Context()
	keeper := newConfigTestKeeper(t)
	wrappedStackKey := wrapTestDataKey(t, keeper)
	encodedStackKey := base64.StdEncoding.EncodeToString(wrappedStackKey)
	ps := &workspace.ProjectStack{SecretsProvider: testGCPKMSURL, EncryptedKey: encodedStackKey}
	enc, err := openTestGCPConfigEncrypter(ctx, ps, keeper)
	require.NoError(t, err)

	primaryDisabled := status.Error(codes.FailedPrecondition, "primary key version is disabled")
	keeper.encryptErr = primaryDisabled
	_, err = enc.EncryptValue(ctx, "no decryption permission")
	require.ErrorIs(t, err, primaryDisabled)
	require.ErrorIs(t, err, errTestConfigDecryptDenied)
	assert.EqualValues(t, 1, keeper.decrypts.Load())

	keeper.allowDecrypt = true
	ciphertext, err := enc.EncryptValue(ctx, "config value")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(ciphertext, "v1:"))
	assert.Equal(t, encodedStackKey, ps.EncryptedKey)
	assert.EqualValues(t, 2, keeper.decrypts.Load())

	reader, err := newCloudSecretsManagerWithKeeper(ctx, testGCPKMSURL, wrappedStackKey, keeper)
	require.NoError(t, err)
	plaintext, err := reader.Decrypter().DecryptValue(ctx, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, "config value", plaintext)
}

func TestGCPConfigWriterDoesNotFallBackOnCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	keeper := newConfigTestKeeper(t)
	keeper.encryptErr = status.Error(codes.Unavailable, "KMS unavailable")
	keeper.onEncrypt = cancel
	encrypter := &gcpConfigEncrypter{keeper: keeper, stackKey: []byte("wrapped stack key")}
	_, err := encrypter.EncryptValue(ctx, "secret")
	require.ErrorIs(t, err, context.Canceled)
	assert.EqualValues(t, 1, keeper.encrypts.Load())
	assert.Zero(t, keeper.decrypts.Load())

	_, err = encrypter.EncryptValue(ctx, "secret")
	require.ErrorIs(t, err, context.Canceled)
	assert.EqualValues(t, 1, keeper.encrypts.Load())
	assert.Zero(t, keeper.decrypts.Load())
}

type configUnwrapperFunc func(context.Context, []byte) ([]byte, error)

func (f configUnwrapperFunc) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	return f(ctx, ciphertext)
}

func TestGCPConfigDecryptChecksCancellationAfterUnwrap(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		batch bool
	}{
		{name: "individual value"},
		{name: "one-element batch", batch: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			keeper := newConfigTestKeeper(t)
			keeper.allowDecrypt = true
			encrypter := &gcpConfigEncrypter{keeper: keeper, stackKey: []byte("wrapped stack key")}
			ciphertext, err := encrypter.EncryptValue(t.Context(), "secret")
			require.NoError(t, err)

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			decrypter := gcpConfigDecrypter{
				keeper: configUnwrapperFunc(func(ctx context.Context, ciphertext []byte) ([]byte, error) {
					cancel()
					return keeper.Decrypt(ctx, ciphertext)
				}),
				stackKey: encrypter.stackKey,
			}
			if tc.batch {
				plaintexts, err := decrypter.BatchDecrypt(ctx, []string{ciphertext})
				require.ErrorIs(t, err, context.Canceled)
				assert.Nil(t, plaintexts)
			} else {
				plaintext, err := decrypter.DecryptValue(ctx, ciphertext)
				require.ErrorIs(t, err, context.Canceled)
				assert.Empty(t, plaintext)
			}
			assert.EqualValues(t, 1, keeper.decrypts.Load())
		})
	}
}

func TestGCPConfigBatchDecryptMixedDeduplicatesEnvelopes(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	keeper := newConfigTestKeeper(t)
	keeper.allowDecrypt = true
	encrypter := &gcpConfigEncrypter{keeper: keeper, stackKey: []byte("wrapped stack key")}
	first, err := encrypter.EncryptValue(ctx, "first")
	require.NoError(t, err)
	second, err := encrypter.EncryptValue(ctx, "second")
	require.NoError(t, err)

	legacyCalls := 0
	decrypter := gcpConfigDecrypter{
		keeper:   keeper,
		stackKey: encrypter.stackKey,
		legacy: legacyConfigBatchSpy{batch: func(_ context.Context, values []string) ([]string, error) {
			legacyCalls++
			assert.Equal(t, []string{"v1:one", "v1:two", "v1:one"}, values)
			return []string{"one", "two", "one"}, nil
		}},
	}
	plaintexts, err := decrypter.BatchDecrypt(ctx, []string{first, "v1:one", second, first, "v1:two", "v1:one", second})
	require.NoError(t, err)
	assert.Equal(t, []string{"first", "one", "second", "first", "two", "one", "second"}, plaintexts)
	assert.Equal(t, 1, legacyCalls)
	assert.EqualValues(t, 2, keeper.decrypts.Load())

	plaintexts, err = decrypter.BatchDecrypt(ctx, []string{second, second})
	require.NoError(t, err)
	assert.Equal(t, []string{"second", "second"}, plaintexts)
	assert.EqualValues(t, 3, keeper.decrypts.Load(), "only deduplicate within a batch")
}

type legacyConfigBatchSpy struct {
	batch func(context.Context, []string) ([]string, error)
}

func (d legacyConfigBatchSpy) DecryptValue(context.Context, string) (string, error) {
	return "", errors.New("unexpected individual legacy decryption")
}

func (d legacyConfigBatchSpy) BatchDecrypt(ctx context.Context, ciphertexts []string) ([]string, error) {
	return d.batch(ctx, ciphertexts)
}

func TestGCPConfigBatchDecryptLegacy(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name         string
		cancelBefore bool
		cancelDuring bool
		wantError    error
		wantCalls    int
	}{
		{name: "success", wantCalls: 1},
		{name: "already canceled", cancelBefore: true, wantError: context.Canceled},
		{name: "canceled during batch", cancelDuring: true, wantError: context.Canceled, wantCalls: 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tt.cancelBefore {
				cancel()
			}

			ciphertexts := []string{"v1:ciphertext1", "v1:ciphertext2", "v1:ciphertext3"}
			calls := 0
			decrypter := gcpConfigDecrypter{
				legacy: legacyConfigBatchSpy{
					batch: func(_ context.Context, batch []string) ([]string, error) {
						calls++
						assert.Equal(t, []string{"v1:ciphertext1", "v1:ciphertext2", "v1:ciphertext3"}, batch)
						if tt.cancelDuring {
							cancel()
						}
						return []string{"first", "", "third"}, nil
					},
				},
			}
			plaintexts, err := decrypter.BatchDecrypt(ctx, ciphertexts)
			assert.Equal(t, tt.wantCalls, calls)
			if tt.wantError != nil {
				require.ErrorIs(t, err, tt.wantError)
				assert.Nil(t, plaintexts)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, []string{"first", "", "third"}, plaintexts)
		})
	}
}

func TestGCPConfigBatchCancelsInFlightRequests(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	keeper := newConfigTestKeeper(t)
	encrypter := &gcpConfigEncrypter{keeper: keeper}
	values, err := encrypter.BatchEncrypt(ctx, make([]string, gcpConfigBatchConcurrency*2))
	require.NoError(t, err)
	started := make(chan struct{}, len(values))
	decrypter := gcpConfigDecrypter{
		keeper: configUnwrapperFunc(func(ctx context.Context, _ []byte) ([]byte, error) {
			started <- struct{}{}
			<-ctx.Done()
			return nil, ctx.Err()
		}),
	}
	result := make(chan error, 1)
	go func() {
		_, err := decrypter.BatchDecrypt(ctx, values)
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

func wrapTestDataKey(t *testing.T, keeper ConfigKMSKeeper) []byte {
	t.Helper()
	key := make([]byte, config.SymmetricCrypterKeyBytes)
	_, err := rand.Read(key)
	require.NoError(t, err)
	wrapped, err := keeper.Encrypt(t.Context(), key)
	require.NoError(t, err)
	return wrapped
}

var errTestConfigDecryptDenied = errors.New("KMS decryption permission denied")

type configTestKeeper struct {
	aead         cipher.AEAD
	allowDecrypt bool
	encryptErr   error
	onEncrypt    func()
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
	if k.onEncrypt != nil {
		k.onEncrypt()
	}
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
		return nil, errTestConfigDecryptDenied
	}
	return k.aead.Open(nil, nil, ciphertext, nil)
}
