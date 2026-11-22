// Copyright 2020, Pulumi Corporation.
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

package engine

import (
	"context"
	"errors"
	"testing"

	"github.com/pulumi/pulumi/sdk/v3/go/common/diag"
	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/common/resource/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type eventTestDecrypter struct {
	config.Decrypter
	batch func(context.Context, []string) ([]string, error)
}

func (d eventTestDecrypter) BatchDecrypt(ctx context.Context, ciphertexts []string) ([]string, error) {
	return d.batch(ctx, ciphertexts)
}

func TestTrySendEvent(t *testing.T) {
	t.Parallel()
	e := Event{}
	c := make(chan Event, 100)
	assert.Equal(t, true, trySendEvent(c, e))
	close(c)
	assert.Equal(t, false, trySendEvent(c, e))
}

func TestTryCloseEventChan(t *testing.T) {
	t.Parallel()
	c := make(chan Event, 100)
	assert.Equal(t, true, tryCloseEventChan(c))
	assert.Equal(t, false, tryCloseEventChan(c))
}

func TestDiagEventReportsExistsURNAtStackLevel(t *testing.T) {
	t.Parallel()

	c := make(chan Event, 2)
	e := eventEmitter{ch: c}

	urn := resource.URN("urn:pulumi:stack::project::pkgA:m:typA::__exists__1")
	diagEvent(&e, diag.Message(urn, "exists"), "", "exists", diag.Warning, false)
	assert.Equal(t, resource.URN(""), (<-c).Payload().(DiagEventPayload).URN)

	urn = resource.URN("urn:pulumi:stack::project::pkgA:m:typA::res")
	diagEvent(&e, diag.Message(urn, "resource"), "", "resource", diag.Warning, false)
	assert.Equal(t, urn, (<-c).Payload().(DiagEventPayload).URN)
}

func TestUpdateStartedEventIsInternal(t *testing.T) {
	t.Parallel()

	e := NewEvent(UpdateStartedEventPayload{
		UpdateID:  "update-1",
		Version:   3,
		Permalink: "https://app.pulumi.com/org/proj/stack/updates/3",
	})

	assert.Equal(t, UpdateStartedEvent, e.Type)
	assert.True(t, e.Internal())
}

func TestConfigSecretsForRedaction(t *testing.T) {
	t.Parallel()

	t.Run("secure leaves", func(t *testing.T) {
		t.Parallel()

		cfg := config.Map{
			config.MustMakeKey("test", "scalar"): config.NewSecureValue("scalar"),
			config.MustMakeKey("test", "nested"): config.NewSecureObjectValue(
				`{"map":{"array":[{"secure":"nested"},"plain",{"secure":"nested"},{"secure":""}]},"other":"plain"}`,
			),
			config.MustMakeKey("test", "plain"): config.NewValue("plaintext sibling"),
		}
		calls := 0
		decrypter := eventTestDecrypter{
			Decrypter: config.NewPanicCrypter(),
			batch: func(ctx context.Context, ciphertexts []string) ([]string, error) {
				calls++
				assert.Equal(t, t.Context(), ctx)
				assert.Contains(t, [][]string{
					{"scalar", "nested", "nested", ""},
					{"nested", "nested", "", "scalar"},
				}, ciphertexts)
				plaintext := map[string]string{"scalar": "top-level secret", "nested": "nested secret", "": ""}
				result := make([]string, len(ciphertexts))
				for i, ciphertext := range ciphertexts {
					result[i] = plaintext[ciphertext]
				}
				return result, nil
			},
		}
		plaintexts, err := configSecretsForRedaction(t.Context(), cfg, decrypter)
		require.NoError(t, err)
		assert.Equal(t, 1, calls)
		assert.ElementsMatch(t, []string{"top-level secret", "nested secret", "nested secret", ""}, plaintexts)
	})

	t.Run("no secure leaves", func(t *testing.T) {
		t.Parallel()

		cfg := config.Map{
			config.MustMakeKey("test", "object"): config.NewSecureObjectValue(`{"array":["plain"]}`),
		}
		plaintexts, err := configSecretsForRedaction(t.Context(), cfg, config.NewPanicCrypter())
		require.NoError(t, err)
		assert.Empty(t, plaintexts)
	})

	t.Run("malformed secure object", func(t *testing.T) {
		t.Parallel()

		key := config.MustMakeKey("test", "malformed")
		cfg := config.Map{
			key:                                  config.NewSecureObjectValue(`{"array":[`),
			config.MustMakeKey("test", "scalar"): config.NewSecureValue("scalar"),
		}
		plaintexts, err := configSecretsForRedaction(t.Context(), cfg, config.NewPanicCrypter())
		var decryptErr DecryptError
		require.ErrorAs(t, err, &decryptErr)
		assert.Equal(t, key, decryptErr.Key)
		assert.Nil(t, plaintexts)
	})
}

func TestConfigSecretsForRedactionRetriesByKey(t *testing.T) {
	t.Parallel()

	scalar := config.MustMakeKey("test", "scalar")
	nested := config.MustMakeKey("test", "nested")
	cfg := config.Map{
		scalar: config.NewSecureValue("scalar"),
		nested: config.NewSecureObjectValue(
			`{"array":[{"secure":"nested"},"plain",{"secure":"nested"},{"secure":""}]}`,
		),
		config.MustMakeKey("test", "plain"): config.NewValue("plaintext config"),
	}
	for _, test := range []struct {
		name        string
		failRetry   bool
		cancelRetry bool
	}{
		{name: "recover"},
		{name: "invalid response on second retry", failRetry: true},
		{name: "cancellation on second retry", cancelRetry: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var batches [][]string
			decrypter := eventTestDecrypter{
				Decrypter: config.NewPanicCrypter(),
				batch: func(batchCtx context.Context, ciphertexts []string) ([]string, error) {
					assert.Equal(t, ctx, batchCtx)
					batches = append(batches, ciphertexts)
					if len(batches) == 1 {
						assert.ElementsMatch(t, []string{"scalar", "nested", "nested", ""}, ciphertexts)
						return []string{"discarded aggregate value"}, errors.New("aggregate decryption failed")
					}
					if len(batches) == 3 {
						if test.failRetry {
							return nil, nil
						}
						if test.cancelRetry {
							cancel()
						}
					}
					if len(ciphertexts) == 1 {
						return []string{"scalar secret"}, nil
					}
					return []string{"nested secret", "nested secret", ""}, nil
				},
			}
			plaintexts, err := configSecretsForRedaction(ctx, cfg, decrypter)
			require.Len(t, batches, 3)
			require.ElementsMatch(t, [][]string{{"scalar"}, {"nested", "nested", ""}}, batches[1:])
			switch {
			case test.failRetry:
				var decryptErr DecryptError
				require.ErrorAs(t, err, &decryptErr)
				keys := map[string]config.Key{"scalar": scalar, "nested": nested}
				assert.Equal(t, keys[batches[2][0]], decryptErr.Key)
				assert.ErrorContains(t, decryptErr.Err, "config decryption batch returned 0 plaintexts, expected")
				assert.Nil(t, plaintexts)
			case test.cancelRetry:
				require.ErrorIs(t, err, context.Canceled)
				assert.Nil(t, plaintexts)
			default:
				require.NoError(t, err)
				assert.Contains(t, [][]string{
					{"scalar secret", "nested secret", "nested secret", ""},
					{"nested secret", "nested secret", "", "scalar secret"},
				}, plaintexts)
			}
		})
	}
}

func TestBatchDecryptConfigSecrets(t *testing.T) {
	t.Parallel()

	t.Run("packing and order", func(t *testing.T) {
		t.Parallel()

		var batches [][]string
		decrypter := eventTestDecrypter{
			batch: func(ctx context.Context, ciphertexts []string) ([]string, error) {
				assert.Equal(t, t.Context(), ctx)
				batches = append(batches, ciphertexts)
				plaintexts := make([]string, len(ciphertexts))
				for i, ciphertext := range ciphertexts {
					plaintexts[i] = "plain:" + ciphertext
				}
				return plaintexts, nil
			},
		}
		ciphertexts := []string{"", "ab", "cd", "", "oversized", "", "e", "fgh"}
		plaintexts, err := batchDecryptConfigSecrets(t.Context(), decrypter, ciphertexts, 4)
		require.NoError(t, err)
		assert.Equal(t, [][]string{{"", "ab", "cd", ""}, {"oversized"}, {"", "e", "fgh"}}, batches)
		assert.Equal(t, []string{
			"plain:", "plain:ab", "plain:cd", "plain:", "plain:oversized",
			"plain:", "plain:e", "plain:fgh",
		}, plaintexts)
	})

	t.Run("cancellation", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		calls := 0
		decrypter := eventTestDecrypter{
			batch: func(batchCtx context.Context, _ []string) ([]string, error) {
				assert.Equal(t, ctx, batchCtx)
				calls++
				cancel()
				return []string{"first secret"}, nil
			},
		}
		plaintexts, err := batchDecryptConfigSecrets(ctx, decrypter, []string{"ab", "cd"}, 2)
		require.ErrorIs(t, err, context.Canceled)
		assert.Nil(t, plaintexts)
		assert.Equal(t, 1, calls)
	})

	t.Run("result length mismatch", func(t *testing.T) {
		t.Parallel()

		calls := 0
		decrypter := eventTestDecrypter{
			batch: func(context.Context, []string) ([]string, error) {
				calls++
				if calls == 1 {
					return []string{"first secret"}, nil
				}
				return nil, nil
			},
		}
		plaintexts, err := batchDecryptConfigSecrets(t.Context(), decrypter, []string{"ab", "cd", "ef"}, 2)
		require.EqualError(t, err, "config decryption batch returned 0 plaintexts, expected 1")
		assert.Nil(t, plaintexts)
		assert.Equal(t, 2, calls)
	})
}
