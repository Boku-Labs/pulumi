// Copyright 2025, Pulumi Corporation.
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

package stack

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/pulumi/pulumi/pkg/v3/backend"
	"github.com/pulumi/pulumi/pkg/v3/display"
	"github.com/pulumi/pulumi/sdk/v3/go/common/apitype"
	"github.com/pulumi/pulumi/sdk/v3/go/common/resource/config"
	"github.com/stretchr/testify/require"
	"gocloud.dev/gcerrors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestBuildUpdatesJSONWithFailedDecryptedSecureObject(t *testing.T) {
	t.Parallel()

	mockDecrypter := &failingDecrypter{}

	update := []backend.UpdateInfo{
		{
			Version:   1,
			Kind:      apitype.UpdateUpdate,
			StartTime: time.Now().Unix(),
			Message:   "Update with config that can't be decrypted",
			Environment: map[string]string{
				"PULUMI_ENV": "test",
			},
			Config: config.Map{
				config.MustMakeKey("test", "key2"): config.NewSecureObjectValue("object"),
			},
			Result:  backend.SucceededResult,
			EndTime: time.Now().Add(time.Minute).Unix(),
			ResourceChanges: display.ResourceChanges{
				display.StepOp(apitype.OpCreate): 1,
			},
		},
	}

	result, err := buildUpdatesJSON(t.Context(), update, mockDecrypter)
	require.NoError(t, err)
	require.Equal(t, errorDecryptingValue, *result[0].Config["test:key2"].Value)
}

func TestBuildUpdatesJSONBatchesSecretsAndCancels(t *testing.T) {
	t.Parallel()

	cfg := config.Map{
		config.MustMakeKey("test", "first"):  config.NewSecureValue("first"),
		config.MustMakeKey("test", "second"): config.NewSecureValue("second"),
	}
	updates := []backend.UpdateInfo{{Config: cfg}}
	calls := 0
	decrypter := historyBatchDecrypter{batch: func(_ context.Context, ciphertexts []string) ([]string, error) {
		calls++
		require.ElementsMatch(t, []string{"first", "second"}, ciphertexts)
		return ciphertexts, nil
	}}
	result, err := buildUpdatesJSON(t.Context(), updates, decrypter)
	require.NoError(t, err)
	require.Equal(t, 1, calls)
	require.Equal(t, "first", *result[0].Config["test:first"].Value)
	require.Equal(t, "second", *result[0].Config["test:second"].Value)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	decrypter.batch = func(ctx context.Context, _ []string) ([]string, error) {
		cancel()
		return nil, ctx.Err()
	}
	var out bytes.Buffer
	err = displayUpdatesJSON(ctx, &out, updates, decrypter)
	require.ErrorIs(t, err, context.Canceled)
	require.Empty(t, out.String())
}

func TestBuildUpdatesJSONDoesNotRetryProviderCancellation(t *testing.T) {
	t.Parallel()

	secret := config.MustMakeKey("test", "secret")
	object := config.MustMakeKey("test", "object")
	plain := config.MustMakeKey("test", "plain")
	updates := []backend.UpdateInfo{
		{Version: 3, Config: config.Map{secret: config.NewSecureValue("preceding")}},
		{Version: 2, Config: config.Map{
			secret: config.NewSecureValue("unavailable"),
			object: config.NewSecureObjectValue(`{"leaf":{"secure":"nested"},"sibling":"plain"}`),
			plain:  config.NewValue("public"),
		}},
		{Version: 1, Config: config.Map{secret: config.NewSecureValue("following")}},
	}
	for _, test := range []struct {
		name  string
		cause error
	}{
		{"cancellation", gcerrors.ErrCanceled},
		{"deadline", status.Error(codes.DeadlineExceeded, "KMS deadline expired")},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			retries := 0
			batches := 0
			decrypter := historyBatchDecrypter{
				individual: func(_ context.Context, value string) (string, error) {
					retries++
					return value, nil
				},
				batch: func(_ context.Context, ciphertexts []string) ([]string, error) {
					batches++
					if len(ciphertexts) == 2 {
						require.ElementsMatch(t, []string{"unavailable", "nested"}, ciphertexts)
						return nil, fmt.Errorf("decrypting configuration: %w", test.cause)
					}
					return []string{"decrypted " + ciphertexts[0]}, nil
				},
			}
			result, err := buildUpdatesJSON(t.Context(), updates, decrypter)
			require.NoError(t, err)
			require.Zero(t, retries)
			require.Equal(t, 3, batches)
			require.Len(t, result, 3)
			require.Equal(t, 3, result[0].Version)
			require.Equal(t, 2, result[1].Version)
			require.Equal(t, 1, result[2].Version)
			preceding := configValueJSON{Value: new("decrypted preceding"), Secret: true}
			require.Equal(t, preceding, result[0].Config["test:secret"])
			require.Equal(t, configValueJSON{Value: new("public")}, result[1].Config["test:plain"])
			unavailable := configValueJSON{Value: new(errorDecryptingValue), Secret: true}
			require.Equal(t, unavailable, result[1].Config["test:secret"])
			require.Equal(t, unavailable, result[1].Config["test:object"])
			following := configValueJSON{Value: new("decrypted following"), Secret: true}
			require.Equal(t, following, result[2].Config["test:secret"])
		})
	}
}

func TestBuildUpdatesJSONPreservesRetriesBeforeProviderDeadline(t *testing.T) {
	t.Parallel()

	updates := []backend.UpdateInfo{
		{Config: config.Map{
			config.MustMakeKey("test", "one"):   config.NewSecureValue("one"),
			config.MustMakeKey("test", "two"):   config.NewSecureValue("two"),
			config.MustMakeKey("test", "three"): config.NewSecureValue("three"),
		}},
		{Config: config.Map{config.MustMakeKey("test", "later"): config.NewSecureValue("later")}},
	}
	var retried []string
	decrypter := historyBatchDecrypter{
		individual: func(_ context.Context, value string) (string, error) {
			retried = append(retried, value)
			if len(retried) == 2 {
				return "", fmt.Errorf("retry deadline: %w", gcerrors.ErrDeadlineExceeded)
			}
			return "decrypted " + value, nil
		},
		batch: func(_ context.Context, ciphertexts []string) ([]string, error) {
			if len(ciphertexts) == 3 {
				return nil, errors.New("batch failure")
			}
			require.Equal(t, []string{"later"}, ciphertexts)
			return []string{"decrypted later"}, nil
		},
	}
	result, err := buildUpdatesJSON(t.Context(), updates, decrypter)
	require.NoError(t, err)
	require.Len(t, retried, 2)
	require.Len(t, result, 2)
	want := map[string]configValueJSON{
		"test:one":   {Value: new(errorDecryptingValue), Secret: true},
		"test:two":   {Value: new(errorDecryptingValue), Secret: true},
		"test:three": {Value: new(errorDecryptingValue), Secret: true},
	}
	want["test:"+retried[0]] = configValueJSON{Value: new("decrypted " + retried[0]), Secret: true}
	require.Equal(t, want, result[0].Config)
	require.Equal(t, configValueJSON{Value: new("decrypted later"), Secret: true}, result[1].Config["test:later"])
}

func TestDisplayUpdatesJSONCommandCancellationDuringRetry(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	updates := []backend.UpdateInfo{{Config: config.Map{
		config.MustMakeKey("test", "secret"): config.NewSecureValue("secret"),
	}}}
	retries := 0
	decrypter := historyBatchDecrypter{
		individual: func(callCtx context.Context, _ string) (string, error) {
			require.Same(t, ctx, callCtx)
			retries++
			cancel()
			return "", fmt.Errorf("retry deadline: %w", gcerrors.ErrDeadlineExceeded)
		},
		batch: func(context.Context, []string) ([]string, error) {
			return nil, errors.New("batch failure")
		},
	}
	var out bytes.Buffer
	err := displayUpdatesJSON(ctx, &out, updates, decrypter)
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, 1, retries)
	require.Empty(t, out.String())
}

type historyBatchDecrypter struct {
	individual func(context.Context, string) (string, error)
	batch      func(context.Context, []string) ([]string, error)
}

func (d historyBatchDecrypter) DecryptValue(ctx context.Context, ciphertext string) (string, error) {
	return d.individual(ctx, ciphertext)
}

func (d historyBatchDecrypter) BatchDecrypt(ctx context.Context, ciphertexts []string) ([]string, error) {
	return d.batch(ctx, ciphertexts)
}

type failingDecrypter struct{}

func (m *failingDecrypter) DecryptValue(ctx context.Context, ciphertext string) (string, error) {
	return ciphertext, errors.New("bad value")
}

func (m *failingDecrypter) BatchDecrypt(ctx context.Context, ciphertexts []string) ([]string, error) {
	return []string{}, errors.New("fake failure")
}
