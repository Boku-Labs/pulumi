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
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pulumi/pulumi/pkg/v3/backend"
	"github.com/pulumi/pulumi/pkg/v3/display"
	"github.com/pulumi/pulumi/sdk/v3/go/common/apitype"
	"github.com/pulumi/pulumi/sdk/v3/go/common/resource/config"
	"github.com/stretchr/testify/require"
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
	_, err = buildUpdatesJSON(ctx, updates, decrypter)
	require.ErrorIs(t, err, context.Canceled)
}

type historyBatchDecrypter struct {
	config.Decrypter
	batch func(context.Context, []string) ([]string, error)
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
