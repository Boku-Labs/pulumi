// Copyright 2024, Pulumi Corporation.
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
	"encoding/json"
	"testing"

	"github.com/pulumi/pulumi/pkg/v3/backend"
	"github.com/pulumi/pulumi/pkg/v3/resource/deploy"
	resourceStack "github.com/pulumi/pulumi/pkg/v3/resource/stack"
	"github.com/pulumi/pulumi/pkg/v3/secrets"
	"github.com/pulumi/pulumi/pkg/v3/secrets/cloud"
	"github.com/pulumi/pulumi/pkg/v3/secrets/passphrase"
	"github.com/pulumi/pulumi/sdk/v3/go/common/resource/config"
	"github.com/pulumi/pulumi/sdk/v3/go/common/workspace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//nolint:paralleltest // Modifies the environment
func TestNewStackSecretsManagerLoaderFromEnv(t *testing.T) {
	// Arrange.
	cases := []struct {
		envValue string
		expected bool
	}{
		{"true", true},
		{"1", true},
		{"false", false},
		{"0", false},
	}

	for _, c := range cases {
		t.Setenv("PULUMI_FALLBACK_TO_STATE_SECRETS_MANAGER", c.envValue)

		// Act.
		loader := NewStackSecretsManagerLoaderFromEnv()

		// Assert.
		assert.Equal(
			t, c.expected, loader.FallbackToState,
			"FallbackToState (%v) should be pulled from the environment (%v)", c.envValue,
		)
	}
}

func TestStackSecretsManagerLoaderDecrypterFallsBack(t *testing.T) {
	t.Parallel()

	// Arrange.
	sm := &secrets.MockSecretsManager{
		TypeF: func() string { return "mock" },
		DecrypterF: func() config.Decrypter {
			return &secrets.MockDecrypter{DecryptValueF: func(_ string) string { return "defaulted plaintext" }}
		},
	}
	snap := &deploy.Snapshot{SecretsManager: sm}

	s := &backend.MockStack{
		RefF: func() backend.StackReference {
			return &backend.MockStackReference{FullyQualifiedNameV: "org/project/stack"}
		},
		SnapshotF: func(context.Context, secrets.Provider) (*deploy.Snapshot, error) {
			return snap, nil
		},
	}

	ps := &workspace.ProjectStack{}
	ssml := SecretsManagerLoader{FallbackToState: true}

	// Act.
	decrypter, state, err := ssml.GetDecrypter(t.Context(), s, ps)
	require.NoError(t, err)
	plaintext, err := decrypter.DecryptValue(t.Context(), "test")

	// Assert.
	//
	// We can't assert that the decrypter we get back is the one we returned since
	// it may be decorated (e.g. with a caching decrypter). We thus assert that
	// our fallback was called as a proxy.
	require.NoError(t, err)
	assert.Equal(
		t, SecretsManagerUnchanged, state,
		"A mock decrypter should have no effect on the project stack",
	)
	assert.Equal(t, plaintext, "defaulted plaintext", "Should have fallen back to the mock decrypter")
}

func TestStackSecretsManagerLoaderBindsCloudFallbackConfigContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	calls := 0
	decrypter := stackConfigTestDecrypter(func(ctx context.Context, values []string) ([]string, error) {
		calls++
		assert.Equal(t, []string{"v2:wrapped:payload"}, values)
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return []string{"secret"}, nil
	})
	stateManager := resourceStack.NewBatchingCachingSecretsManager(&secrets.MockSecretsManager{
		TypeF:      func() string { return cloud.Type },
		DecrypterF: func() config.Decrypter { return decrypter },
		StateF: func() json.RawMessage {
			return []byte(`{"url":"gcpkms://projects/fixture","encryptedkey":"a2V5"}`)
		},
	})
	s := &backend.MockStack{
		RefF: func() backend.StackReference {
			return &backend.MockStackReference{FullyQualifiedNameV: "org/project/stack"}
		},
		SnapshotF: func(context.Context, secrets.Provider) (*deploy.Snapshot, error) {
			return &deploy.Snapshot{SecretsManager: stateManager}, nil
		},
	}
	loader := SecretsManagerLoader{FallbackToState: true}
	projectStack := &workspace.ProjectStack{}
	wrapped, state, err := loader.GetDecrypter(ctx, s, projectStack)
	require.NoError(t, err)
	assert.Equal(t, SecretsManagerShouldSave, state)
	assert.Equal(t, "gcpkms://projects/fixture", projectStack.SecretsProvider)

	cancel()
	key := config.MustMakeKey("project", "secret")
	settings := config.Map{key: config.NewSecureValue("v2:wrapped:payload")}
	_, err = settings.Decrypt(wrapped)
	require.ErrorIs(t, err, context.Canceled)
	resolved, err := settings.Decrypt(stateManager.Decrypter())
	require.NoError(t, err)
	assert.Equal(t, "secret", resolved[key])
	assert.Equal(t, 2, calls)
}

type stackConfigTestDecrypter func(context.Context, []string) ([]string, error)

func (f stackConfigTestDecrypter) BatchDecrypt(ctx context.Context, ciphertexts []string) ([]string, error) {
	return f(ctx, ciphertexts)
}

func (f stackConfigTestDecrypter) DecryptValue(ctx context.Context, ciphertext string) (string, error) {
	values, err := f(ctx, []string{ciphertext})
	if err != nil {
		return "", err
	}
	return values[0], nil
}

func TestStackSecretsManagerLoaderDecrypterUpdatesConfig(t *testing.T) {
	t.Parallel()

	// Arrange.
	sm := &secrets.MockSecretsManager{
		TypeF:      func() string { return passphrase.Type },
		DecrypterF: func() config.Decrypter { return config.NopDecrypter },
		StateF:     func() json.RawMessage { return []byte(`{"salt":"test-salt"}`) },
	}
	snap := &deploy.Snapshot{SecretsManager: sm}

	s := &backend.MockStack{
		RefF: func() backend.StackReference {
			return &backend.MockStackReference{FullyQualifiedNameV: "org/project/stack"}
		},
		SnapshotF: func(context.Context, secrets.Provider) (*deploy.Snapshot, error) {
			return snap, nil
		},
	}

	ps := &workspace.ProjectStack{}
	ssml := SecretsManagerLoader{FallbackToState: true}

	// Act.
	_, state, err := ssml.GetDecrypter(t.Context(), s, ps)

	// Assert.
	require.NoError(t, err)
	assert.Equal(
		t, SecretsManagerShouldSave, state,
		"A fallback passphrase decrypter should be written to the project stack",
	)
	assert.Equal(t, "test-salt", ps.EncryptionSalt, "The encryption salt should be set on the project stack")
}

func TestStackSecretsManagerLoaderDecrypterUsesDefaultSecretsManager(t *testing.T) {
	t.Parallel()

	// Arrange.
	sm := &secrets.MockSecretsManager{
		TypeF: func() string { return "mock" },
		DecrypterF: func() config.Decrypter {
			return &secrets.MockDecrypter{DecryptValueF: func(_ string) string { return "defaulted plaintext" }}
		},
	}

	s := &backend.MockStack{
		RefF: func() backend.StackReference {
			return &backend.MockStackReference{FullyQualifiedNameV: "org/project/stack"}
		},
		DefaultSecretManagerF: func(_ context.Context, info *workspace.ProjectStack) (secrets.Manager, error) {
			return sm, nil
		},
		SnapshotF: func(context.Context, secrets.Provider) (*deploy.Snapshot, error) {
			return &deploy.Snapshot{}, nil
		},
	}

	ps := &workspace.ProjectStack{}
	ssml := SecretsManagerLoader{FallbackToState: false}

	// Act.
	decrypter, state, err := ssml.GetDecrypter(t.Context(), s, ps)
	require.NoError(t, err)
	plaintext, err := decrypter.DecryptValue(t.Context(), "test")

	// Assert.
	require.NoError(t, err)
	assert.Equal(
		t, SecretsManagerUnchanged, state,
		"No fallback manager should mean no changes to the project stack",
	)
	assert.Equal(t, plaintext, "defaulted plaintext", "Should have loaded the default decrypter")
}

func TestStackSecretsManagerLoaderEncrypterFallsBack(t *testing.T) {
	t.Parallel()

	// Arrange.
	sm := &secrets.MockSecretsManager{
		TypeF: func() string { return "mock" },
		EncrypterF: func() config.Encrypter {
			return &secrets.MockEncrypter{EncryptValueF: func(_ string) string { return "defaulted ciphertext" }}
		},
	}
	snap := &deploy.Snapshot{SecretsManager: sm}

	s := &backend.MockStack{
		RefF: func() backend.StackReference {
			return &backend.MockStackReference{FullyQualifiedNameV: "org/project/stack"}
		},
		SnapshotF: func(context.Context, secrets.Provider) (*deploy.Snapshot, error) {
			return snap, nil
		},
	}

	ps := &workspace.ProjectStack{}
	ssml := SecretsManagerLoader{FallbackToState: true}

	// Act.
	encrypter, state, err := ssml.GetEncrypter(t.Context(), s, ps)
	require.NoError(t, err)
	ciphertext, err := encrypter.EncryptValue(t.Context(), "test")

	// Assert.
	//
	// We can't assert that the encrypter we get back is the one we returned since
	// it may be decorated (e.g. with a caching encrypter). We thus assert that
	// our fallback was called as a proxy.
	require.NoError(t, err)
	assert.Equal(
		t, SecretsManagerUnchanged, state,
		"A mock encrypter should have no effect on the project stack",
	)
	assert.Equal(t, ciphertext, "defaulted ciphertext", "Should have fallen back to the mock encrypter")
}

func TestStackSecretsManagerLoaderEncrypterUpdatesConfig(t *testing.T) {
	t.Parallel()

	// Arrange.
	sm := &secrets.MockSecretsManager{
		TypeF:      func() string { return passphrase.Type },
		EncrypterF: func() config.Encrypter { return config.NopEncrypter },
		StateF:     func() json.RawMessage { return []byte(`{"salt":"test-salt"}`) },
	}
	snap := &deploy.Snapshot{SecretsManager: sm}

	s := &backend.MockStack{
		RefF: func() backend.StackReference {
			return &backend.MockStackReference{FullyQualifiedNameV: "org/project/stack"}
		},
		SnapshotF: func(context.Context, secrets.Provider) (*deploy.Snapshot, error) {
			return snap, nil
		},
	}

	ps := &workspace.ProjectStack{}
	ssml := SecretsManagerLoader{FallbackToState: true}

	// Act.
	_, state, err := ssml.GetEncrypter(t.Context(), s, ps)

	// Assert.
	require.NoError(t, err)
	assert.Equal(
		t, SecretsManagerShouldSave, state,
		"A fallback passphrase encrypter should be written to the project stack",
	)
	assert.Equal(t, "test-salt", ps.EncryptionSalt, "The encryption salt should be set on the project stack")
}

func TestStackSecretsManagerLoaderEncrypterUsesDefaultSecretsManager(t *testing.T) {
	t.Parallel()

	// Arrange.
	sm := &secrets.MockSecretsManager{
		TypeF: func() string { return "mock" },
		EncrypterF: func() config.Encrypter {
			return &secrets.MockEncrypter{EncryptValueF: func(_ string) string { return "defaulted ciphertext" }}
		},
	}

	s := &backend.MockStack{
		RefF: func() backend.StackReference {
			return &backend.MockStackReference{FullyQualifiedNameV: "org/project/stack"}
		},
		DefaultSecretManagerF: func(_ context.Context, info *workspace.ProjectStack) (secrets.Manager, error) {
			return sm, nil
		},
		SnapshotF: func(context.Context, secrets.Provider) (*deploy.Snapshot, error) {
			return &deploy.Snapshot{}, nil
		},
	}

	ps := &workspace.ProjectStack{}
	ssml := SecretsManagerLoader{FallbackToState: false}

	// Act.
	encrypter, state, err := ssml.GetEncrypter(t.Context(), s, ps)
	require.NoError(t, err)
	ciphertext, err := encrypter.EncryptValue(t.Context(), "test")

	// Assert.
	require.NoError(t, err)
	assert.Equal(
		t, SecretsManagerUnchanged, state,
		"No fallback manager should mean no changes to the project stack",
	)
	assert.Equal(t, ciphertext, "defaulted ciphertext", "Should have used the default encrypter")
}
