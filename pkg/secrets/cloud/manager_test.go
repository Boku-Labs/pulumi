// Copyright 2016, Pulumi Corporation.
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
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/pulumi/pulumi/pkg/v3/secrets"
	"github.com/pulumi/pulumi/sdk/v3/go/common/resource/config"
	"github.com/pulumi/pulumi/sdk/v3/go/common/workspace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gosecrets "gocloud.dev/secrets"
	"gocloud.dev/secrets/driver"
	"gocloud.dev/secrets/gcpkms"
	"golang.org/x/oauth2"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

// the main testing function, takes a kms url and tries to make a new secret manager out of it and encrypt and
// decrypt data, this is used by the aws_test and azure_test files.
func testURL(ctx context.Context, t *testing.T, url string) {
	info := &workspace.ProjectStack{}
	info.SecretsProvider = url

	var err error
	var manager secrets.Manager

	// Creating a new cloud secrets manager is sometimes flaky, so we try a few times with backoff
	// before giving up.
	for i := 1; i < 10; i++ {
		manager, err = NewCloudSecretsManager(info, url, false)
		if err == nil {
			break
		}
		time.Sleep(time.Duration(i) * 100 * time.Millisecond)
	}
	require.NoError(t, err)

	enc := manager.Encrypter()
	dec := manager.Decrypter()

	ciphertext, err := enc.EncryptValue(ctx, "plaintext")
	require.NoError(t, err)

	plaintext, err := dec.DecryptValue(ctx, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, "plaintext", plaintext)
}

func randomName(t *testing.T) string {
	letters := "abcdefghijklmnopqrstuvwxyz"
	var name strings.Builder
	for range 32 {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		require.NoError(t, err)

		char := letters[j.Int64()]
		name.WriteString(string(char))
	}
	return name.String()
}

//nolint:paralleltest
func TestSecretsProviderOverride(t *testing.T) {
	// Don't call t.Parallel because we temporarily modify
	// PULUMI_CLOUD_SECRET_OVERRIDE env var and it may interfere with other
	// tests.
	t.Setenv("PULUMI_CLOUD_SECRET_OVERRIDE", "")

	stackConfig := &workspace.ProjectStack{}

	opener := &mockSecretsKeeperOpener{}
	gosecrets.DefaultURLMux().RegisterKeeper("test", opener)

	//nolint:paralleltest
	t.Run("without override", func(t *testing.T) {
		opener.wantURL = "test://foo"
		_, createSecretsManagerError := NewCloudSecretsManager(stackConfig, "test://foo", false)
		assert.Nil(t, createSecretsManagerError, "Creating the cloud secret manager should succeed")

		_, createSecretsManagerError = NewCloudSecretsManager(stackConfig, "test://bar", false)
		msg := "NewCloudSecretsManager with unexpected secretsProvider URL succeeded, expected an error"
		require.NotNil(t, createSecretsManagerError, msg)
	})

	t.Run("with override", func(t *testing.T) {
		opener.wantURL = "test://bar"
		t.Setenv("PULUMI_CLOUD_SECRET_OVERRIDE", "test://bar")

		// Last argument here shouldn't matter anymore, since it gets overridden
		// by the env var. Both calls should succeed.
		msg := "creating the secrets manager should succeed regardless of secrets provider"
		_, createSecretsManagerError := NewCloudSecretsManager(stackConfig, "test://foo", false)
		assert.Nil(t, createSecretsManagerError, msg)
		_, createSecretsManagerError = NewCloudSecretsManager(stackConfig, "test://bar", false)
		assert.Nil(t, createSecretsManagerError, msg)
	})
}

func TestGCPKMSOverridePreservesWrappedStackKey(t *testing.T) {
	configured := strings.Replace(testGCPKMSURL, "gcpkms", "GcpKms", 1)
	t.Setenv("PULUMI_CLOUD_SECRET_OVERRIDE", testGCPKMSURL+"/")
	assert.Equal(t, configured, effectiveCloudSecretsProvider(configured))

	keeper := newConfigTestKeeper(t)
	wrapped := wrapTestDataKey(t, keeper)
	ps := &workspace.ProjectStack{
		SecretsProvider: configured,
		EncryptedKey:    base64.StdEncoding.EncodeToString(wrapped),
	}
	enc, err := NewConfigEncrypter(t.Context(), ps, func(_ context.Context, provider string) (ConfigKMSKeeper, error) {
		assert.Equal(t, configured, provider)
		return keeper, nil
	})
	require.NoError(t, err)
	require.NotNil(t, enc)
	ciphertext, err := enc.EncryptValue(t.Context(), "config value")
	require.NoError(t, err)

	keeper.allowDecrypt = true
	sm, err := newCloudSecretsManagerWithKeeper(t.Context(), configured, wrapped, keeper)
	require.NoError(t, err)
	plaintext, err := sm.Decrypter().DecryptValue(t.Context(), ciphertext)
	require.NoError(t, err)
	assert.Equal(t, "config value", plaintext)
}

func TestCloudSecretsManagerRefusesImplicitGCPKMSRekey(t *testing.T) {
	t.Setenv("PULUMI_CLOUD_SECRET_OVERRIDE", testGCPKMSURL+"-other")
	ps := &workspace.ProjectStack{
		SecretsProvider: testGCPKMSURL,
		EncryptedKey:    base64.StdEncoding.EncodeToString([]byte("existing key")),
		Config: config.Map{
			config.MustMakeKey("test", "secret"): config.NewSecureObjectValue(
				`{"nested":[{"secret":{"secure":"v2:wrapped:payload"}}]}`,
			),
		},
	}
	original := *ps
	_, err := NewCloudSecretsManager(ps, ps.SecretsProvider, false)
	require.ErrorContains(t, err, "cannot replace the wrapped stack key")
	assert.Equal(t, original, *ps)

	ps.EncryptedKey = ""
	t.Setenv("PULUMI_CLOUD_SECRET_OVERRIDE", "")
	_, err = NewCloudSecretsManager(ps, ps.SecretsProvider, false)
	require.ErrorContains(t, err, "cannot replace the wrapped stack key")
	assert.Empty(t, ps.EncryptedKey)
}

func TestCloudSecretsManagerAllowsOverrideWithoutV2Config(t *testing.T) {
	const scheme = "test-v1-replacement"
	const provider = scheme + "://key"
	t.Setenv("PULUMI_CLOUD_SECRET_OVERRIDE", provider)
	mux := gosecrets.DefaultURLMux()
	if !mux.ValidKeeperScheme(scheme) {
		mux.RegisterKeeper(scheme, &mockSecretsKeeperOpener{wantURL: provider})
	}

	ps := &workspace.ProjectStack{
		SecretsProvider: testGCPKMSURL,
		EncryptedKey:    base64.StdEncoding.EncodeToString([]byte("existing key")),
		Config: config.Map{
			config.MustMakeKey("test", "legacy"): config.NewSecureValue("v1:existing"),
			config.MustMakeKey("test", "text"):   config.NewValue("v2:not:ciphertext"),
			config.MustMakeKey("test", "object"): config.NewSecureObjectValue(
				`{"nested":[{"secure":"v1:existing"},"v2:not:ciphertext"]}`,
			),
		},
	}
	originalKey := ps.EncryptedKey
	originalConfig := ps.Config
	manager, err := NewCloudSecretsManager(ps, ps.SecretsProvider, false)
	require.NoError(t, err)
	assert.Equal(t, Type, manager.Type())
	assert.Equal(t, provider, ps.SecretsProvider)
	assert.NotEqual(t, originalKey, ps.EncryptedKey)
	assert.Equal(t, originalConfig, ps.Config)
}

func TestCloudSecretsManagerRejectsMalformedSecureConfigBeforeReplacingKey(t *testing.T) {
	t.Setenv("PULUMI_CLOUD_SECRET_OVERRIDE", testGCPKMSURL+"-other")
	ps := &workspace.ProjectStack{
		SecretsProvider: testGCPKMSURL,
		EncryptedKey:    base64.StdEncoding.EncodeToString([]byte("existing key")),
		Config: config.Map{
			config.MustMakeKey("test", "secret"): config.NewSecureObjectValue(`{"bad":`),
		},
	}
	original := *ps
	_, err := NewCloudSecretsManager(ps, ps.SecretsProvider, false)
	require.ErrorContains(t, err, "unexpected EOF")
	assert.Equal(t, original, *ps)
}

func TestGCPConfigDecryptionContextReachesSDKMap(t *testing.T) {
	t.Parallel()

	keeper := newConfigTestKeeper(t)
	keeper.allowDecrypt = true
	stackKey := wrapTestDataKey(t, keeper)
	writer := &gcpConfigEncrypter{keeper: keeper, stackKey: stackKey}
	first, err := writer.EncryptValue(t.Context(), "first")
	require.NoError(t, err)
	second, err := writer.EncryptValue(t.Context(), "second")
	require.NoError(t, err)

	deadline := time.Now().Add(time.Minute)
	deadlineCtx, stopDeadline := context.WithDeadline(t.Context(), deadline)
	defer stopDeadline()
	ctx, cancel := context.WithCancel(deadlineCtx)
	defer cancel()
	unwrapper := configUnwrapperFunc(func(callCtx context.Context, ciphertext []byte) ([]byte, error) {
		if string(ciphertext) == string(stackKey) {
			return keeper.Decrypt(callCtx, ciphertext)
		}
		if observed, ok := callCtx.Deadline(); ok {
			assert.Equal(t, deadline, observed)
			cancel()
			return nil, callCtx.Err()
		}
		return keeper.Decrypt(callCtx, ciphertext)
	})
	manager, err := newCloudSecretsManagerWithKeeper(t.Context(), testGCPKMSURL, stackKey, unwrapper)
	require.NoError(t, err)
	wrapped := WithConfigDecryptionContext(ctx, manager, testGCPKMSURL)
	key := config.MustMakeKey("test", "first")
	settings := config.Map{
		key:                                config.NewSecureValue(first),
		config.MustMakeKey("test", "next"): config.NewSecureValue(second),
	}
	_, err = settings.Decrypt(wrapped.Decrypter())
	require.ErrorIs(t, err, context.Canceled)

	// An explicit caller context overrides the canceled command context.
	plaintext, err := wrapped.Decrypter().DecryptValue(t.Context(), first)
	require.NoError(t, err)
	assert.Equal(t, "first", plaintext)
	// The wrapper keeps its underlying cache and leaves the original manager usable.
	plaintext, err = manager.Decrypter().DecryptValue(t.Context(), first)
	require.NoError(t, err)
	assert.Equal(t, "first", plaintext)
	assert.EqualValues(t, 2, keeper.decrypts.Load())
}

func TestGCPKMSClientSuppressesPayloadDiagnostics(t *testing.T) {
	t.Setenv("GOOGLE_SDK_GO_LOGGING_LEVEL", "debug")

	logPath := filepath.Join(t.TempDir(), "kms.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY, 0o600)
	require.NoError(t, err)
	previous := os.Stderr
	os.Stderr = logFile
	t.Cleanup(func() {
		os.Stderr = previous
		require.NoError(t, logFile.Close())
	})

	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	kmspb.RegisterKeyManagementServiceServer(server, testKMSLoggingServer{})
	t.Cleanup(server.Stop)
	go func() { _ = server.Serve(listener) }()

	conn, err := grpc.NewClient("passthrough:///kms",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return listener.DialContext(ctx)
		}),
	)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, conn.Close()) })

	ctx := t.Context()
	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "synthetic-local-token"})
	production, err := newGCPKMSClient(ctx, tokenSource, option.WithGRPCConn(conn))
	require.NoError(t, err)
	control, err := kms.NewKeyManagementClient(ctx, option.WithGRPCConn(conn))
	require.NoError(t, err)
	provider, err := url.Parse(testGCPKMSURL)
	require.NoError(t, err)

	roundtrip := func(client *kms.KeyManagementClient) {
		t.Helper()
		opener := gcpkms.URLOpener{Client: client}
		keeper, err := opener.OpenKeeperURL(ctx, provider)
		require.NoError(t, err)
		ciphertext, err := keeper.Encrypt(ctx, []byte(testKMSLogPlaintext))
		require.NoError(t, err)
		assert.Equal(t, testKMSLogCiphertext, string(ciphertext))
		plaintext, err := keeper.Decrypt(ctx, ciphertext)
		require.NoError(t, err)
		assert.Equal(t, testKMSLogPlaintext, string(plaintext))
	}

	roundtrip(production)
	quiet, err := os.ReadFile(logPath)
	require.NoError(t, err)
	assert.Empty(t, quiet)

	// The same synthetic RPCs log requests and responses when using ambient SDK debug logging.
	roundtrip(control)
	debug, err := os.ReadFile(logPath)
	require.NoError(t, err)
	for _, value := range []string{testKMSLogPlaintext, testKMSLogCiphertext} {
		assert.Contains(t, string(debug), base64.StdEncoding.EncodeToString([]byte(value)))
	}
	assert.Contains(t, string(debug), `"rpcName":"Encrypt"`)
	assert.Contains(t, string(debug), `"rpcName":"Decrypt"`)
	assert.Contains(t, string(debug), `"message":"api request"`)
	assert.Contains(t, string(debug), `"message":"api response"`)
}

const (
	testKMSLogPlaintext  = "synthetic kms plaintext"
	testKMSLogCiphertext = "synthetic kms ciphertext"
)

type testKMSLoggingServer struct {
	kmspb.UnimplementedKeyManagementServiceServer
}

func (testKMSLoggingServer) Encrypt(
	_ context.Context, req *kmspb.EncryptRequest,
) (*kmspb.EncryptResponse, error) {
	if string(req.GetPlaintext()) != testKMSLogPlaintext {
		return nil, errors.New("unexpected synthetic plaintext")
	}
	return &kmspb.EncryptResponse{Ciphertext: []byte(testKMSLogCiphertext)}, nil
}

func (testKMSLoggingServer) Decrypt(
	_ context.Context, req *kmspb.DecryptRequest,
) (*kmspb.DecryptResponse, error) {
	if string(req.GetCiphertext()) != testKMSLogCiphertext {
		return nil, errors.New("unexpected synthetic ciphertext")
	}
	return &kmspb.DecryptResponse{Plaintext: []byte(testKMSLogPlaintext)}, nil
}

type mockSecretsKeeperOpener struct {
	wantURL string
}

func (m *mockSecretsKeeperOpener) OpenKeeperURL(ctx context.Context, u *url.URL) (*gosecrets.Keeper, error) {
	if m.wantURL != u.String() {
		return nil, fmt.Errorf("got keeper URL: %q, want: %q", u, m.wantURL)
	}
	return gosecrets.NewKeeper(dummySecretsKeeper{}), nil
}

type dummySecretsKeeper struct {
	driver.Keeper
}

func (k dummySecretsKeeper) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	return ciphertext, nil
}

func (k dummySecretsKeeper) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	return plaintext, nil
}
