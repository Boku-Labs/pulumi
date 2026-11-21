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

package service

import (
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pulumi/pulumi/pkg/v3/backend/httpstate/client"
	"github.com/pulumi/pulumi/sdk/v3/go/common/apitype"
	"github.com/pulumi/pulumi/sdk/v3/go/common/tokens"
	"github.com/pulumi/pulumi/sdk/v3/go/common/workspace"
)

func TestServiceCrypterBatchDecrypt(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name      string
		lastKey   string
		wantError string
	}{
		{name: "canonical keys and empty plaintext", lastKey: "Yg=="},
		{
			name:      "missing response key",
			lastKey:   "Yw==",
			wantError: "decrypted value missing from batch response at input index 3",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodPost, r.Method)
				assert.Equal(t, "/api/stacks/owner/project/stack/batch-decrypt", r.URL.Path)
				assert.Equal(t, "gzip", r.Header.Get("Content-Encoding"))
				body, err := gzip.NewReader(r.Body)
				if err != nil {
					t.Errorf("open gzip request: %v", err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				defer body.Close()
				var request apitype.BatchDecryptRequest
				if err := json.NewDecoder(body).Decode(&request); err != nil {
					t.Errorf("decode batch request: %v", err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				assert.Equal(t, [][]byte{[]byte("a"), []byte("a"), []byte("a"), []byte("b")}, request.Ciphertexts)
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(apitype.BatchDecryptResponse{
					Plaintexts: map[string][]byte{"YQ==": []byte("first secret"), tt.lastKey: {}},
				}); err != nil {
					t.Errorf("encode batch response: %v", err)
				}
			}))
			defer server.Close()

			crypter := &serviceCrypter{
				client: client.NewClient(server.URL, "in-memory-token", false, nil),
				stack:  client.StackIdentifier{Owner: "owner", Project: "project", Stack: tokens.MustParseStackName("stack")},
			}
			plaintexts, err := crypter.BatchDecrypt(t.Context(), []string{"YQ==", "Y\r\nQ==", "YQ==", "Yg=="})
			if tt.wantError != "" {
				require.EqualError(t, err, tt.wantError)
				assert.Nil(t, plaintexts)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, []string{"first secret", "first secret", "first secret", ""}, plaintexts)
		})
	}
}

func TestServiceSecretsReuseBackendClient(t *testing.T) {
	t.Setenv(workspace.PulumiCredentialsPathEnvVar, t.TempDir())
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "token in-memory-token", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/capabilities":
			_ = json.NewEncoder(w).Encode(apitype.CapabilitiesResponse{})
		case "/api/stacks/owner/project/stack/encrypt":
			var req apitype.EncryptValueRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("decode request: %v", err)
				return
			}
			assert.Equal(t, []byte("secret"), req.Plaintext)
			_ = json.NewEncoder(w).Encode(apitype.EncryptValueResponse{Ciphertext: []byte("encrypted")})
		case "/api/stacks/owner/project/stack/decrypt":
			_ = json.NewEncoder(w).Encode(apitype.DecryptValueResponse{Plaintext: []byte("secret")})
		default:
			t.Errorf("unexpected request: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	state, err := json.Marshal(serviceSecretsManagerState{
		URL: server.URL, Owner: "owner", Project: "project", Stack: "stack",
	})
	require.NoError(t, err)
	c := client.NewClient(server.URL, "in-memory-token", false, nil)
	resolve := func(_ context.Context, url string, insecure bool) (*client.Client, error) {
		assert.Equal(t, server.URL, url)
		assert.False(t, insecure)
		return c, nil
	}
	manager, err := NewServiceSecretsManagerFromState(t.Context(), state, resolve)
	require.NoError(t, err)
	ciphertext, err := manager.Encrypter().EncryptValue(t.Context(), "secret")
	require.NoError(t, err)
	assert.Equal(t, base64.StdEncoding.EncodeToString([]byte("encrypted")), ciphertext)
	plaintext, err := manager.Decrypter().DecryptValue(t.Context(), ciphertext)
	require.NoError(t, err)
	assert.Equal(t, "secret", plaintext)
	assert.JSONEq(t, string(state), string(manager.State()))
	account, err := workspace.GetAccount(server.URL)
	require.NoError(t, err)
	assert.Empty(t, account.AccessToken)
	_, err = NewServiceSecretsManagerFromState(t.Context(), state,
		func(context.Context, string, bool) (*client.Client, error) { return nil, errors.New("no credentials") })
	require.ErrorContains(t, err, "no credentials")
}
