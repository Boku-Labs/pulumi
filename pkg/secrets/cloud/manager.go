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

// Package cloud implements support for a generic cloud secret manager.
package cloud

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	netUrl "net/url"
	"os"
	"strings"

	gosecrets "gocloud.dev/secrets"
	_ "gocloud.dev/secrets/awskms"        // support for awskms://
	_ "gocloud.dev/secrets/azurekeyvault" // support for azurekeyvault://
	"gocloud.dev/secrets/gcpkms"          // support for gcpkms://
	_ "gocloud.dev/secrets/hashivault"    // support for hashivault://
	"google.golang.org/api/cloudkms/v1"

	"github.com/pulumi/pulumi/pkg/v3/authhelpers"
	"github.com/pulumi/pulumi/pkg/v3/secrets"
	"github.com/pulumi/pulumi/sdk/v3/go/common/resource/config"
	"github.com/pulumi/pulumi/sdk/v3/go/common/workspace"
)

// Type is the type of secrets managed by this secrets provider
const Type = "cloud"

type cloudSecretsManagerState struct {
	URL          string `json:"url"`
	EncryptedKey []byte `json:"encryptedkey"`
}

// openKeeper opens the keeper, handling pulumi-specifc cases in the URL.
func openKeeper(ctx context.Context, url string) (*gosecrets.Keeper, error) {
	u, err := netUrl.Parse(url)
	if err != nil {
		return nil, fmt.Errorf("unable to parse the secrets provider URL: %w", err)
	}

	switch u.Scheme {
	case gcpkms.Scheme:
		credentials, err := authhelpers.ResolveGoogleCredentials(ctx, cloudkms.CloudkmsScope)
		if err != nil {
			return nil, fmt.Errorf("missing google credentials: %w", err)
		}

		kmsClient, _, err := gcpkms.Dial(ctx, credentials.TokenSource)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to gcpkms: %w", err)
		}
		opener := gcpkms.URLOpener{
			Client: kmsClient,
		}

		return opener.OpenKeeperURL(ctx, u)
	default:
		return gosecrets.OpenKeeper(ctx, url)
	}
}

// newCloudSecretsManager returns a secrets manager that uses the target cloud key management
// service to encrypt/decrypt a data key used for envelope encryption of secrets values.
func newCloudSecretsManager(url string, encryptedDataKey []byte) (*Manager, error) {
	keeper, err := openKeeper(context.Background(), url)
	if err != nil {
		return nil, err
	}
	return newCloudSecretsManagerWithKeeper(url, encryptedDataKey, keeper)
}

func newCloudSecretsManagerWithKeeper(url string, encryptedDataKey []byte, keeper dataKeyUnwrapper) (*Manager, error) {
	// We're emulating gocloud.dev's old behaviour here. Pre v0.28.0 it used to have an inner wrapping, which
	// we keep for compatibility (see above). However the newer version expects this to be unwrapped, before
	// it's used, so let's do that here.
	ciphertext := encryptedDataKey
	if strings.HasPrefix(url, "azurekeyvault://") {
		decoded, err := base64.RawURLEncoding.DecodeString(string(encryptedDataKey))
		if err != nil {
			return nil, err
		}
		ciphertext = decoded
	}
	plaintextDataKey, err := keeper.Decrypt(context.Background(), ciphertext)
	if err != nil {
		return nil, err
	}
	state, err := json.Marshal(cloudSecretsManagerState{
		URL:          url,
		EncryptedKey: encryptedDataKey,
	})
	if err != nil {
		return nil, fmt.Errorf("marshalling state: %w", err)
	}
	crypter := config.NewSymmetricCrypter(plaintextDataKey)
	var decrypter config.Decrypter = crypter
	if parseGCPKMSProvider(url) != nil {
		decrypter = gcpConfigDecrypter{legacy: crypter, keeper: keeper, stackKey: encryptedDataKey}
	}
	cachedCrypter := config.NewCiphertextToPlaintextCachedCrypter(crypter, decrypter)
	return &Manager{
		crypter: cachedCrypter,
		state:   state,
	}, nil
}

// Manager is the secrets.Manager implementation for cloud key management services
type Manager struct {
	state   json.RawMessage
	crypter config.Crypter
}

func (m *Manager) Type() string                { return Type }
func (m *Manager) State() json.RawMessage      { return m.state }
func (m *Manager) Encrypter() config.Encrypter { return m.crypter }
func (m *Manager) Decrypter() config.Decrypter { return m.crypter }

func EditProjectStack(info *workspace.ProjectStack, state json.RawMessage) error {
	info.EncryptionSalt = ""

	var s cloudSecretsManagerState
	err := json.Unmarshal(state, &s)
	if err != nil {
		return fmt.Errorf("unmarshalling cloud state: %w", err)
	}

	info.SecretsProvider = s.URL
	info.EncryptedKey = base64.StdEncoding.EncodeToString(s.EncryptedKey)
	return nil
}

// NewCloudSecretsManagerFromState deserialize configuration from state and returns a secrets
// manager that uses the target cloud key management service to encrypt/decrypt a data key used for
// envelope encryption of secrets values.
func NewCloudSecretsManagerFromState(state json.RawMessage) (secrets.Manager, error) {
	var s cloudSecretsManagerState
	err := json.Unmarshal(state, &s)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling state: %w", err)
	}

	// We're emulating gocloud.dev's old behaviour here.  Pre v0.28.0 it used to have an inner wrapping, which
	// we keep for compatibility (see above). However the newer version expects this to be unwrapped, before
	// it's used. newCloudSecretsManager will manage that but we need to check here as well to handle the
	// #15329 regression.
	dataKey := s.EncryptedKey
	if strings.HasPrefix(s.URL, "azurekeyvault://") {
		wrappedKey, err := base64.RawURLEncoding.DecodeString(string(dataKey))
		if err != nil {
			// https://github.com/pulumi/pulumi/issues/15329 resulted in some non-encoded keys being written
			// to state. This checks that case to see if there valid base64 data.
			firstErr := err
			_, err := base64.StdEncoding.DecodeString(string(wrappedKey))
			if err != nil {
				// Wasn't valid base64 so probably just gibberish, return the first error we saw.
				return nil, firstErr
			}
			// This is a valid base64 string so it's probably just a bad encoding, wrap it as expected and
			// pass it on to newCloudSecretsManager
			dataKey = []byte(base64.RawURLEncoding.EncodeToString(dataKey))
		}
	}

	return newCloudSecretsManager(s.URL, dataKey)
}

func NewCloudSecretsManager(info *workspace.ProjectStack,
	secretsProvider string, rotateSecretsProvider bool,
) (secrets.Manager, error) {
	return newCloudSecretsManagerForStack(info, secretsProvider, rotateSecretsProvider, openKeeper)
}

// effectiveCloudSecretsProvider applies a per-execution override. Preserve the
// configured spelling of an equivalent GCP KMS URL to keep its wrapped key.
func effectiveCloudSecretsProvider(provider string) string {
	override := os.Getenv("PULUMI_CLOUD_SECRET_OVERRIDE")
	if override == "" || override == provider {
		return provider
	}
	configured := parseGCPKMSProvider(provider)
	replacement := parseGCPKMSProvider(override)
	if configured != nil && replacement != nil && configured.String() == replacement.String() {
		return provider
	}
	return override
}

func newCloudSecretsManagerForStack(
	info *workspace.ProjectStack, secretsProvider string, rotateSecretsProvider bool,
	open func(context.Context, string) (*gosecrets.Keeper, error),
) (secrets.Manager, error) {
	// Only passphrase secrets providers use an encryption salt.
	info.EncryptionSalt = ""
	secretsProvider = effectiveCloudSecretsProvider(secretsProvider)

	// Decode an existing wrapped key before opening the keeper.
	ctx := context.Background()
	dataKey, err := base64.StdEncoding.DecodeString(info.EncryptedKey)
	needsNewKey := rotateSecretsProvider || info.EncryptedKey == "" || info.SecretsProvider != secretsProvider
	if !needsNewKey && err != nil {
		return nil, err
	}
	keeper, err := open(ctx, secretsProvider)
	if err != nil {
		return nil, err
	}

	if needsNewKey {
		_, dataKey, err = newWrappedDataKey(ctx, keeper)
		if err != nil {
			return nil, err
		}
		// Preserve the legacy Azure Key Vault encoding in stack metadata.
		if strings.HasPrefix(secretsProvider, "azurekeyvault://") {
			dataKey = []byte(base64.RawURLEncoding.EncodeToString(dataKey))
		}
	}

	sm, err := newCloudSecretsManagerWithKeeper(secretsProvider, dataKey, keeper)
	if err != nil {
		return nil, err
	}
	info.SecretsProvider = secretsProvider
	if needsNewKey {
		info.EncryptedKey = base64.StdEncoding.EncodeToString(dataKey)
	}
	return sm, nil
}
