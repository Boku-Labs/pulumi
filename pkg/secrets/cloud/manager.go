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
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	netUrl "net/url"
	"strings"

	kms "cloud.google.com/go/kms/apiv1"
	gosecrets "gocloud.dev/secrets"
	_ "gocloud.dev/secrets/awskms"        // support for awskms://
	_ "gocloud.dev/secrets/azurekeyvault" // support for azurekeyvault://
	"gocloud.dev/secrets/gcpkms"          // support for gcpkms://
	_ "gocloud.dev/secrets/hashivault"    // support for hashivault://
	"golang.org/x/oauth2"
	"google.golang.org/api/cloudkms/v1"
	"google.golang.org/api/option"

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

		kmsClient, err := newGCPKMSClient(ctx, credentials.TokenSource)
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

func newGCPKMSClient(
	ctx context.Context, tokenSource oauth2.TokenSource, opts ...option.ClientOption,
) (*kms.KeyManagementClient, error) {
	return kms.NewKeyManagementClient(ctx, append([]option.ClientOption{
		option.WithTokenSource(tokenSource),
		option.WithUserAgent("go-cloud/secrets/0.46.0"),
		option.WithLogger(slog.New(slog.DiscardHandler)),
	}, opts...)...)
}

// generateNewDataKey generates a new DataKey seeded by a fresh random 32-byte key and encrypted
// using the target cloud key management service.
func generateNewDataKey(url string) ([]byte, error) {
	plaintextDataKey := make([]byte, 32)
	_, err := rand.Read(plaintextDataKey)
	if err != nil {
		return nil, err
	}
	keeper, err := openKeeper(context.Background(), url)
	if err != nil {
		return nil, err
	}
	return keeper.Encrypt(context.Background(), plaintextDataKey)
}

// newCloudSecretsManager returns a secrets manager that uses the target cloud key management
// service to encrypt/decrypt a data key used for envelope encryption of secrets values.
func newCloudSecretsManager(url string, encryptedDataKey []byte) (*Manager, error) {
	ctx := context.Background()
	keeper, err := openKeeper(ctx, url)
	if err != nil {
		return nil, err
	}
	return newCloudSecretsManagerWithKeeper(ctx, url, encryptedDataKey, keeper)
}

func newCloudSecretsManagerWithKeeper(
	ctx context.Context, url string, encryptedDataKey []byte, keeper dataKeyUnwrapper,
) (*Manager, error) {
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
	plaintextDataKey, err := keeper.Decrypt(ctx, ciphertext)
	if err != nil {
		return nil, err
	}
	if len(plaintextDataKey) != config.SymmetricCrypterKeyBytes {
		return nil, fmt.Errorf("invalid stack data key length: got %d bytes, want %d",
			len(plaintextDataKey), config.SymmetricCrypterKeyBytes)
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

// WithConfigDecryptionContext binds a context for GCP KMS config decryption through SDK
// methods that supply context.TODO. The original manager is left intact.
func WithConfigDecryptionContext(ctx context.Context, manager secrets.Manager, provider string) secrets.Manager {
	if parseGCPKMSProvider(provider) == nil || manager == nil || manager.Type() != Type {
		return manager
	}
	return configDecryptionContextManager{Manager: manager, ctx: ctx}
}

type configDecryptionContextManager struct {
	secrets.Manager
	ctx context.Context
}

func (m configDecryptionContextManager) Decrypter() config.Decrypter {
	return configDecryptionContext{m.Manager.Decrypter(), m.ctx}
}

type configDecryptionContext struct {
	decrypter config.Decrypter
	ctx       context.Context
}

func (d configDecryptionContext) DecryptValue(ctx context.Context, ciphertext string) (string, error) {
	if ctx == context.TODO() && strings.HasPrefix(ciphertext, gcpConfigCiphertextPrefix) {
		ctx = d.ctx
	}
	return d.decrypter.DecryptValue(ctx, ciphertext)
}

func (d configDecryptionContext) BatchDecrypt(ctx context.Context, ciphertexts []string) ([]string, error) {
	if ctx == context.TODO() && hasGCPConfigCiphertext(ciphertexts) {
		ctx = d.ctx
	}
	return d.decrypter.BatchDecrypt(ctx, ciphertexts)
}

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
	// V2 ciphertext is bound to the wrapped stack key. Replacing its key
	// requires an explicit provider change or rotation.
	provider := effectiveCloudSecretsProvider(secretsProvider)
	if !rotateSecretsProvider && secretsProvider == info.SecretsProvider &&
		parseGCPKMSProvider(secretsProvider) != nil &&
		(info.EncryptedKey == "" || provider != secretsProvider) {
		for _, value := range info.Config {
			if !value.Secure() {
				continue
			}
			ciphertexts, err := value.SecureValues(config.NopDecrypter)
			if err != nil {
				return nil, err
			}
			if hasGCPConfigCiphertext(ciphertexts) {
				return nil, errors.New("cannot replace the wrapped stack key while v2 encrypted configuration exists")
			}
		}
	}
	secretsProvider = provider

	// Only a passphrase provider has an encryption salt. So changing a secrets provider
	// from passphrase to a cloud secrets provider should ensure that we remove the enryptionsalt
	// as it's a legacy artifact and needs to be removed
	info.EncryptionSalt = ""

	var secretsManager *Manager

	// If we're rotating then just clear the key so we create a fresh one below
	if rotateSecretsProvider {
		info.EncryptedKey = ""
	}

	// if there is no key OR the secrets provider is changing
	// then we need to generate the new key based on the new secrets provider
	if info.EncryptedKey == "" || info.SecretsProvider != secretsProvider {
		dataKey, err := generateNewDataKey(secretsProvider)
		if err != nil {
			return nil, err
		}
		// gocloud.dev versions before v0.28.0 wrapped the
		// data key in a base64.RawURLEncoding before wrapping
		// it again in base64.StdEncoding.  We keep emulating
		// this here for compatibility.
		if strings.HasPrefix(secretsProvider, "azurekeyvault://") {
			dataKey = []byte(base64.RawURLEncoding.EncodeToString(dataKey))
		}
		info.EncryptedKey = base64.StdEncoding.EncodeToString(dataKey)
	}
	info.SecretsProvider = secretsProvider

	dataKey, err := base64.StdEncoding.DecodeString(info.EncryptedKey)
	if err != nil {
		return nil, err
	}

	secretsManager, err = newCloudSecretsManager(secretsProvider, dataKey)
	if err != nil {
		return nil, err
	}

	return secretsManager, nil
}
