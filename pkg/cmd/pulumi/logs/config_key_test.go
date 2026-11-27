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

package logs

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/pulumi/pulumi/pkg/v3/backend"
	cmdBackend "github.com/pulumi/pulumi/pkg/v3/cmd/pulumi/backend"
	"github.com/pulumi/pulumi/pkg/v3/engine/encryptedlog"
	"github.com/pulumi/pulumi/pkg/v3/secrets/cloud"
	"github.com/pulumi/pulumi/pkg/v3/util/testutil"
	pkgWorkspace "github.com/pulumi/pulumi/pkg/v3/workspace"
	"github.com/pulumi/pulumi/sdk/v3/go/common/apitype"
	"github.com/pulumi/pulumi/sdk/v3/go/common/diag"
	"github.com/pulumi/pulumi/sdk/v3/go/common/diag/colors"
	"github.com/pulumi/pulumi/sdk/v3/go/common/resource/config"
	"github.com/pulumi/pulumi/sdk/v3/go/common/tokens"
	"github.com/pulumi/pulumi/sdk/v3/go/common/workspace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gosecrets "gocloud.dev/secrets"
	"gocloud.dev/secrets/driver"
)

var registerLogConfigKeeper sync.Once

func TestDecryptAndShareLogWithConfigKey(t *testing.T) {
	ctx := t.Context()
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("PULUMI_CLOUD_SECRET_OVERRIDE", "unused://override")

	const scheme = "log-test-kms"
	const provider = scheme + "://config-key"
	registerLogConfigKeeper.Do(func() {
		gosecrets.DefaultURLMux().RegisterKeeper(scheme, logConfigKeeperOpener{})
	})
	project := &workspace.Project{
		Name:    "log-test",
		Runtime: workspace.NewProjectRuntimeInfo("go", nil),
	}
	require.NoError(t, project.Save("Pulumi.yaml"))

	key := bytes.Repeat([]byte{1}, config.SymmetricCrypterKeyBytes)
	stackConfig := workspace.ProjectStack{
		SecretsProvider: provider,
		EncryptedKey:    base64.StdEncoding.EncodeToString(key),
	}
	require.NoError(t, stackConfig.Save("Pulumi.dev.yaml"))
	configBefore, err := os.ReadFile("Pulumi.dev.yaml")
	require.NoError(t, err)

	const alternateYAML = "alternate.yaml"
	const alternateJSON = "alternate.json"
	alternateConfig := map[string][]byte{
		alternateYAML: []byte("\uFEFFsecretsprovider: " + provider +
			"\nencryptedkey: " + stackConfig.EncryptedKey + "\nconfig: {region: europe-west1}\n"),
		alternateJSON: []byte("\uFEFF{\"secretsprovider\":\"" + provider +
			"\",\"encryptedkey\":\"" + stackConfig.EncryptedKey + "\",\"config\":{\"region\":\"europe-west1\"}}"),
	}
	for path, contents := range alternateConfig {
		require.NoError(t, os.WriteFile(path, contents, 0o600))
	}

	ref := &backend.MockStackReference{NameV: tokens.MustParseStackName("dev")}
	var checkpoint *apitype.UntypedDeployment
	checkpointReads := 0
	b := &backend.MockBackend{
		ExportDeploymentF: func(context.Context, backend.Stack) (*apitype.UntypedDeployment, error) {
			checkpointReads++
			return checkpoint, nil
		},
	}
	stack := &backend.MockStack{
		RefF:            func() backend.StackReference { return ref },
		BackendF:        func() backend.Backend { return b },
		ConfigLocationF: func() backend.StackConfigLocation { return backend.StackConfigLocation{} },
	}
	b.GetStackF = func(context.Context, backend.StackReference) (backend.Stack, error) { return stack, nil }
	testutil.MockLoginManager(t, &cmdBackend.MockLoginManager{
		LoginF: func(
			context.Context, pkgWorkspace.Context, diag.Sink, string,
			*workspace.Project, bool, bool, colors.Colorization, ...cmdBackend.LoginOption,
		) (backend.Backend, error) {
			return b, nil
		},
	})
	ws := &pkgWorkspace.MockContext{
		ReadProjectF: func(string) (*workspace.Project, string, error) { return project, dir, nil },
	}

	const record = "saved before deployment\n"
	const name = "dev-20260401T120000.log"
	f, err := os.Create(name)
	require.NoError(t, err)
	prepared, err := encryptedlog.PrepareKey(ctx, config.NewSymmetricCrypter(key))
	require.NoError(t, err)
	writer, err := encryptedlog.NewWriterFromKey(f, prepared)
	require.NoError(t, err)
	_, err = io.WriteString(writer, record)
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	require.NoError(t, f.Close())

	staleKey, err := json.Marshal(map[string]any{
		"url":          provider,
		"encryptedkey": make([]byte, config.SymmetricCrypterKeyBytes),
	})
	require.NoError(t, err)
	stale, err := json.Marshal(apitype.DeploymentV3{
		SecretsProviders: &apitype.SecretsProvidersV1{Type: cloud.Type, State: staleKey},
	})
	require.NoError(t, err)
	//nolint:paralleltest // the log commands share a mock login manager
	for _, tc := range []struct {
		name       string
		state      *apitype.UntypedDeployment
		configFile string
	}{
		{name: "no checkpoint"},
		{name: "stale checkpoint", state: &apitype.UntypedDeployment{Version: 3, Deployment: stale}},
		{name: "custom YAML without a project or checkpoint", configFile: alternateYAML},
		{name: "custom JSON without a project or checkpoint", configFile: alternateJSON},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkpoint = tc.state
			beforeReads := checkpointReads
			args := []string{name}
			var commandWorkspace pkgWorkspace.Context = ws
			if tc.configFile != "" {
				args = append(args, "--config-file", tc.configFile)
				commandWorkspace = &pkgWorkspace.MockContext{}
			}

			var out bytes.Buffer
			cmd := newDecryptCmd(commandWorkspace)
			cmd.SetOut(&out)
			cmd.SetArgs(args)
			require.NoError(t, cmd.ExecuteContext(t.Context()))
			assert.Equal(t, record, out.String())

			stackName := "dev"
			share := newShareCmd(commandWorkspace, &stackName,
				func(context.Context, pkgWorkspace.Context) (string, []byte, error) {
					return "session", key, nil
				})
			share.SetArgs(args)
			require.NoError(t, share.ExecuteContext(t.Context()))
			shared, err := os.ReadFile(strings.TrimSuffix(name, ".log") + ".shared.log")
			require.NoError(t, err)
			assert.True(t, bytes.HasPrefix(shared, []byte(encryptedlog.Magic)))
			assert.NotContains(t, string(shared), record)
			if tc.configFile != "" {
				assert.Equal(t, beforeReads, checkpointReads)
				saved, err := os.ReadFile(tc.configFile)
				require.NoError(t, err)
				assert.Equal(t, alternateConfig[tc.configFile], saved)
			}
		})
	}

	t.Run("absent remote config and checkpoint", func(t *testing.T) {
		checkpoint = nil
		remoteReads := 0
		stack.ConfigLocationF = func() backend.StackConfigLocation {
			return backend.StackConfigLocation{IsRemote: true}
		}
		stack.LoadRemoteF = func(context.Context, *workspace.Project) (*workspace.ProjectStack, error) {
			remoteReads++
			return nil, nil
		}

		var out bytes.Buffer
		cmd := newDecryptCmd(ws)
		cmd.SilenceUsage = true
		cmd.SetOut(&out)
		cmd.SetArgs([]string{name})
		err := cmd.ExecuteContext(t.Context())
		require.ErrorContains(t, err, "checkpoint: stack has no deployment")
		require.ErrorContains(t, err, "stack configuration: stack configuration has no wrapped cloud secrets key")
		assert.Equal(t, 1, remoteReads)
		assert.Empty(t, out.String())
	})

	badConfig := workspace.ProjectStack{
		SecretsProvider: provider,
		EncryptedKey:    base64.StdEncoding.EncodeToString(key[:len(key)-1]),
	}
	require.NoError(t, badConfig.Save("invalid.yaml"))
	invalidConfig := newDecryptCmd(&pkgWorkspace.MockContext{})
	invalidConfig.SetArgs([]string{name, "--config-file", "invalid.yaml"})
	require.ErrorContains(t, invalidConfig.ExecuteContext(t.Context()), "invalid stack data key length")

	saved, err := os.ReadFile("Pulumi.dev.yaml")
	require.NoError(t, err)
	assert.Equal(t, configBefore, saved)
}

type logConfigKeeperOpener struct{}

func (logConfigKeeperOpener) OpenKeeperURL(context.Context, *url.URL) (*gosecrets.Keeper, error) {
	return gosecrets.NewKeeper(logConfigKeeper{}), nil
}

type logConfigKeeper struct{ driver.Keeper }

func (logConfigKeeper) Decrypt(_ context.Context, key []byte) ([]byte, error) {
	return key, nil
}
