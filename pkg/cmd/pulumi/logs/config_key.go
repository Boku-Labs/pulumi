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

package logs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/pulumi/pulumi/pkg/v3/backend"
	"github.com/pulumi/pulumi/pkg/v3/backend/display"
	cmdBackend "github.com/pulumi/pulumi/pkg/v3/cmd/pulumi/backend"
	cmdStack "github.com/pulumi/pulumi/pkg/v3/cmd/pulumi/stack"
	"github.com/pulumi/pulumi/pkg/v3/engine/encryptedlog"
	"github.com/pulumi/pulumi/pkg/v3/secrets/cloud"
	pkgWorkspace "github.com/pulumi/pulumi/pkg/v3/workspace"
	"github.com/pulumi/pulumi/sdk/v3/go/common/encoding"
	"github.com/pulumi/pulumi/sdk/v3/go/common/util/cmdutil"
	"github.com/pulumi/pulumi/sdk/v3/go/common/workspace"
)

// openStackLog uses an explicit config file when supplied, otherwise it tries the checkpoint and stack YAML.
func openStackLog(
	ctx context.Context, ws pkgWorkspace.Context, stackName, configFile string, f *os.File,
) (*encryptedlog.Reader, error) {
	if configFile != "" {
		ps, err := loadLogKeyConfig(configFile)
		if err != nil {
			return nil, fmt.Errorf("loading stack configuration %q: %w", configFile, err)
		}
		reader, err := openLogWithConfigKey(ctx, f, ps)
		if err != nil {
			return nil, fmt.Errorf("decrypting log using stack configuration %q: %w", configFile, err)
		}
		return reader, nil
	}

	if stackName == "" {
		stackName = stackNameFromFilename(filepath.Base(f.Name()))
	}
	if stackName == "" {
		return nil, fmt.Errorf("cannot determine stack from filename %q; use --stack to specify", filepath.Base(f.Name()))
	}

	opts := display.Options{Color: cmdutil.GetGlobalColorization()}
	s, err := cmdStack.RequireStack(ctx, cmdutil.Diag(), ws, cmdBackend.DefaultLoginManager, stackName, cmdStack.LoadOnly,
		opts, "")
	if err != nil {
		return nil, fmt.Errorf("loading stack %q for decryption: %w", stackName, err)
	}

	sm, checkpointErr := secretsManagerFromStack(ctx, s)
	if checkpointErr == nil {
		reader, err := encryptedlog.NewReader(ctx, f, sm.Decrypter())
		if err == nil {
			return reader, nil
		}
		checkpointErr = err
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("rewinding log: %w", err)
	}
	reader, configErr := openLogWithStackConfig(ctx, ws, s, f)
	if configErr == nil {
		return reader, nil
	}
	return nil, fmt.Errorf("decrypting log for stack %q: %w", stackName, errors.Join(
		fmt.Errorf("checkpoint: %w", checkpointErr),
		fmt.Errorf("stack configuration: %w", configErr),
	))
}

func loadLogKeyConfig(path string) (*workspace.ProjectStack, error) {
	ext := filepath.Ext(path)
	marshaler, ok := encoding.Marshalers[ext]
	if !ok {
		return nil, fmt.Errorf("no marshaler found for file format %q", ext)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Ignore config entries, as shorthand keys require a project to resolve.
	var key struct {
		SecretsProvider string `json:"secretsprovider" yaml:"secretsprovider"`
		EncryptedKey    string `json:"encryptedkey" yaml:"encryptedkey"`
	}
	if err := marshaler.Unmarshal(bytes.TrimPrefix(data, []byte("\uFEFF")), &key); err != nil {
		return nil, err
	}
	return &workspace.ProjectStack{SecretsProvider: key.SecretsProvider, EncryptedKey: key.EncryptedKey}, nil
}

func openLogWithStackConfig(
	ctx context.Context, ws pkgWorkspace.Context, s backend.Stack, f *os.File,
) (*encryptedlog.Reader, error) {
	project, _, err := ws.ReadProject("")
	if err != nil {
		return nil, err
	}
	ps, err := cmdStack.LoadProjectStack(ctx, cmdutil.Diag(), project, s, "")
	if err != nil {
		return nil, err
	}
	return openLogWithConfigKey(ctx, f, ps)
}

func openLogWithConfigKey(
	ctx context.Context, f *os.File, ps *workspace.ProjectStack,
) (*encryptedlog.Reader, error) {
	sm, err := cloud.OpenCloudSecretsManager(ctx, ps)
	if err != nil {
		return nil, err
	}
	return encryptedlog.NewReader(ctx, f, sm.Decrypter())
}
