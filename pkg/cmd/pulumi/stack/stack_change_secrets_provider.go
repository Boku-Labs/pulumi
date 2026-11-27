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

package stack

import (
	"context"
	"fmt"
	"io"
	"maps"

	"github.com/pulumi/pulumi/pkg/v3/backend"
	"github.com/pulumi/pulumi/pkg/v3/backend/display"
	cmdBackend "github.com/pulumi/pulumi/pkg/v3/cmd/pulumi/backend"
	"github.com/pulumi/pulumi/pkg/v3/cmd/pulumi/constrictor"
	"github.com/pulumi/pulumi/pkg/v3/resource/stack"
	"github.com/pulumi/pulumi/pkg/v3/secrets"
	pkgWorkspace "github.com/pulumi/pulumi/pkg/v3/workspace"
	"github.com/pulumi/pulumi/sdk/v3/go/common/resource/config"
	"github.com/pulumi/pulumi/sdk/v3/go/common/util/cmdutil"
	"github.com/pulumi/pulumi/sdk/v3/go/common/util/contract"
	"github.com/pulumi/pulumi/sdk/v3/go/common/workspace"
	"github.com/spf13/cobra"
)

type stackChangeSecretsProviderCmd struct {
	stdout io.Writer

	stack string

	secretsProvider secrets.Provider
}

func newStackChangeSecretsProviderCmd() *cobra.Command {
	var scspcmd stackChangeSecretsProviderCmd
	cmd := &cobra.Command{
		Use:   "change-secrets-provider",
		Short: "Change the secrets provider for a stack",
		Long: "Change the secrets provider for a stack. " +
			"Valid secret providers types are `default`, `passphrase`, `awskms`, `azurekeyvault`, `gcpkms`, `hashivault`.\n\n" +
			"To change to using the Pulumi Default Secrets Provider, use the following:\n" +
			"\n" +
			"pulumi stack change-secrets-provider default" +
			"\n" +
			"\n" +
			"To change the stack to use a cloud secrets backend, use one of the following:\n" +
			"\n" +
			"* `pulumi stack change-secrets-provider \"awskms://alias/ExampleAlias?region=us-east-1\"" +
			"`\n" +
			"* `pulumi stack change-secrets-provider " +
			"\"awskms://1234abcd-12ab-34cd-56ef-1234567890ab?region=us-east-1\"`\n" +
			"* `pulumi stack change-secrets-provider " +
			"\"azurekeyvault://mykeyvaultname.vault.azure.net/keys/mykeyname\"`\n" +
			"* `pulumi stack change-secrets-provider " +
			"\"gcpkms://projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>\"`\n" +
			"* `pulumi stack change-secrets-provider \"hashivault://mykey\"`",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if scspcmd.stdout == nil {
				scspcmd.stdout = cmd.OutOrStdout()
			}
			return scspcmd.Run(ctx, args)
		},
	}

	constrictor.AttachArguments(cmd, &constrictor.Arguments{
		Arguments: []constrictor.Argument{
			{Name: "new-secrets-provider"},
		},
		Required: 1,
	})

	cmd.PersistentFlags().StringVarP(
		&scspcmd.stack, "stack", "s", "",
		"The name of the stack to operate on. Defaults to the current stack")

	return cmd
}

func (cmd *stackChangeSecretsProviderCmd) Run(ctx context.Context, args []string) error {
	stdout := cmd.stdout
	if cmd.secretsProvider == nil {
		cmd.secretsProvider = cmdBackend.SecretsProvider(cmdBackend.DefaultLoginManager)
	}

	// For change-secrets-provider, we explicitly don't want any fallback behaviour when loading secrets providers.
	ssml := SecretsManagerLoader{}

	ws := pkgWorkspace.Instance

	opts := display.Options{
		Color: cmdutil.GetGlobalColorization(),
	}

	if err := ValidateSecretsProvider(args[0]); err != nil {
		return err
	}

	project, _, err := ws.ReadProject("")
	if err != nil {
		return err
	}

	// Get the current stack and its project
	currentStack, err := RequireStack(
		ctx,
		cmdutil.Diag(),
		ws,
		cmdBackend.DefaultLoginManager,
		cmd.stack,
		LoadOnly,
		opts,
		"",
	)
	if err != nil {
		return err
	}
	if err := RejectManagedStack(currentStack, "`pulumi stack change-secrets-provider`"); err != nil {
		return fmt.Errorf("%w; use a customer-managed key (CMK) in Pulumi Cloud to control the encryption key instead",
			err)
	}

	currentProjectStack, err := LoadProjectStack(ctx, cmdutil.Diag(), project, currentStack, "")
	if err != nil {
		return err
	}

	// Build decrypter based on the existing secrets provider
	var decrypter config.Decrypter
	if currentProjectStack.Config.HasSecureValue() {
		dec, state, decerr := ssml.GetDecrypter(ctx, currentStack, currentProjectStack)
		if decerr != nil {
			return decerr
		}
		contract.Assertf(
			state == SecretsManagerUnchanged,
			"We're reading a secure value so the encryption information must be present already",
		)
		decrypter = dec
	} else {
		decrypter = config.NewPanicCrypter()
	}

	secretsProvider := args[0]
	// If we're setting the secrets provider to the same provider then do a rotation.
	rotateProvider := secretsProvider == currentProjectStack.SecretsProvider ||
		// passphrase doesn't get saved to stack state, so if we're changing to passphrase see if
		// the current secrets provider is empty
		((secretsProvider == "passphrase") && (currentProjectStack.SecretsProvider == ""))
	return migrateOldConfigAndCheckpointToNewSecretsProvider(
		ctx,
		stdout,
		ssml,
		cmd.secretsProvider,
		currentStack,
		currentProjectStack,
		decrypter,
		secretsProvider,
		rotateProvider,
	)
}

func migrateOldConfigAndCheckpointToNewSecretsProvider(
	ctx context.Context,
	stdout io.Writer,
	ssml SecretsManagerLoader,
	secretsProvider secrets.Provider,
	currentStack backend.Stack,
	currentConfig *workspace.ProjectStack,
	decrypter config.Decrypter,
	newProvider string,
	rotateProvider bool,
) error {
	stagedConfig := *currentConfig
	stagedConfig.Config = maps.Clone(currentConfig.Config)
	err := configureSecretsManagerForExistingStack(ctx, currentStack, &stagedConfig, newProvider, rotateProvider)
	if err != nil {
		return err
	}

	fmt.Fprintln(stdout, "Migrating old configuration and state to new secrets provider")

	newSecretsManager, state, err := ssml.GetSecretsManager(ctx, currentStack, &stagedConfig)
	if err != nil {
		return err
	}
	contract.Assertf(
		state == SecretsManagerUnchanged,
		"The staged stack config must already contain the new secrets provider information",
	)

	newProjectConfig, err := currentConfig.Config.Copy(decrypter, newSecretsManager.Encrypter())
	if err != nil {
		return err
	}
	stagedConfig.Config = newProjectConfig

	if err := SaveProjectStack(ctx, currentStack, &stagedConfig, ""); err != nil {
		return err
	}

	// Load the current checkpoint so those secrets can also be decrypted
	checkpoint, err := backend.ExportStackDeployment(ctx, currentStack)
	if err != nil {
		return err
	}
	snap, err := stack.DeserializeUntypedDeployment(ctx, checkpoint, secretsProvider)
	if err != nil {
		return stack.FormatDeploymentDeserializationError(err, currentStack.Ref().Name().String())
	}

	// Reserialize the Snapshopshot with the NewSecrets Manager
	snap.SecretsManager = newSecretsManager
	dep, err := stack.SerializeUntypedDeployment(ctx, snap, nil /*opts*/)
	if err != nil {
		return err
	}

	// Import the newly changes Deployment
	return backend.ImportStackDeployment(ctx, currentStack, dep)
}
