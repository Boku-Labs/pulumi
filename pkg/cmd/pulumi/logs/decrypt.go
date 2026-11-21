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
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	survey "github.com/AlecAivazis/survey/v2"
	"github.com/dustin/go-humanize"
	"github.com/spf13/cobra"

	"github.com/pulumi/pulumi/pkg/v3/backend"
	"github.com/pulumi/pulumi/pkg/v3/backend/display"
	backend_secrets "github.com/pulumi/pulumi/pkg/v3/backend/secrets"
	cmdBackend "github.com/pulumi/pulumi/pkg/v3/cmd/pulumi/backend"
	"github.com/pulumi/pulumi/pkg/v3/cmd/pulumi/cmd"
	cmdStack "github.com/pulumi/pulumi/pkg/v3/cmd/pulumi/stack"
	"github.com/pulumi/pulumi/pkg/v3/cmd/pulumi/ui"
	"github.com/pulumi/pulumi/pkg/v3/engine/encryptedlog"
	"github.com/pulumi/pulumi/pkg/v3/secrets"
	"github.com/pulumi/pulumi/pkg/v3/secrets/cloud"
	pkgWorkspace "github.com/pulumi/pulumi/pkg/v3/workspace"
	"github.com/pulumi/pulumi/sdk/v3/go/common/apitype"
	"github.com/pulumi/pulumi/sdk/v3/go/common/encoding"
	"github.com/pulumi/pulumi/sdk/v3/go/common/env"
	"github.com/pulumi/pulumi/sdk/v3/go/common/util/cmdutil"
	"github.com/pulumi/pulumi/sdk/v3/go/common/util/logging"
	"github.com/pulumi/pulumi/sdk/v3/go/common/workspace"
)

func newDecryptCmd(ws pkgWorkspace.Context) *cobra.Command {
	var latest bool
	var configFile string
	command := &cobra.Command{
		Use:   "decrypt [filename]",
		Short: "Decrypt and display automatic logs",
		Long: "Decrypt and display the contents of an automatic log file.\n" +
			"\n" +
			"If no filename is provided, a list of available log files is\n" +
			"displayed and the user is prompted to choose one. Pass\n" +
			"--latest to skip the prompt and decrypt the most recent log\n" +
			"file instead",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			stackName, _ := cmd.Flags().GetString("stack")

			var filename string
			if len(args) > 0 {
				filename = args[0]
			} else {
				var err error
				if latest {
					filterName := stackName
					if filterName == "" {
						filterName = currentStackName(ws)
					}
					filename, err = findLatestLog(filterName)
					if err != nil {
						return err
					}
					fmt.Fprintf(cmd.ErrOrStderr(), "Decrypting %s\n", filename)
				} else {
					filename, err = chooseLog(stackName, "Select a log file to decrypt:")
					if err != nil {
						return err
					}
				}
			}

			f, err := os.Open(filename)
			if err != nil {
				return fmt.Errorf("opening log file: %w", err)
			}
			defer f.Close()

			var magic [4]byte
			if _, err := io.ReadFull(f, magic[:]); err != nil {
				return fmt.Errorf("reading log file: %w", err)
			}
			if _, err := f.Seek(0, io.SeekStart); err != nil {
				return fmt.Errorf("seeking log file: %w", err)
			}

			out := bufio.NewWriter(cmd.OutOrStdout())
			defer out.Flush()

			if string(magic[:]) == encryptedlog.Magic {
				reader, err := openStackLog(cmd.Context(), ws, stackName, configFile, f)
				if err != nil {
					return err
				}
				return formatLogRecords(reader, out, false)
			}

			gz, err := gzip.NewReader(f)
			if err != nil {
				return fmt.Errorf("log file is neither encrypted nor gzip-compressed: %w", err)
			}
			defer gz.Close()

			return formatLogRecords(gz, out, false)
		},
	}

	command.Flags().StringVar(&configFile, "config-file", "",
		"Use the cloud secrets key from this stack configuration file")
	command.Flags().BoolVar(&latest, "latest", false,
		"Decrypt the most recent log file without prompting")

	return command
}

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

// stackNameFromFilename extracts the stack name from a log filename.
// Files are named "<stack>-<timestamp>[-<updateid>].log" where "/" in
// stack names is replaced with "+".
func stackNameFromFilename(name string) string {
	loc := logTimestampRe.FindStringIndex(name)
	if loc == nil {
		return ""
	}
	prefix := strings.TrimSuffix(name[:loc[0]], "-")
	if prefix == "" {
		return ""
	}
	return strings.ReplaceAll(prefix, "+", "/")
}

// secretsManagerFromStack reconstructs the secrets manager from the
// stack's stored deployment.
func secretsManagerFromStack(ctx context.Context, s backend.Stack) (secrets.Manager, error) {
	dep, err := s.Backend().ExportDeployment(ctx, s)
	if err != nil {
		return nil, fmt.Errorf("exporting deployment: %w", err)
	}
	if dep == nil || len(dep.Deployment) == 0 {
		return nil, errors.New("stack has no deployment")
	}

	var v3 apitype.DeploymentV3
	if err := json.Unmarshal(dep.Deployment, &v3); err != nil {
		return nil, fmt.Errorf("unmarshaling deployment: %w", err)
	}
	if v3.SecretsProviders == nil {
		return nil, errors.New("deployment has no secrets provider configured")
	}

	provider := backend_secrets.NewNamedStackProvider(
		s.Ref().Name().String(), cmdBackend.DefaultLoginManager.ClientSource().ClientForURL)
	return provider.OfType(ctx, v3.SecretsProviders.Type, v3.SecretsProviders.State)
}

func currentStackName(ws pkgWorkspace.Context) string {
	w, err := ws.New("")
	if err != nil {
		return ""
	}
	backendURL, _ := pkgWorkspace.GetCurrentCloudURL(ws, env.Global(), nil)
	name, _ := w.Settings().StackForBackend(backendURL)
	return name
}

var logTimestampRe = regexp.MustCompile(`(\d{8}T\d{6})`)

// findLatestLog returns the path to the most recent .log file in
// ~/.pulumi/logs/. With a stack name, it prefers files for that stack.
// Without a stack name, it prefers "pulumi-" prefixed CLI-level logs.
func findLatestLog(stackName string) (string, error) {
	logsDir, err := workspace.GetPulumiPath("logs")
	if err != nil {
		return "", fmt.Errorf("getting log directory: %w", err)
	}

	entries, err := listLogs(logsDir)
	if err != nil {
		return "", err
	}
	if len(entries) == 0 {
		return "", fmt.Errorf("no log files found in %s", logsDir)
	}

	if stackName != "" {
		for _, e := range entries {
			if e.stack == stackName {
				return e.path, nil
			}
		}
	} else {
		for _, e := range entries {
			if e.cliLevel {
				return e.path, nil
			}
		}
	}

	return entries[0].path, nil
}

// chooseLog prompts the user to pick a log file from ~/.pulumi/logs/.
// If stackName is non-empty, the list is filtered to logs for that
// stack. The prompt parameter is used as the survey message.
func chooseLog(stackName, prompt string) (string, error) {
	logsDir, err := workspace.GetPulumiPath("logs")
	if err != nil {
		return "", fmt.Errorf("getting log directory: %w", err)
	}

	entries, err := listLogs(logsDir)
	if err != nil {
		return "", err
	}

	if stackName != "" {
		var filtered []logEntry
		for _, e := range entries {
			if e.stack == stackName {
				filtered = append(filtered, e)
			}
		}
		entries = filtered
	}

	if len(entries) == 0 {
		if stackName != "" {
			return "", fmt.Errorf("no log files found for stack %q in %s", stackName, logsDir)
		}
		return "", fmt.Errorf("no log files found in %s", logsDir)
	}

	if !cmdutil.Interactive() {
		return "", errors.New(
			"cannot prompt for a log file in non-interactive mode; " +
				"pass --latest or a filename argument")
	}

	options, optionMap := formatLogChoices(entries)

	var choice string
	if err := ui.AskOne(&survey.Select{
		Message:  prompt,
		Options:  options,
		PageSize: cmd.OptimalPageSize(cmd.OptimalPageSizeOpts{Nopts: len(options)}),
	}, &choice, ui.SurveyIcons(cmdutil.GetGlobalColorization())); err != nil {
		return "", errors.New("no log file selected")
	}

	return optionMap[choice], nil
}

// formatLogChoices builds aligned "STACK  CREATED  UPDATE ID" rows for
// the chooser and returns the rows alongside a map from row back to log
// path.
func formatLogChoices(entries []logEntry) ([]string, map[string]string) {
	type row struct {
		stack, created, updateID, path string
	}

	rows := make([]row, len(entries))
	stackWidth, createdWidth := 0, 0
	for i, e := range entries {
		stack := e.stackDisplay()
		updateID := e.updateID
		if updateID == "" {
			updateID = "—"
		}
		created := humanize.Time(e.timestamp)

		rows[i] = row{
			stack:    stack,
			created:  created,
			updateID: updateID,
			path:     e.path,
		}
		if l := len(stack); l > stackWidth {
			stackWidth = l
		}
		if l := len(created); l > createdWidth {
			createdWidth = l
		}
	}

	options := make([]string, len(rows))
	optionMap := make(map[string]string, len(rows))
	for i, r := range rows {
		// Append the index to disambiguate identical (stack, created,
		// updateID) rows that map to different files.
		line := fmt.Sprintf("%-*s  %-*s  %s", stackWidth, r.stack, createdWidth, r.created, r.updateID)
		if _, dup := optionMap[line]; dup {
			line = fmt.Sprintf("%s  [%d]", line, i+1)
		}
		options[i] = line
		optionMap[line] = r.path
	}
	return options, optionMap
}

func parseLogTimestamp(name string) (time.Time, bool) {
	m := logTimestampRe.FindString(name)
	if m == "" {
		return time.Time{}, false
	}
	t, err := time.ParseInLocation("20060102T150405", m, time.Local)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// formatLogRecords reads JSON log lines from r, reconstructs formatted
// messages from pulumi.log.arg* fields, removes those fields, and
// writes the resulting JSON to w.
func formatLogRecords(r io.Reader, w io.Writer, redactSecrets bool) error {
	scanner := bufio.NewScanner(r)
	enc := json.NewEncoder(w)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var rec map[string]any
		if err := json.Unmarshal(line, &rec); err != nil {
			// Not JSON — write through as-is (e.g. old plain-text logs).
			fmt.Fprintf(w, "%s\n", line)
			continue
		}

		// Collect pulumi.log.argN keys in order, reconstruct the
		// formatted message, and delete the arg keys.
		var argKeys []string
		for k := range rec {
			if strings.HasPrefix(k, "pulumi.log.arg") {
				argKeys = append(argKeys, k)
			}
		}
		if len(argKeys) > 0 {
			sort.Strings(argKeys)
			args := make([]any, len(argKeys))
			for i, k := range argKeys {
				v := decodePropertyArg(rec[k])
				if redactSecrets {
					redactSecretsInValue(v)
				}
				args[i] = v
				delete(rec, k)
			}
			if msg, ok := rec["msg"].(string); ok {
				rec["msg"] = fmt.Sprintf(msg, args...)
			}
		}

		if redactSecrets {
			redactSecretsInValue(rec)
		}

		if err := enc.Encode(rec); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func decodePropertyArg(v any) any {
	s, ok := v.(string)
	if !ok {
		return v
	}
	if sv, err := logging.DecodeStructValueFromLog([]byte(s)); err == nil {
		return sv.AsInterface()
	}
	return v
}
