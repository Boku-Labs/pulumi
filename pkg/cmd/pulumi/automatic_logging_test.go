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

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConfigSetSecretSkipsAutomaticFileLogging(t *testing.T) {
	t.Setenv("PULUMI_SKIP_UPDATE_CHECK", "true")
	t.Setenv("PULUMI_HIDE_NOTIFICATIONS", "true")
	t.Chdir(t.TempDir())

	for _, tc := range []struct {
		name    string
		args    []string
		wantLog bool
	}{
		{"explicit secret", []string{"set", "--secret", "key", "test-value"}, false},
		{"false secret flag", []string{"set", "--secret=false", "key", "test-value"}, true},
		{"set-all secret", []string{"set-all", "--secret", "key=test-value"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("PULUMI_HOME", home)
			pulumiCmd, cleanup := NewPulumiCmd()
			defer cleanup()
			pulumiCmd.SetArgs(append([]string{"config"}, tc.args...))

			require.ErrorContains(t, pulumiCmd.Execute(), "no Pulumi.yaml project file found")
			entries, err := os.ReadDir(filepath.Join(home, "logs"))
			if tc.wantLog {
				require.NoError(t, err)
				require.Len(t, entries, 1)
			} else {
				require.ErrorIs(t, err, os.ErrNotExist)
			}
		})
	}
}
