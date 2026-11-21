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

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValueChunks(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		limit  int
		values []string
		want   [][]string
	}{
		{
			name: "pack exact fit", limit: 5,
			values: []string{"abc", "de", "xy", "z"},
			want:   [][]string{{"abc", "de"}, {"xy", "z"}},
		},
		{
			name: "split an oversized value", limit: 3,
			values: []string{"a", "large", "", "b", "cd", "ef"},
			want:   [][]string{{"a"}, {"large"}, {"", "b", "cd"}, {"ef"}},
		},
		{
			name: "reset running size after a split", limit: 4,
			values: []string{"abc", "de", "fg", "h", "ijk"},
			want:   [][]string{{"abc"}, {"de", "fg"}, {"h", "ijk"}},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var chunks valueChunks
			for _, value := range test.values {
				chunks.add(value, test.limit)
			}
			assert.Equal(t, test.want, chunks.chunks)
		})
	}
}
