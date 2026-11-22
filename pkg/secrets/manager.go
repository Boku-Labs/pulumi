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

// Package secrets defines the interface common to all secret managers.
package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"gocloud.dev/gcerrors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pulumi/pulumi/sdk/v3/go/common/resource/config"
)

// Manager provides the interface for providing stack encryption.
type Manager interface {
	// Type returns a string that reflects the type of this provider. This is serialized along with the state of
	// the manager into the deployment such that we can re-construct the correct manager when deserializing a
	// deployment into a snapshot.
	Type() string
	// An opaque JSON blob, which can be used later to reconstruct the provider when deserializing the
	// deployment into a snapshot.
	State() json.RawMessage
	// Encrypter returns a `config.Encrypter` that can be used to encrypt values when serializing a snapshot into a
	// deployment.
	Encrypter() config.Encrypter
	// Decrypter returns a `config.Decrypter` that can be used to decrypt values when deserializing a snapshot from a
	// deployment.
	Decrypter() config.Decrypter
}

// AreCompatible returns true if the two Managers are of the same type and have the same state.
func AreCompatible(a, b Manager) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}

	if a.Type() != b.Type() {
		return false
	}

	as := a.State()
	bs := b.State()
	return bytes.Equal(as, bs)
}

// IsCancellationError reports whether a secrets operation was canceled or exceeded its deadline.
func IsCancellationError(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, gcerrors.ErrCanceled) || errors.Is(err, gcerrors.ErrDeadlineExceeded) {
		return true
	}
	code := status.Code(err)
	return code == codes.Canceled || code == codes.DeadlineExceeded
}

// EncrypterWithContext carries a command's context through config APIs that
// do not accept one.
type EncrypterWithContext struct {
	Context context.Context
	config.Encrypter
}

func (e EncrypterWithContext) EncryptValue(_ context.Context, value string) (string, error) {
	return e.Encrypter.EncryptValue(e.Context, value)
}

func (e EncrypterWithContext) BatchEncrypt(_ context.Context, values []string) ([]string, error) {
	return e.Encrypter.BatchEncrypt(e.Context, values)
}

// DecrypterWithContext carries a command's context through config APIs that
// do not accept one.
type DecrypterWithContext struct {
	Context context.Context
	config.Decrypter
}

func (d DecrypterWithContext) DecryptValue(_ context.Context, value string) (string, error) {
	return d.Decrypter.DecryptValue(d.Context, value)
}

func (d DecrypterWithContext) BatchDecrypt(_ context.Context, values []string) ([]string, error) {
	return d.Decrypter.BatchDecrypt(d.Context, values)
}
