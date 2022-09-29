// Licensed to zntr.io under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. zntr.io licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package logical

import (
	"context"

	"github.com/hashicorp/vault/api"
)

//go:generate mockgen -destination logical.mock.go -package logical zntr.io/vaultify/logical Logical

// Logical backend interface
type Logical interface {
	ReadWithContext(ctx context.Context, path string) (*api.Secret, error)
	ReadWithDataWithContext(ctx context.Context, path string, data map[string][]string) (*api.Secret, error)
	WriteWithContext(ctx context.Context, path string, data map[string]interface{}) (*api.Secret, error)
	WriteBytesWithContext(ctx context.Context, path string, data []byte) (*api.Secret, error)
	ListWithContext(ctx context.Context, path string) (*api.Secret, error)
	UnwrapWithContext(ctx context.Context, token string) (*api.Secret, error)
	DeleteWithContext(ctx context.Context, path string) (*api.Secret, error)
	DeleteWithDataWithContext(ctx context.Context, path string, data map[string][]string) (*api.Secret, error)
}
