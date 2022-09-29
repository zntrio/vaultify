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

package transit

import (
	"context"
	"crypto"
)

// Encryptor describes encryption operations contract.
type Encryptor interface {
	Encrypt(ctx context.Context, cleartext []byte) ([]byte, error)
}

// Decryptor describes decryption operations contract.
type Decryptor interface {
	Decrypt(ctx context.Context, encrypted []byte) ([]byte, error)
}

// Signer represents signature creation operations contract.
type Signer interface {
	Sign(ctx context.Context, protected []byte) ([]byte, error)
}

// Verifier represents signature verification operations contract.
type Verifier interface {
	Verify(ctx context.Context, protected, signature []byte) error
}

// PublicKeyExporter represents public key operations contract.
type PublicKeyExporter interface {
	PublicKey(ctx context.Context) (crypto.PublicKey, error)
}

// Service represents the Vault Transit backend operation service contract.
type Service interface {
	Encryptor
	Decryptor
	Signer
	Verifier
	PublicKeyExporter
}

type keyType int

const (
	keyTypeRsa keyType = iota
	keyTypeEd25519
	keyTypeEcdsa
)
