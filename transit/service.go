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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/hashicorp/vault/api"
	"github.com/mitchellh/mapstructure"

	"zntr.io/vaultify/logical"
	vpath "zntr.io/vaultify/path"
)

type service struct {
	logical   logical.Logical
	mountPath string
	keyName   string

	keyType    keyType
	publicKey  crypto.PublicKey
	canSign    bool
	canEncrypt bool
	canDecrypt bool
}

// New instantiates a Vault transit backend encryption service.
func New(client *api.Client, mountPath, keyName string) (Service, error) {
	return &service{
		logical:   client.Logical(),
		mountPath: strings.TrimSuffix(path.Clean(mountPath), "/"),
		keyName:   keyName,
	}, nil
}

// -----------------------------------------------------------------------------

func (s *service) Encrypt(ctx context.Context, cleartext []byte) ([]byte, error) {
	// Prepare query
	encryptPath := vpath.SanitizePath(path.Join(url.PathEscape(s.mountPath), "encrypt", url.PathEscape(s.keyName)))
	data := map[string]interface{}{
		"plaintext": base64.StdEncoding.EncodeToString(cleartext),
	}

	// Send to Vault.
	secret, err := s.logical.WriteWithContext(ctx, encryptPath, data)
	if err != nil {
		return nil, fmt.Errorf("unable to encrypt with '%s' key: %w", s.keyName, err)
	}

	// Check response wrapping
	if secret.WrapInfo != nil {
		// Unwrap with response token
		secret, err = s.logical.UnwrapWithContext(ctx, secret.WrapInfo.Token)
		if err != nil {
			return nil, fmt.Errorf("unable to unwrap the response: %w", err)
		}
	}

	// Parse server response.
	if cipherText, ok := secret.Data["ciphertext"].(string); ok && cipherText != "" {
		return []byte(cipherText), nil
	}

	// Return error.
	return nil, errors.New("could not encrypt given data")
}

func (s *service) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	// Prepare query
	decryptPath := vpath.SanitizePath(path.Join(url.PathEscape(s.mountPath), "decrypt", url.PathEscape(s.keyName)))
	data := map[string]interface{}{
		"ciphertext": string(ciphertext),
	}

	// Send to Vault.
	secret, err := s.logical.WriteWithContext(ctx, decryptPath, data)
	if err != nil {
		return nil, fmt.Errorf("unable to decrypt with '%s' key: %w", s.keyName, err)
	}

	// Check response wrapping
	if secret.WrapInfo != nil {
		// Unwrap with response token
		secret, err = s.logical.UnwrapWithContext(ctx, secret.WrapInfo.Token)
		if err != nil {
			return nil, fmt.Errorf("unable to unwrap the response: %w", err)
		}
	}

	// Parse server response.
	if plainText64, ok := secret.Data["plaintext"].(string); ok && plainText64 != "" {
		plainText, err := base64.StdEncoding.DecodeString(plainText64)
		if err != nil {
			return nil, fmt.Errorf("unable to decode secret: %w", err)
		}

		// Return no error
		return plainText, nil
	}

	// Return error.
	return nil, errors.New("could not decrypt given data")
}

func (s *service) Sign(ctx context.Context, protected []byte) ([]byte, error) {
	// Prepare query
	signPath := vpath.SanitizePath(path.Join(url.PathEscape(s.mountPath), "sign", url.PathEscape(s.keyName)))
	data := map[string]interface{}{
		"input":                base64.StdEncoding.EncodeToString(protected),
		"marshaling_algorithm": "jws",
	}

	// Send to Vault.
	secret, err := s.logical.WriteWithContext(ctx, signPath, data)
	if err != nil {
		return nil, fmt.Errorf("unable to sign with '%s' key: %w", s.keyName, err)
	}

	// Check response wrapping
	if secret.WrapInfo != nil {
		// Unwrap with response token
		secret, err = s.logical.UnwrapWithContext(ctx, secret.WrapInfo.Token)
		if err != nil {
			return nil, fmt.Errorf("unable to unwrap the response: %w", err)
		}
	}

	// Parse server response.
	if signature, ok := secret.Data["signature"].(string); ok && signature != "" {
		sigRaw, err := base64.RawURLEncoding.DecodeString(signature[9:])
		if err != nil {
			return nil, errors.New("unable to decode signature")
		}

		// Decoded signature
		return sigRaw, nil
	}

	// Return error.
	return nil, errors.New("could not sign given data")
}

func (s *service) Verify(ctx context.Context, protected, signature []byte) error {
	// Prepare query
	signPath := vpath.SanitizePath(path.Join(url.PathEscape(s.mountPath), "verify", url.PathEscape(s.keyName)))
	data := map[string]interface{}{
		"input":                base64.StdEncoding.EncodeToString(protected),
		"signature":            fmt.Sprintf("vault:v1:%s", base64.RawURLEncoding.EncodeToString(signature)),
		"marshaling_algorithm": "jws",
	}

	// Send to Vault.
	secret, err := s.logical.WriteWithContext(ctx, signPath, data)
	if err != nil {
		return fmt.Errorf("unable to verify with '%s' key: %w", s.keyName, err)
	}

	// Check response wrapping
	if secret.WrapInfo != nil {
		// Unwrap with response token
		secret, err = s.logical.UnwrapWithContext(ctx, secret.WrapInfo.Token)
		if err != nil {
			return fmt.Errorf("unable to unwrap the response: %w", err)
		}
	}

	// Parse server response.
	if valid, ok := secret.Data["valid"].(bool); ok && valid {
		return nil
	}

	// Return error.
	return errors.New("could not verify the given signature")
}

func (s *service) PublicKey(ctx context.Context) (crypto.PublicKey, error) {
	// Check public key lazy loading
	if s.publicKey == nil {
		if err := s.resolveKeyCapabilities(ctx); err != nil {
			return nil, err
		}
	}

	return s.publicKey, nil
}

// -----------------------------------------------------------------------------

func (s *service) resolveKeyCapabilities(ctx context.Context) error {
	// Prepare query
	keyPath := vpath.SanitizePath(path.Join(url.PathEscape(s.mountPath), "keys", url.PathEscape(s.keyName)))

	// Send to Vault.
	response, err := s.logical.ReadWithContext(ctx, keyPath)
	if response == nil || err != nil {
		return fmt.Errorf("unable to retrieve key information with '%s' key: %w", s.keyName, err)
	}

	// Decode key information
	keyInfo := struct {
		KeyType            string      `mapstructure:"type"`
		Keys               interface{} `mapstructure:"keys"`
		LatestVersion      int         `mapstructure:"latest_version"`
		SupportsSigning    bool        `mapstructure:"supports_signing"`
		SupportsEncryption bool        `mapstructure:"supports_encryption"`
		SupportsDecryption bool        `mapstructure:"supports_decryption"`
	}{}
	if errKi := mapstructure.WeakDecode(response.Data, &keyInfo); errKi != nil {
		return fmt.Errorf("unable to decode '%s' key information: %w", s.keyName, errKi)
	}

	// Add local keytype
	switch keyInfo.KeyType {
	case "rsa-2048", "rsa-3072", "rsa-4096":
		s.keyType = keyTypeRsa
	case "ecdsa-p256", "ecdsa-p384", "ecdsa-p521":
		s.keyType = keyTypeEcdsa
	case "ed25519":
		s.keyType = keyTypeEd25519
	default:
		return errors.New("unsupported key type")
	}

	// Check public key
	if !keyInfo.SupportsSigning {
		return fmt.Errorf("%q key doesn't support signing hence there is no public key", s.keyName)
	}

	// Extract public key
	publicKeyInfo := map[int]struct {
		PublicKey string `mapstructure:"public_key"`
	}{}
	if errPki := mapstructure.WeakDecode(keyInfo.Keys, &publicKeyInfo); errPki != nil {
		return fmt.Errorf("unable to decode public key structure: %w", errPki)
	}

	// Decode public key
	pub, err := s.createPublicKey(publicKeyInfo[keyInfo.LatestVersion].PublicKey)
	if err != nil {
		return fmt.Errorf("unable to retrieve latest public key version: %w", err)
	}

	// Assign to service
	s.publicKey = pub
	s.canDecrypt = keyInfo.SupportsDecryption
	s.canEncrypt = keyInfo.SupportsEncryption
	s.canSign = keyInfo.SupportsSigning

	return nil
}

func (s *service) createPublicKey(keyData string) (crypto.PublicKey, error) {
	switch s.keyType {
	case keyTypeRsa:
		block, _ := pem.Decode([]byte(keyData))
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		key, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("unable to cast to RSA public key")
		}
		return key, nil
	case keyTypeEcdsa:
		block, _ := pem.Decode([]byte(keyData))
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		key, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("unable to cast to ECDSA public key")
		}
		return key, nil
	case keyTypeEd25519:
		key, err := base64.StdEncoding.DecodeString(keyData)
		if err != nil {
			return nil, err
		}
		return ed25519.PublicKey(key), nil
	}
	return nil, errors.New("unknown public key type")
}
