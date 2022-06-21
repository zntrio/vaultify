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

package kv_test

import (
	"context"
	"errors"
	"fmt"
	"os"

	"zntr.io/vaultify"
	"zntr.io/vaultify/kv"
)

func ExampleSecretWriter_Write() {
	// Initialize Vault service
	factory, err := vaultify.DefaultClient()
	if err != nil {
		panic(err)
	}

	// Initialze a KV service with KV backend version detection
	secrets, err := factory.KV("secrets")
	if err != nil {
		panic(err)
	}

	ctx := context.Background()

	// Write to Vault
	if err := secrets.Write(ctx, "production/security/databases/billing/admin_account", kv.SecretData{
		"account":  "pga_1234567",
		"password": "562y6RpswrvDz7D2VtiX8xBVg2a8mlG8",
	}); err != nil {
		panic(err)
	}
}

func ExampleSecretWriter_WriteWithMeta() {
	// Initialize Vault service
	factory, err := vaultify.DefaultClient()
	if err != nil {
		panic(err)
	}

	// Initialze a KV service with KV backend version detection
	secrets, err := factory.KV("secrets", kv.WithVaultMetatadata(true))
	if err != nil {
		panic(err)
	}

	ctx := context.Background()

	// Write to Vault
	if err := secrets.WriteWithMeta(ctx, "production/security/databases/billing/admin_account", kv.SecretData{
		"account":  "pga_1234567",
		"password": "562y6RpswrvDz7D2VtiX8xBVg2a8mlG8",
	}, kv.SecretMetadata{
		"owner": "cloudops",
	}); err != nil {
		panic(err)
	}
}

func ExampleSecretLister_List() {
	// Initialize Vault service
	factory, err := vaultify.DefaultClient()
	if err != nil {
		panic(err)
	}

	// Initialze a KV service with KV backend version detection
	secrets, err := factory.KV("secrets")
	if err != nil {
		panic(err)
	}

	ctx := context.Background()

	// Read from Vault
	paths, err := secrets.List(ctx, "production")
	switch {
	case errors.Is(err, kv.ErrPathNotFound):
		// Path not found
	default:
	}

	fmt.Fprintf(os.Stdout, "Paths: %v\n", paths)
}

func ExampleSecretReader_Read() {
	// Initialize Vault service
	factory, err := vaultify.DefaultClient()
	if err != nil {
		panic(err)
	}

	// Initialze a KV service with KV backend version detection
	secrets, err := factory.KV("secrets")
	if err != nil {
		panic(err)
	}

	ctx := context.Background()

	// Read from Vault
	data, meta, err := secrets.Read(ctx, "production/security/databases/billing/admin_account")
	switch {
	case errors.Is(err, kv.ErrPathNotFound):
		// Path not found
	case errors.Is(err, kv.ErrNoData):
		// Secret returned a nil data object
	default:
	}

	fmt.Fprintf(os.Stdout, "Data: %v\n", data)
	fmt.Fprintf(os.Stdout, "Meta: %v\n", meta)
}
