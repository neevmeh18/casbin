// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package casbin

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/casbin/casbin/v3/model"
)

func TestPolicyReloadValidatorRejectsCandidateAtomically(t *testing.T) {
	policyFile := filepath.Join(t.TempDir(), "policy.csv")
	if err := os.WriteFile(policyFile, []byte("p, alice, data1, read\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	e, err := NewEnforcer("examples/basic_model.conf", policyFile)
	if err != nil {
		t.Fatal(err)
	}

	e.AddPolicyValidator(PolicyValidatorFunc(func(candidate model.Model) error {
		for _, rule := range candidate["p"]["p"].Policy {
			if len(rule) > 0 && rule[0] == "mallory" {
				return errors.New("forbidden subject")
			}
		}
		return nil
	}))

	if err := os.WriteFile(policyFile, []byte("p, mallory, data1, read\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	err = e.LoadPolicy()
	if err == nil || !strings.Contains(err.Error(), "validator 0 rejected candidate") {
		t.Fatalf("expected contextual validation error, got %v", err)
	}

	allowed, err := e.Enforce("alice", "data1", "read")
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Fatal("previously active policy was replaced after rejected reload")
	}

	allowed, err = e.Enforce("mallory", "data1", "read")
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Fatal("rejected candidate policy became active")
	}
}

func TestPolicyReloadValidatorCannotMutateCandidate(t *testing.T) {
	policyFile := filepath.Join(t.TempDir(), "policy.csv")
	if err := os.WriteFile(policyFile, []byte("p, alice, data1, read\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	e, err := NewEnforcer("examples/basic_model.conf", policyFile)
	if err != nil {
		t.Fatal(err)
	}

	e.AddPolicyValidator(PolicyValidatorFunc(func(candidate model.Model) error {
		candidate["p"]["p"].Policy[0][0] = "mallory"
		return nil
	}))

	if err := e.LoadPolicy(); err != nil {
		t.Fatal(err)
	}

	allowed, err := e.Enforce("alice", "data1", "read")
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Fatal("validator mutation leaked into active candidate policy")
	}

	allowed, err = e.Enforce("mallory", "data1", "read")
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Fatal("validator was able to mutate the candidate policy")
	}
}
