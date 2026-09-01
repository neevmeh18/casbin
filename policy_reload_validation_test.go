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
	"github.com/casbin/casbin/v3/persist"
	"github.com/casbin/casbin/v3/rbac"
)

type retainingPolicyAdapter struct {
	retained model.Model
	lines    []string
}

func (a *retainingPolicyAdapter) LoadPolicy(m model.Model) error {
	a.retained = m
	for _, line := range a.lines {
		if err := persist.LoadPolicyLine(line, m); err != nil {
			return err
		}
	}
	return nil
}

func (a *retainingPolicyAdapter) SavePolicy(model.Model) error { return errors.New(notImplemented) }
func (a *retainingPolicyAdapter) AddPolicy(string, string, []string) error {
	return errors.New(notImplemented)
}
func (a *retainingPolicyAdapter) RemovePolicy(string, string, []string) error {
	return errors.New(notImplemented)
}
func (a *retainingPolicyAdapter) RemoveFilteredPolicy(string, string, int, ...string) error {
	return errors.New(notImplemented)
}

type panicPolicyDetector struct{}

func (panicPolicyDetector) Check(rbac.RoleManager) error {
	panic("detector bug")
}

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

func TestFailedRoleLinkRebuildRestoresActiveAuthorizationState(t *testing.T) {
	policyFile := filepath.Join(t.TempDir(), "policy.csv")
	initialPolicy := "p, data2_admin, data2, read\ng, alice, data2_admin\n"
	if err := os.WriteFile(policyFile, []byte(initialPolicy), 0o600); err != nil {
		t.Fatal(err)
	}

	e, err := NewEnforcer("examples/rbac_model.conf", policyFile)
	if err != nil {
		t.Fatal(err)
	}

	allowed, err := e.Enforce("alice", "data2", "read")
	if err != nil || !allowed {
		t.Fatalf("expected initial role authorization to work, allowed=%v err=%v", allowed, err)
	}

	// This candidate has an invalid grouping rule and fails while rebuilding
	// role links after loading. The active model and role-manager state must stay
	// equivalent to the previous policy.
	invalidPolicy := "p, data2_admin, data2, read\ng, alice\n"
	if err := os.WriteFile(policyFile, []byte(invalidPolicy), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := e.LoadPolicy(); err == nil || !strings.Contains(err.Error(), "role-link rebuild failed") {
		t.Fatalf("expected role-link rebuild failure, got %v", err)
	}

	allowed, err = e.Enforce("alice", "data2", "read")
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Fatal("failed reload corrupted the previously active role authorization state")
	}
}

func TestPolicyReloadValidatorPanicFailsClosed(t *testing.T) {
	policyFile := filepath.Join(t.TempDir(), "policy.csv")
	if err := os.WriteFile(policyFile, []byte("p, alice, data1, read\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	e, err := NewEnforcer("examples/basic_model.conf", policyFile)
	if err != nil {
		t.Fatal(err)
	}

	e.AddPolicyValidator(PolicyValidatorFunc(func(candidate model.Model) error {
		panic("validator bug")
	}))

	if err := os.WriteFile(policyFile, []byte("p, mallory, data1, read\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	err = e.LoadPolicy()
	if err == nil || !strings.Contains(err.Error(), "validator panic") {
		t.Fatalf("expected validator panic to reject reload, got %v", err)
	}

	allowed, err := e.Enforce("alice", "data1", "read")
	if err != nil || !allowed {
		t.Fatalf("active policy changed after validator panic, allowed=%v err=%v", allowed, err)
	}
}

func TestSyncedPolicyReloadHoldsTransactionLock(t *testing.T) {
	policyFile := filepath.Join(t.TempDir(), "policy.csv")
	if err := os.WriteFile(policyFile, []byte("p, alice, data1, read\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	e, err := NewSyncedEnforcer("examples/basic_model.conf", policyFile)
	if err != nil {
		t.Fatal(err)
	}

	entered := make(chan struct{})
	release := make(chan struct{})
	e.AddPolicyValidator(PolicyValidatorFunc(func(candidate model.Model) error {
		close(entered)
		<-release
		return nil
	}))

	done := make(chan error, 1)
	go func() {
		done <- e.LoadPolicy()
	}()

	<-entered
	if e.m.TryLock() {
		e.m.Unlock()
		close(release)
		<-done
		t.Fatal("synced reload released its write lock before validation/apply completed")
	}

	close(release)
	if err := <-done; err != nil {
		t.Fatalf("LoadPolicy failed: %v", err)
	}
}

func TestPolicyReloadValidatorHasNoLiveRoleManagerHandles(t *testing.T) {
	policyFile := filepath.Join(t.TempDir(), "policy.csv")
	policy := "p, data2_admin, data2, read\ng, alice, data2_admin\n"
	if err := os.WriteFile(policyFile, []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}

	e, err := NewEnforcer("examples/rbac_model.conf", policyFile)
	if err != nil {
		t.Fatal(err)
	}

	e.AddPolicyValidator(PolicyValidatorFunc(func(candidate model.Model) error {
		for _, section := range candidate {
			for _, assertion := range section {
				if assertion.RM != nil || assertion.CondRM != nil {
					return errors.New("validator received live role-manager handle")
				}
			}
		}
		return nil
	}))

	if err := e.LoadPolicy(); err != nil {
		t.Fatalf("isolated validation view was not provided: %v", err)
	}
}

func TestPolicyReloadBreaksAdapterAliasBeforeCommit(t *testing.T) {
	adapter := &retainingPolicyAdapter{lines: []string{"p, alice, data1, read"}}
	e, err := NewEnforcer("examples/basic_model.conf", adapter)
	if err != nil {
		t.Fatal(err)
	}

	if adapter.retained == nil {
		t.Fatal("adapter did not retain its load target")
	}
	adapter.retained["p"]["p"].Policy[0][0] = "mallory"

	if got := e.model["p"]["p"].Policy[0][0]; got != "alice" {
		t.Fatalf("adapter alias mutated active policy after commit: %q", got)
	}
}

func TestPolicyReloadAdapterCannotReachLiveRoleManagers(t *testing.T) {
	adapter := &retainingPolicyAdapter{
		lines: []string{"p, data2_admin, data2, read", "g, alice, data2_admin"},
	}
	e, err := NewEnforcer("examples/rbac_model.conf", adapter)
	if err != nil {
		t.Fatal(err)
	}

	for _, section := range adapter.retained {
		for _, assertion := range section {
			if assertion.RM != nil || assertion.CondRM != nil {
				t.Fatal("adapter load target exposed live role-manager state")
			}
		}
	}

	linked, err := e.GetRoleManager().HasLink("alice", "data2_admin")
	if err != nil || !linked {
		t.Fatalf("committed policy did not rebuild role links, linked=%v err=%v", linked, err)
	}
}

func TestPolicyReloadDetectorFailureRollsBackCandidate(t *testing.T) {
	policyFile := filepath.Join(t.TempDir(), "policy.csv")
	initialPolicy := "p, data2_admin, data2, read\ng, alice, data2_admin\n"
	if err := os.WriteFile(policyFile, []byte(initialPolicy), 0o600); err != nil {
		t.Fatal(err)
	}

	e, err := NewEnforcer("examples/rbac_model.conf", policyFile)
	if err != nil {
		t.Fatal(err)
	}

	cyclicPolicy := "p, data2_admin, data2, read\ng, alice, data2_admin\ng, data2_admin, alice\n"
	if err := os.WriteFile(policyFile, []byte(cyclicPolicy), 0o600); err != nil {
		t.Fatal(err)
	}

	err = e.LoadPolicy()
	if err == nil || !strings.Contains(err.Error(), "detector rejected candidate") {
		t.Fatalf("expected detector rejection, got %v", err)
	}

	if got := e.model["g"]["g"].Policy; len(got) != 1 {
		t.Fatalf("detector-rejected candidate became active: %#v", got)
	}
	linked, err := e.GetRoleManager().HasLink("alice", "data2_admin")
	if err != nil || !linked {
		t.Fatalf("old role state was not restored, linked=%v err=%v", linked, err)
	}
}

func TestPolicyReloadDetectorPanicFailsClosed(t *testing.T) {
	policyFile := filepath.Join(t.TempDir(), "policy.csv")
	initial := "p, data2_admin, data2, read\ng, alice, data2_admin\n"
	if err := os.WriteFile(policyFile, []byte(initial), 0o600); err != nil {
		t.Fatal(err)
	}

	e, err := NewEnforcer("examples/rbac_model.conf", policyFile)
	if err != nil {
		t.Fatal(err)
	}
	e.SetDetector(panicPolicyDetector{})

	candidate := "p, data2_admin, data2, read\ng, mallory, data2_admin\n"
	if err := os.WriteFile(policyFile, []byte(candidate), 0o600); err != nil {
		t.Fatal(err)
	}
	err = e.LoadPolicy()
	if err == nil || !strings.Contains(err.Error(), "detector panic") {
		t.Fatalf("expected detector panic to reject reload, got %v", err)
	}
	if got := e.model["g"]["g"].Policy[0][0]; got != "alice" {
		t.Fatalf("detector panic changed active policy: %q", got)
	}
	linked, err := e.GetRoleManager().HasLink("alice", "data2_admin")
	if err != nil || !linked {
		t.Fatalf("detector panic did not restore old role state, linked=%v err=%v", linked, err)
	}
}

func TestUnpreparedPolicyReloadCannotCommit(t *testing.T) {
	e, err := NewEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
	if err != nil {
		t.Fatal(err)
	}

	before := e.model["p"]["p"].Policy[0][0]
	if err := e.applyModifiedModel(preparedPolicyReload{}); err == nil {
		t.Fatal("zero-value reload plan was accepted")
	}
	if after := e.model["p"]["p"].Policy[0][0]; after != before {
		t.Fatalf("unprepared commit changed active policy: before=%q after=%q", before, after)
	}
}
