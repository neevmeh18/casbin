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
	"fmt"

	"github.com/casbin/casbin/v3/model"
)

// PolicyValidator validates a fully loaded candidate policy before it becomes
// active. Validators must return an error for any policy that must not be used
// for authorization decisions.
type PolicyValidator interface {
	ValidatePolicy(model.Model) error
}

// PolicyValidatorFunc adapts a function into a PolicyValidator.
type PolicyValidatorFunc func(model.Model) error

// ValidatePolicy implements PolicyValidator.
func (f PolicyValidatorFunc) ValidatePolicy(m model.Model) error {
	return f(m)
}

// AddPolicyValidator adds a validation step to policy reloads.
// Validators run after the candidate policy is loaded and sorted, but before
// it can replace the active policy.
func (e *Enforcer) AddPolicyValidator(validator PolicyValidator) {
	if validator == nil {
		return
	}
	e.policyValidators = append(e.policyValidators, validator)
}

// SetPolicyValidators replaces all policy reload validators.
func (e *Enforcer) SetPolicyValidators(validators ...PolicyValidator) {
	e.policyValidators = append([]PolicyValidator(nil), validators...)
}

// validatePolicyReload checks a defensive copy so validators cannot mutate the
// candidate that will later become active.
func (e *Enforcer) validatePolicyReload(candidate model.Model) error {
	for i, validator := range e.policyValidators {
		if validator == nil {
			continue
		}
		if err := validator.ValidatePolicy(candidate.Copy()); err != nil {
			return fmt.Errorf("load policy: validator %d rejected candidate: %w", i, err)
		}
	}
	return nil
}
