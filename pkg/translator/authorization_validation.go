/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package translator

import (
	"fmt"

	agenticv1alpha2 "sigs.k8s.io/kube-agentic-networking/api/v1alpha2"
)

// ValidateAuthorization reports whether an authorization block can be translated
// without widening access. A nil block is valid and means "allow everything from the
// rule's source". A non-nil block must be an Inline rule with at least one matcher or
// a CEL rule with a CEL expression. Anything else is rejected so it can never match
// all traffic by accident.
func ValidateAuthorization(auth *agenticv1alpha2.AuthorizationRule) error {
	if auth == nil {
		return nil
	}
	switch auth.Type {
	case agenticv1alpha2.AuthorizationRuleTypeInline:
		if len(auth.Methods) == 0 && len(auth.Paths) == 0 && len(auth.Headers) == 0 &&
			len(auth.Hosts) == 0 && len(auth.Ports) == 0 {
			return fmt.Errorf("Inline authorization must specify at least one matcher (methods, paths, headers, hosts, or ports)")
		}
	case agenticv1alpha2.AuthorizationRuleTypeCEL:
		if auth.CEL == nil {
			return fmt.Errorf("cel must be specified when type is set to 'CEL'")
		}
	default:
		return fmt.Errorf("unsupported authorization type %q", auth.Type)
	}
	return nil
}
