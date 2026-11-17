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
	"testing"

	agenticv1alpha2 "sigs.k8s.io/kube-agentic-networking/api/v1alpha2"
)

func TestValidateAuthorization(t *testing.T) {
	tests := []struct {
		name    string
		auth    *agenticv1alpha2.AuthorizationRule
		wantErr bool
	}{
		{"nil authorization allows all", nil, false},
		{"inline without matchers", &agenticv1alpha2.AuthorizationRule{Type: agenticv1alpha2.AuthorizationRuleTypeInline}, true},
		{"inline with empty headers", &agenticv1alpha2.AuthorizationRule{Type: agenticv1alpha2.AuthorizationRuleTypeInline, Headers: []agenticv1alpha2.HTTPHeaderMatch{}}, true},
		{"inline with ports only", &agenticv1alpha2.AuthorizationRule{Type: agenticv1alpha2.AuthorizationRuleTypeInline, Ports: []agenticv1alpha2.PortNumber{8080}}, false},
		{"inline with a header", &agenticv1alpha2.AuthorizationRule{Type: agenticv1alpha2.AuthorizationRuleTypeInline, Headers: []agenticv1alpha2.HTTPHeaderMatch{{Name: "x-example", Value: "v"}}}, false},
		{"cel without cel field", &agenticv1alpha2.AuthorizationRule{Type: agenticv1alpha2.AuthorizationRuleTypeCEL}, true},
		{"cel with expression", &agenticv1alpha2.AuthorizationRule{Type: agenticv1alpha2.AuthorizationRuleTypeCEL, CEL: &agenticv1alpha2.AccessPolicyCELRule{Expression: "true"}}, false},
		{"unknown type", &agenticv1alpha2.AuthorizationRule{Type: "Bogus"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateAuthorization(tt.auth); (err != nil) != tt.wantErr {
				t.Fatalf("ValidateAuthorization() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTranslateAccessRuleToRBACPolicyFailsClosed(t *testing.T) {
	tr := &Translator{}
	source := agenticv1alpha2.AccessRuleSource{
		Type:           agenticv1alpha2.AuthorizationSourceTypeServiceAccount,
		ServiceAccount: &agenticv1alpha2.AuthorizationSourceServiceAccount{Name: "sa", Namespace: "ns"},
	}

	// Positive control: a well-formed rule from the same source translates.
	ok := agenticv1alpha2.AccessRule{Name: "ok", Source: source, Authorization: &agenticv1alpha2.AuthorizationRule{
		Type: agenticv1alpha2.AuthorizationRuleTypeInline, Methods: []agenticv1alpha2.HTTPMethod{"GET"}}}
	if tr.translateAccessRuleToRBACPolicy("ns", ok) == nil {
		t.Fatal("expected the control rule to translate")
	}

	for name, auth := range map[string]*agenticv1alpha2.AuthorizationRule{
		"inline without matchers": {Type: agenticv1alpha2.AuthorizationRuleTypeInline},
		"cel without cel field":   {Type: agenticv1alpha2.AuthorizationRuleTypeCEL},
	} {
		t.Run(name, func(t *testing.T) {
			rule := agenticv1alpha2.AccessRule{Name: "bad", Source: source, Authorization: auth}
			if got := tr.translateAccessRuleToRBACPolicy("ns", rule); got != nil {
				t.Fatalf("expected the rule to be skipped, got %v", got)
			}
		})
	}
}

func TestTranslateAccessPolicyToRBACSkipsRulesWithMalformedAuthorization(t *testing.T) {
	const caller = "spiffe://example.com/ns/default/sa/caller"
	tests := []struct {
		name         string
		auth         *agenticv1alpha2.AuthorizationRule
		wantPolicies int
	}{
		{"control: inline with a method is translated", &agenticv1alpha2.AuthorizationRule{
			Type: agenticv1alpha2.AuthorizationRuleTypeInline, Methods: []agenticv1alpha2.HTTPMethod{"GET"}}, 1},
		{"inline without matchers is skipped", &agenticv1alpha2.AuthorizationRule{
			Type: agenticv1alpha2.AuthorizationRuleTypeInline}, 0},
		{"cel without cel field is skipped", &agenticv1alpha2.AuthorizationRule{
			Type: agenticv1alpha2.AuthorizationRuleTypeCEL}, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := newTestAccessPolicy("policy-x", "default", "dummy", "Gateway", caller)
			p.Spec.Rules[0].Authorization = tc.auth
			tr := &Translator{agenticIdentityTrustDomain: testTrustDomain}
			rbac := tr.translateAccessPolicyToRBAC(p)
			if got := len(rbac.GetRules().GetPolicies()); got != tc.wantPolicies {
				t.Errorf("rules: got %d policies, want %d", got, tc.wantPolicies)
			}
			if got := len(rbac.GetShadowRules().GetPolicies()); got != tc.wantPolicies {
				t.Errorf("shadow rules: got %d policies, want %d", got, tc.wantPolicies)
			}
		})
	}
}
