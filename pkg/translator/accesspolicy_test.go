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
	"time"

	rbacconfigv3 "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	rbacv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/rbac/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	agenticv0alpha0 "sigs.k8s.io/kube-agentic-networking/api/v0alpha0"
	agenticv1alpha2 "sigs.k8s.io/kube-agentic-networking/api/v1alpha2"
	agenticclient "sigs.k8s.io/kube-agentic-networking/k8s/client/clientset/versioned/fake"
	agenticinformers "sigs.k8s.io/kube-agentic-networking/k8s/client/informers/externalversions"
	"sigs.k8s.io/kube-agentic-networking/pkg/constants"
)

const (
	testTrustDomain = "cluster.local"
)

var (
	acceptedStatus = agenticv1alpha2.AccessPolicyStatus{
		Ancestors: []gatewayv1.PolicyAncestorStatus{
			{
				Conditions: []metav1.Condition{
					{
						Type:   string(agenticv1alpha2.PolicyConditionAccepted),
						Status: metav1.ConditionTrue,
					},
				},
			},
		},
	}

	rejectedStatus = agenticv1alpha2.AccessPolicyStatus{
		Ancestors: []gatewayv1.PolicyAncestorStatus{
			{
				Conditions: []metav1.Condition{
					{
						Type:   string(agenticv1alpha2.PolicyConditionAccepted),
						Status: metav1.ConditionFalse,
					},
				},
			},
		},
	}
)

type expectedRule struct {
	principal           string
	permissions         []string
	isExternalAuth      bool
	hasCelCondition     bool
	expectAnyPermission bool
}

func TestBuildGatewayLevelRBACFilters(t *testing.T) {
	ns := "test-ns"
	gwName := "test-gw"

	tests := []struct {
		name            string
		policies        []runtime.Object
		gatewaysToCheck map[string][]string                // gateway name -> expected filter names in order
		expectedRules   map[string]map[string]expectedRule // gateway name -> rule name -> expectedRule
	}{
		{
			name:     "no policies targeting gateway",
			policies: []runtime.Object{},
			gatewaysToCheck: map[string][]string{
				gwName: {},
			},
			expectedRules: map[string]map[string]expectedRule{},
		},
		{
			name: "single policy targeting gateway",
			policies: []runtime.Object{
				newTestAccessPolicy("gw-policy", ns, gwName, "Gateway", "spiffe://cluster.local/ns/ns1/sa/sa1"),
			},
			gatewaysToCheck: map[string][]string{
				gwName: {constants.GatewayAllowRBACFilterName},
			},
			expectedRules: map[string]map[string]expectedRule{
				gwName: {
					"gw-policy-rule-1": {
						principal:           "spiffe://cluster.local/ns/ns1/sa/sa1",
						expectAnyPermission: true,
					},
				},
			},
		},
		{
			name: "multiple policies targeting the same gateway",
			policies: []runtime.Object{
				newTestAccessPolicy("gw-policy-1", ns, gwName, "Gateway", "spiffe://cluster.local/ns/ns1/sa/sa1"),
				newTestAccessPolicy("gw-policy-2", ns, gwName, "Gateway", "spiffe://cluster.local/ns/ns2/sa/sa2"),
			},
			gatewaysToCheck: map[string][]string{
				gwName: {constants.GatewayAllowRBACFilterName},
			},
			expectedRules: map[string]map[string]expectedRule{
				gwName: {
					"gw-policy-1-rule-1": {
						principal:           "spiffe://cluster.local/ns/ns1/sa/sa1",
						expectAnyPermission: true,
					},
					"gw-policy-2-rule-1": {
						principal:           "spiffe://cluster.local/ns/ns2/sa/sa2",
						expectAnyPermission: true,
					},
				},
			},
		},
		{
			name: "one policy targeting multiple gateways",
			policies: []runtime.Object{
				&agenticv1alpha2.XAccessPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "multi-gw-policy", Namespace: ns},
					Spec: agenticv1alpha2.AccessPolicySpec{
						TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
							{
								LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
									Group: gatewayv1.Group(gatewayv1.GroupName),
									Kind:  gatewayv1.Kind("Gateway"),
									Name:  gatewayv1.ObjectName(gwName),
								},
							},
							{
								LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
									Group: gatewayv1.Group(gatewayv1.GroupName),
									Kind:  gatewayv1.Kind("Gateway"),
									Name:  "other-gw",
								},
							},
						},
						Action: agenticv1alpha2.ActionTypeAllow,
						Rules:  []agenticv1alpha2.AccessRule{{Name: "rule-name"}},
					},
					Status: acceptedStatus,
				},
			},
			gatewaysToCheck: map[string][]string{
				gwName:     {constants.GatewayAllowRBACFilterName},
				"other-gw": {constants.GatewayAllowRBACFilterName},
			},
			expectedRules: map[string]map[string]expectedRule{
				gwName: {
					"multi-gw-policy-rule-name": {
						principal:           "",
						expectAnyPermission: true,
					},
				},
				"other-gw": {
					"multi-gw-policy-rule-name": {
						principal:           "",
						expectAnyPermission: true,
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agenticClient := agenticclient.NewSimpleClientset(tt.policies...)
			agenticInformerFactory := agenticinformers.NewSharedInformerFactory(agenticClient, 0)
			lister := agenticInformerFactory.Agentic().V1alpha2().XAccessPolicies().Lister()

			for _, p := range tt.policies {
				_ = agenticInformerFactory.Agentic().V1alpha2().XAccessPolicies().Informer().GetIndexer().Add(p)
			}

			tr := &Translator{accessPolicyLister: lister}

			for gwn, expectedNames := range tt.gatewaysToCheck {
				gw := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: gwn, Namespace: ns}}
				filters, err := tr.buildGatewayLevelRBACFilters(gw)
				if err != nil {
					t.Fatalf("Gateway %s: Failed to build filters: %v", gwn, err)
				}

				if len(filters) != len(expectedNames) {
					t.Errorf("Gateway %s: Expected %d filters, got %d", gwn, len(expectedNames), len(filters))
				}

				for i, f := range filters {
					if f.GetName() != expectedNames[i] {
						t.Errorf("Gateway %s, Filter %d: expected name %s, got %s", gwn, i, expectedNames[i], f.GetName())
					}

					if f.GetName() == constants.GatewayAllowRBACFilterName {
						rbacProto := &rbacv3.RBAC{}
						if err := f.GetTypedConfig().UnmarshalTo(rbacProto); err != nil {
							t.Fatalf("Gateway %s: failed to unmarshal RBAC: %v", gwn, err)
						}
						verifyRBAC(t, rbacProto.GetRules(), tt.expectedRules[gwn])
					}
				}
			}
		})
	}
}

func TestBuildBackendLevelRBACFilters(t *testing.T) {
	tr := &Translator{}
	filters, err := tr.buildBackendLevelRBACFilters()
	if err != nil {
		t.Fatalf("Failed to build filters: %v", err)
	}

	if len(filters) != 2 {
		t.Errorf("Expected 2 filters, got %d", len(filters))
	}

	expectedNames := []string{constants.BackendExtAuthRBACFilterName, constants.BackendAllowRBACFilterName}
	for i, f := range filters {
		if f.GetName() != expectedNames[i] {
			t.Errorf("Filter %d: expected name %s, got %s", i, expectedNames[i], f.GetName())
		}

		// Verify it's an RBAC filter
		rbac := &rbacv3.RBAC{}
		if err := f.GetTypedConfig().UnmarshalTo(rbac); err != nil {
			t.Errorf("Filter %d: failed to unmarshal to RBAC: %v", i, err)
		}
	}
}

func TestBuildBackendLevelRBACOverrides(t *testing.T) {
	ns := "test-ns"
	beName := "test-backend"

	tests := []struct {
		name            string
		policies        []runtime.Object
		backendsToCheck map[string][]string                // backend name -> expected filter names in order
		expectedRules   map[string]map[string]expectedRule // backend name -> rule name -> expectedRule
	}{
		{
			name:     "no policies targeting backend",
			policies: []runtime.Object{},
			backendsToCheck: map[string][]string{
				beName: {},
			},
			expectedRules: map[string]map[string]expectedRule{},
		},
		{
			name: "single policy targeting backend",
			policies: []runtime.Object{
				newTestAccessPolicy("be-policy", ns, beName, "XBackend", "spiffe://cluster.local/ns/ns1/sa/sa1"),
			},
			backendsToCheck: map[string][]string{
				beName: {constants.BackendAllowRBACFilterName},
			},
			expectedRules: map[string]map[string]expectedRule{
				beName: {
					"be-policy-rule-1": {
						principal:           "spiffe://cluster.local/ns/ns1/sa/sa1",
						expectAnyPermission: true,
					},
				},
			},
		},
		{
			name: "multiple policies targeting the same backend",
			policies: []runtime.Object{
				newTestAccessPolicy("be-policy-1", ns, beName, "XBackend", "spiffe://cluster.local/ns/ns1/sa/sa1"),
				newTestAccessPolicy("be-policy-2", ns, beName, "XBackend", "spiffe://cluster.local/ns/ns2/sa/sa2"),
			},
			backendsToCheck: map[string][]string{
				beName: {constants.BackendAllowRBACFilterName},
			},
			expectedRules: map[string]map[string]expectedRule{
				beName: {
					"be-policy-1-rule-1": {
						principal:           "spiffe://cluster.local/ns/ns1/sa/sa1",
						expectAnyPermission: true,
					},
					"be-policy-2-rule-1": {
						principal:           "spiffe://cluster.local/ns/ns2/sa/sa2",
						expectAnyPermission: true,
					},
				},
			},
		},
		{
			name: "one policy targeting multiple backends",
			policies: []runtime.Object{
				&agenticv1alpha2.XAccessPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "multi-be-policy", Namespace: ns},
					Spec: agenticv1alpha2.AccessPolicySpec{
						TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
							{
								LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
									Group: gatewayv1.Group(agenticv0alpha0.GroupName),
									Kind:  gatewayv1.Kind("XBackend"),
									Name:  gatewayv1.ObjectName(beName),
								},
							},
							{
								LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
									Group: gatewayv1.Group(agenticv0alpha0.GroupName),
									Kind:  gatewayv1.Kind("XBackend"),
									Name:  "other-backend",
								},
							},
						},
						Action: agenticv1alpha2.ActionTypeAllow,
						Rules:  []agenticv1alpha2.AccessRule{{Name: "rule-name"}},
					},
					Status: acceptedStatus,
				},
			},
			backendsToCheck: map[string][]string{
				beName:          {constants.BackendAllowRBACFilterName},
				"other-backend": {constants.BackendAllowRBACFilterName},
			},
			expectedRules: map[string]map[string]expectedRule{
				beName: {
					"multi-be-policy-rule-name": {
						principal:           "",
						expectAnyPermission: true,
					},
				},
				"other-backend": {
					"multi-be-policy-rule-name": {
						principal:           "",
						expectAnyPermission: true,
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agenticClient := agenticclient.NewSimpleClientset(tt.policies...)
			agenticInformerFactory := agenticinformers.NewSharedInformerFactory(agenticClient, 0)
			lister := agenticInformerFactory.Agentic().V1alpha2().XAccessPolicies().Lister()

			for _, p := range tt.policies {
				_ = agenticInformerFactory.Agentic().V1alpha2().XAccessPolicies().Informer().GetIndexer().Add(p)
			}

			tr := &Translator{accessPolicyLister: lister}

			for ben, expectedFilterNames := range tt.backendsToCheck {
				xbackend := &agenticv0alpha0.XBackend{ObjectMeta: metav1.ObjectMeta{Name: ben, Namespace: ns}}

				configs, err := tr.buildBackendLevelRBACOverrides(xbackend)
				if err != nil {
					t.Fatalf("Backend %s: Failed to build configs: %v", ben, err)
				}

				if len(configs) != len(expectedFilterNames) {
					t.Errorf("Backend %s: Expected %d configs, got %d", ben, len(expectedFilterNames), len(configs))
				}

				for _, expectedName := range expectedFilterNames {
					config, ok := configs[expectedName]
					if !ok {
						t.Errorf("Backend %s: Expected config for filter %s not found", ben, expectedName)
						continue
					}

					if expectedName == constants.BackendAllowRBACFilterName {
						rbacPerRoute := &rbacv3.RBACPerRoute{}
						if err := config.UnmarshalTo(rbacPerRoute); err != nil {
							t.Fatalf("Backend %s: failed to unmarshal RBACPerRoute: %v", ben, err)
						}
						verifyRBAC(t, rbacPerRoute.GetRbac().GetRules(), tt.expectedRules[ben])
					}
				}
			}
		})
	}
}

func TestBuildRBACConfigWithoutCommonPolicies(t *testing.T) {
	tr := &Translator{}
	policy := &agenticv1alpha2.XAccessPolicy{
		Spec: agenticv1alpha2.AccessPolicySpec{
			Rules: []agenticv1alpha2.AccessRule{
				{
					Name: "custom-rule",
					Authorization: &agenticv1alpha2.AuthorizationRule{
						Type: agenticv1alpha2.AuthorizationRuleTypeInline,
					},
				},
			},
		},
	}

	rbac := tr.buildRBACConfigWithCommonPolicies(policy)

	expectedPolicies := []string{
		"custom-rule",
	}

	if len(rbac.GetRules().GetPolicies()) != len(expectedPolicies) {
		t.Errorf("Expected %d policies, got %d", len(expectedPolicies), len(rbac.GetRules().GetPolicies()))
	}

	rbacPolicy := rbac.GetRules().GetPolicies()["custom-rule"]
	if rbacPolicy == nil {
		t.Fatal("Expected policy 'custom-rule' not found")
	}

	permissions := rbacPolicy.GetPermissions()
	if len(permissions) != 1 || !permissions[0].GetAny() {
		t.Errorf("Expected 'Any' permission for empty methods and skipped base methods")
	}
}

func TestFindAccessPoliciesForTarget(t *testing.T) {
	ns := "test-ns"

	policies := []runtime.Object{
		&agenticv1alpha2.XAccessPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "policy-accepted", Namespace: ns},
			Spec: agenticv1alpha2.AccessPolicySpec{
				TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
						Group: gatewayv1.Group(agenticv0alpha0.GroupName),
						Kind:  gatewayv1.Kind("XBackend"),
						Name:  "my-backend",
					},
				}},
			},
			Status: acceptedStatus,
		},
		&agenticv1alpha2.XAccessPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "policy-rejected", Namespace: ns},
			Spec: agenticv1alpha2.AccessPolicySpec{
				TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
						Group: gatewayv1.Group(agenticv0alpha0.GroupName),
						Kind:  gatewayv1.Kind("XBackend"),
						Name:  "my-backend",
					},
				}},
			},
			Status: rejectedStatus,
		},
		&agenticv1alpha2.XAccessPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "policy-targeting-other-backend", Namespace: ns},
			Spec: agenticv1alpha2.AccessPolicySpec{
				TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
						Group: gatewayv1.Group(agenticv0alpha0.GroupName),
						Kind:  gatewayv1.Kind("XBackend"),
						Name:  "other-backend",
					},
				}},
			},
			Status: acceptedStatus,
		},
	}

	agenticClient := agenticclient.NewSimpleClientset(policies...)
	agenticInformerFactory := agenticinformers.NewSharedInformerFactory(agenticClient, 0)
	lister := agenticInformerFactory.Agentic().V1alpha2().XAccessPolicies().Lister()

	// Populate cache
	for _, p := range policies {
		_ = agenticInformerFactory.Agentic().V1alpha2().XAccessPolicies().Informer().GetIndexer().Add(p)
	}

	tr := &Translator{accessPolicyLister: lister}

	found, err := tr.findAccessPoliciesForTarget(agenticv0alpha0.GroupName, "XBackend", ns, "my-backend")
	if err != nil {
		t.Fatalf("Failed to find policies: %v", err)
	}

	if len(found) != 1 {
		t.Errorf("Expected 1 accepted policy, got %d", len(found))
	}

	if found[0].Name != "policy-accepted" {
		t.Errorf("Expected policy-accepted, got %s", found[0].Name)
	}
}

func TestFindAccessPoliciesForTargetSorting(t *testing.T) {
	ns := "test-ns"
	now := metav1.Now()
	past := metav1.NewTime(now.Add(-1 * time.Hour))
	future := metav1.NewTime(now.Add(1 * time.Hour))

	policies := []runtime.Object{
		&agenticv1alpha2.XAccessPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "policy-future", Namespace: ns, CreationTimestamp: future},
			Spec: agenticv1alpha2.AccessPolicySpec{
				TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
						Group: gatewayv1.Group(agenticv0alpha0.GroupName),
						Kind:  gatewayv1.Kind("XBackend"),
						Name:  "my-backend",
					},
				}},
				Action: agenticv1alpha2.ActionTypeAllow,
				Rules:  []agenticv1alpha2.AccessRule{{Name: "rule-1"}},
			},
			Status: acceptedStatus,
		},
		&agenticv1alpha2.XAccessPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "policy-past", Namespace: ns, CreationTimestamp: past},
			Spec: agenticv1alpha2.AccessPolicySpec{
				TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
						Group: gatewayv1.Group(agenticv0alpha0.GroupName),
						Kind:  gatewayv1.Kind("XBackend"),
						Name:  "my-backend",
					},
				}},
				Action: agenticv1alpha2.ActionTypeAllow,
				Rules:  []agenticv1alpha2.AccessRule{{Name: "rule-1"}},
			},
			Status: acceptedStatus,
		},
		&agenticv1alpha2.XAccessPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "policy-now", Namespace: ns, CreationTimestamp: now},
			Spec: agenticv1alpha2.AccessPolicySpec{
				TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
						Group: gatewayv1.Group(agenticv0alpha0.GroupName),
						Kind:  gatewayv1.Kind("XBackend"),
						Name:  "my-backend",
					},
				}},
				Action: agenticv1alpha2.ActionTypeAllow,
				Rules:  []agenticv1alpha2.AccessRule{{Name: "rule-1"}},
			},
			Status: acceptedStatus,
		},
	}

	agenticClient := agenticclient.NewSimpleClientset(policies...)
	agenticInformerFactory := agenticinformers.NewSharedInformerFactory(agenticClient, 0)
	lister := agenticInformerFactory.Agentic().V1alpha2().XAccessPolicies().Lister()

	for _, p := range policies {
		_ = agenticInformerFactory.Agentic().V1alpha2().XAccessPolicies().Informer().GetIndexer().Add(p)
	}

	tr := &Translator{accessPolicyLister: lister}

	found, err := tr.findAccessPoliciesForTarget(agenticv0alpha0.GroupName, "XBackend", ns, "my-backend")
	if err != nil {
		t.Fatalf("Failed to find policies: %v", err)
	}

	if len(found) != 3 {
		t.Errorf("Expected 3 policies, got %d", len(found))
	}

	// Expected order: past, now, future
	if found[0].Name != "policy-past" {
		t.Errorf("Expected policy-past, got %s", found[0].Name)
	}
	if found[1].Name != "policy-now" {
		t.Errorf("Expected policy-now, got %s", found[1].Name)
	}
	if found[2].Name != "policy-future" {
		t.Errorf("Expected policy-future, got %s", found[2].Name)
	}
}

func TestConvertSAtoSPIFFEID(t *testing.T) {
	tests := []struct {
		trustDomain string
		namespace   string
		name        string
		want        string
	}{
		{
			trustDomain: testTrustDomain,
			namespace:   "ns-1",
			name:        "sa-1",
			want:        "spiffe://cluster.local/ns/ns-1/sa/sa-1",
		},
		{
			trustDomain: "example.com",
			namespace:   "default",
			name:        "builder",
			want:        "spiffe://example.com/ns/default/sa/builder",
		},
	}

	for _, tt := range tests {
		got := convertSAtoSPIFFEID(tt.trustDomain, tt.namespace, tt.name)
		if got != tt.want {
			t.Errorf("convertSAtoSPIFFEID(%q, %q, %q) = %q, want %q", tt.trustDomain, tt.namespace, tt.name, got, tt.want)
		}
	}
}

func TestTranslateAccessPolicyToRBAC(t *testing.T) {
	tests := []struct {
		name                   string
		accessPolicy           *agenticv1alpha2.XAccessPolicy
		expectedRules          map[string]expectedRule // rule name -> expected results in Rules
		expectedShadowRules    map[string]expectedRule // rule name -> expected results in ShadowRules
		expectShadowStatPrefix bool
	}{
		{
			name: "one rule with tools",
			accessPolicy: func() *agenticv1alpha2.XAccessPolicy {
				p := newTestAccessPolicy("policy-1", "default", "dummy", "Gateway", "spiffe://example.com/ns/default/sa/caller")
				p.Spec.Rules[0].Authorization = &agenticv1alpha2.AuthorizationRule{
					Type:    agenticv1alpha2.AuthorizationRuleTypeInline,
					Headers: []agenticv1alpha2.HTTPHeaderMatch{{Name: "x-tool", Value: "tool-1"}},
				}
				return p
			}(),
			expectedRules: map[string]expectedRule{
				"rule-1": {
					principal:   "spiffe://example.com/ns/default/sa/caller",
					permissions: []string{"tool-1"},
				},
			},
			expectedShadowRules: map[string]expectedRule{
				"rule-1": {
					principal:   "spiffe://example.com/ns/default/sa/caller",
					permissions: []string{"tool-1"},
				},
			},
		},
		{
			name: "one rule with empty tools",
			accessPolicy: func() *agenticv1alpha2.XAccessPolicy {
				p := newTestAccessPolicy("policy-2", "default", "dummy", "Gateway", "spiffe://example.com/ns/default/sa/caller")
				p.Spec.Rules[0].Authorization = &agenticv1alpha2.AuthorizationRule{
					Type: agenticv1alpha2.AuthorizationRuleTypeInline,
				}
				return p
			}(),
			expectedRules: map[string]expectedRule{
				"rule-1": {
					principal:           "spiffe://example.com/ns/default/sa/caller",
					permissions:         []string{},
					expectAnyPermission: true,
				},
			},
			expectedShadowRules: map[string]expectedRule{
				"rule-1": {
					principal:           "spiffe://example.com/ns/default/sa/caller",
					permissions:         []string{},
					expectAnyPermission: true,
				},
			},
		},
		{
			name:         "one rule with nil authorization",
			accessPolicy: newTestAccessPolicy("policy-3", "default", "dummy", "Gateway", "spiffe://example.com/ns/default/sa/caller"),
			expectedRules: map[string]expectedRule{
				"rule-1": {
					principal:           "spiffe://example.com/ns/default/sa/caller",
					permissions:         []string{},
					expectAnyPermission: true,
				},
			},
			expectedShadowRules: map[string]expectedRule{
				"rule-1": {
					principal:           "spiffe://example.com/ns/default/sa/caller",
					permissions:         []string{},
					expectAnyPermission: true,
				},
			},
		},
		{
			name: "multi rule with tools",
			accessPolicy: &agenticv1alpha2.XAccessPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns-1", Name: "policy-4"},
				Spec: agenticv1alpha2.AccessPolicySpec{
					Rules: []agenticv1alpha2.AccessRule{
						{
							Name: "rule-1",
							Source: agenticv1alpha2.AccessRuleSource{
								Type: agenticv1alpha2.AuthorizationSourceTypeServiceAccount,
								ServiceAccount: &agenticv1alpha2.AuthorizationSourceServiceAccount{
									Name:      "my-sa",
									Namespace: "my-ns",
								},
							},
							Authorization: &agenticv1alpha2.AuthorizationRule{
								Type:    agenticv1alpha2.AuthorizationRuleTypeInline,
								Headers: []agenticv1alpha2.HTTPHeaderMatch{{Name: "x-tool", Value: "tool-a"}},
							},
						},
						{
							Name: "rule-2",
							Source: agenticv1alpha2.AccessRuleSource{
								Type: agenticv1alpha2.AuthorizationSourceTypeSPIFFE,
								SPIFFE: func() *agenticv1alpha2.AuthorizationSourceSPIFFE {
									s := agenticv1alpha2.AuthorizationSourceSPIFFE("spiffe://example.com/ns/default/sa/caller")
									return &s
								}(),
							},
							Authorization: &agenticv1alpha2.AuthorizationRule{
								Type:    agenticv1alpha2.AuthorizationRuleTypeInline,
								Headers: []agenticv1alpha2.HTTPHeaderMatch{{Name: "x-tool", Type: regexMatchType(), Value: "^(tool-b|tool-c)$"}},
							},
						},
					},
				},
			},
			expectedRules: map[string]expectedRule{
				"rule-1": {
					principal:   "spiffe://" + testTrustDomain + "/ns/my-ns/sa/my-sa",
					permissions: []string{"tool-a"},
				},
				"rule-2": {
					principal:   "spiffe://example.com/ns/default/sa/caller",
					permissions: []string{"tool-b", "tool-c"},
				},
			},
			expectedShadowRules: map[string]expectedRule{
				"rule-1": {
					principal:   "spiffe://" + testTrustDomain + "/ns/my-ns/sa/my-sa",
					permissions: []string{"tool-a"},
				},
				"rule-2": {
					principal:   "spiffe://example.com/ns/default/sa/caller",
					permissions: []string{"tool-b", "tool-c"},
				},
			},
		},
		{
			name: "one rule with service account in same namespace (empty ns in source)",
			accessPolicy: &agenticv1alpha2.XAccessPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "my-ns", Name: "policy-5"},
				Spec: agenticv1alpha2.AccessPolicySpec{
					Rules: []agenticv1alpha2.AccessRule{
						{
							Name: "rule-1",
							Source: agenticv1alpha2.AccessRuleSource{
								Type: agenticv1alpha2.AuthorizationSourceTypeServiceAccount,
								ServiceAccount: &agenticv1alpha2.AuthorizationSourceServiceAccount{
									Name: "my-sa",
									// Namespace is omitted
								},
							},
							Authorization: &agenticv1alpha2.AuthorizationRule{
								Type:    agenticv1alpha2.AuthorizationRuleTypeInline,
								Headers: []agenticv1alpha2.HTTPHeaderMatch{{Name: "x-tool", Value: "tool-1"}},
							},
						},
					},
				},
			},
			expectedRules: map[string]expectedRule{
				"rule-1": {
					principal:   "spiffe://" + testTrustDomain + "/ns/my-ns/sa/my-sa",
					permissions: []string{"tool-1"},
				},
			},
			expectedShadowRules: map[string]expectedRule{
				"rule-1": {
					principal:   "spiffe://" + testTrustDomain + "/ns/my-ns/sa/my-sa",
					permissions: []string{"tool-1"},
				},
			},
		},
		{
			name: "external authz",
			accessPolicy: &agenticv1alpha2.XAccessPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "policy-ext-auth"},
				Spec: agenticv1alpha2.AccessPolicySpec{
					Action: agenticv1alpha2.ActionTypeExternalAuth,
					ExternalAuth: &gatewayv1.HTTPExternalAuthFilter{
						ExternalAuthProtocol: gatewayv1.HTTPRouteExternalAuthGRPCProtocol,
						BackendRef: gatewayv1.BackendObjectReference{
							Name: "ext-auth-svc",
						},
					},
					Rules: []agenticv1alpha2.AccessRule{
						{
							Name: "rule-ext-auth",
							Source: agenticv1alpha2.AccessRuleSource{
								Type: agenticv1alpha2.AuthorizationSourceTypeSPIFFE,
								SPIFFE: func() *agenticv1alpha2.AuthorizationSourceSPIFFE {
									s := agenticv1alpha2.AuthorizationSourceSPIFFE("spiffe://example.com/ns/default/sa/caller")
									return &s
								}(),
							},
						},
					},
				},
			},
			expectedRules: map[string]expectedRule{
				"rule-ext-auth": {
					permissions:         []string{},
					expectAnyPermission: true,
				},
			},
			expectedShadowRules: map[string]expectedRule{
				"rule-ext-auth": {
					principal:           "spiffe://example.com/ns/default/sa/caller",
					permissions:         []string{},
					expectAnyPermission: true,
				},
			},
			expectShadowStatPrefix: true,
		},
		{
			name: "external authz with empty rules",
			accessPolicy: &agenticv1alpha2.XAccessPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "policy-ext-auth-empty-rules"},
				Spec: agenticv1alpha2.AccessPolicySpec{
					Action: agenticv1alpha2.ActionTypeExternalAuth,
					ExternalAuth: &gatewayv1.HTTPExternalAuthFilter{
						ExternalAuthProtocol: gatewayv1.HTTPRouteExternalAuthGRPCProtocol,
						BackendRef: gatewayv1.BackendObjectReference{
							Name: "ext-auth-svc",
						},
					},
				},
			},
			expectedRules: map[string]expectedRule{
				"policy-ext-auth-empty-rules": {
					permissions:         []string{},
					expectAnyPermission: true,
				},
			},
			expectedShadowRules: map[string]expectedRule{
				"policy-ext-auth-empty-rules": {
					permissions:         []string{},
					expectAnyPermission: true,
				},
			},
			expectShadowStatPrefix: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tr := &Translator{agenticIdentityTrustDomain: testTrustDomain}
			rbac := tr.translateAccessPolicyToRBAC(tc.accessPolicy)

			verifyRBAC(t, rbac.GetRules(), tc.expectedRules)
			verifyRBAC(t, rbac.GetShadowRules(), tc.expectedShadowRules)

			if (rbac.GetShadowRulesStatPrefix() != "") != tc.expectShadowStatPrefix {
				t.Errorf("ShadowRulesStatPrefix: expected set=%v, got %q", tc.expectShadowStatPrefix, rbac.GetShadowRulesStatPrefix())
			}
		})
	}
}

func TestBuildAllowMCPSessionClosePolicy(t *testing.T) {
	policy := buildAllowMCPSessionClosePolicy()
	ids := policy.GetPrincipals()[0].GetAndIds().GetIds()
	if len(ids) != 2 {
		t.Errorf("expected 2 ID matchers, got %d", len(ids))
	}
	// DELETE method
	if ids[0].GetHeader().GetStringMatch().GetExact() != "DELETE" {
		t.Errorf("expected DELETE method matcher")
	}
	// Session ID header presence
	if !ids[1].GetHeader().GetPresentMatch() {
		t.Errorf("expected session-id present matcher")
	}
}

func TestBuildAllowAnyoneToInitializeAndListToolsPolicy(t *testing.T) {
	policy := buildAllowAnyoneToInitializeAndListToolsPolicy()
	if !policy.GetPrincipals()[0].GetAny() {
		t.Errorf("principal should be ANY")
	}
	matcher := policy.GetPermissions()[0].GetAndRules().GetRules()[0].GetSourcedMetadata().GetMetadataMatcher()
	if matcher.GetFilter() != constants.MCPProxyFilterName || matcher.GetPath()[0].GetKey() != "method" {
		t.Errorf("policy incorrectly configured")
	}
	orMethods := matcher.GetValue().GetOrMatch()
	if orMethods == nil || len(orMethods.GetValueMatchers()) != 3 {
		t.Errorf("expected 3 allowed methods")
	}
}

func TestBuildAllowHTTPGetPolicy(t *testing.T) {
	policy := buildAllowHTTPGetPolicy()
	if !policy.GetPrincipals()[0].GetAny() {
		t.Errorf("principal should be ANY")
	}
	if policy.GetPermissions()[0].GetHeader().GetName() != ":method" ||
		policy.GetPermissions()[0].GetHeader().GetStringMatch().GetExact() != "GET" {
		t.Errorf("policy incorrectly configured")
	}
}

func verifyRBAC(t *testing.T, rbacRules *rbacconfigv3.RBAC, expectedRules map[string]expectedRule) {
	t.Helper()
	if len(expectedRules) == 0 {
		if rbacRules != nil && len(rbacRules.GetPolicies()) > 0 {
			t.Errorf("did not expect any policies, but got %d", len(rbacRules.GetPolicies()))
		}
		return
	}

	if rbacRules == nil {
		t.Fatal("expected RBAC rules to be populated")
	}

	if len(rbacRules.GetPolicies()) != len(expectedRules) {
		t.Errorf("expected %d policies, got %d", len(expectedRules), len(rbacRules.GetPolicies()))
	}

	for ruleName, expected := range expectedRules {
		rbacPolicy, ok := rbacRules.GetPolicies()[ruleName]
		if !ok {
			t.Errorf("expected policy with key %q not found", ruleName)
			continue
		}
		verifyPolicy(t, rbacPolicy, expected)
	}
}

func verifyPolicy(t *testing.T, rbacPolicy *rbacconfigv3.Policy, expected expectedRule) {
	t.Helper()
	// Verify Principal
	if expected.principal != "" {
		found := false
		for _, p := range rbacPolicy.GetPrincipals() {
			auth := p.GetAuthenticated()
			if auth != nil && auth.GetPrincipalName().GetExact() == expected.principal {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("did not find expected principal %q", expected.principal)
		}
	} else if len(rbacPolicy.GetPrincipals()) > 0 {
		// If no principal expected, should match 'Any'
		foundAny := false
		for _, p := range rbacPolicy.GetPrincipals() {
			if p.GetAny() {
				foundAny = true
				break
			}
		}
		if !foundAny {
			t.Errorf("expected 'Any' principal but not found")
		}
	}

	// Verify CEL Condition
	if expected.hasCelCondition {
		if rbacPolicy.GetCondition() == nil {
			t.Errorf("expected CEL condition but found none")
		}
	} else if rbacPolicy.GetCondition() != nil {
		t.Errorf("did not expect CEL condition but found one")
	}

	// Verify Tools Permissions
	if len(rbacPolicy.GetPermissions()) == 0 {
		t.Errorf("expected permissions for tools, but found none")
		return
	}

	if expected.expectAnyPermission {
		if len(rbacPolicy.GetPermissions()) != 1 || !rbacPolicy.GetPermissions()[0].GetAny() {
			t.Errorf("expected 'Any' permission for omitted authorization")
		}
		return
	}

	if expected.isExternalAuth || expected.hasCelCondition {
		if len(rbacPolicy.GetPermissions()) != 1 {
			t.Errorf("expected 1 permission for external auth or CEL, got %d", len(rbacPolicy.GetPermissions()))
			return
		}
		methodRule := rbacPolicy.GetPermissions()[0].GetSourcedMetadata()
		if methodRule == nil || methodRule.GetMetadataMatcher().GetValue().GetStringMatch().GetExact() != constants.ToolsCallMethod {
			t.Errorf("expected tools/call method permission for external auth or CEL")
		}
		return
	}

	// Inline rules now match plain HTTP headers. "permissions" holds the expected x-tool values.
	var exact, regex string
	found := false
	for _, perm := range rbacPolicy.GetPermissions() {
		if e, r, ok := findHeaderMatch(perm, "x-tool"); ok {
			exact, regex, found = e, r, true
			break
		}
	}
	if !found {
		t.Errorf("expected an x-tool header matcher in permissions, found none")
		return
	}
	if len(expected.permissions) == 1 {
		if exact != expected.permissions[0] {
			t.Errorf("tool header: expected %q, got %q", expected.permissions[0], exact)
		}
		return
	}
	alt := ""
	for i, tool := range expected.permissions {
		if i > 0 {
			alt += "|"
		}
		alt += tool
	}
	if want := "^(" + alt + ")$"; regex != want {
		t.Errorf("tool header regex: expected %q, got %q", want, regex)
	}
}

// findHeaderMatch searches a permission tree for a header matcher with the given name.
func findHeaderMatch(p *rbacconfigv3.Permission, name string) (exact, regex string, found bool) {
	if p == nil {
		return "", "", false
	}
	if h := p.GetHeader(); h != nil && h.GetName() == name {
		return h.GetStringMatch().GetExact(), h.GetStringMatch().GetSafeRegex().GetRegex(), true
	}
	for _, sub := range p.GetAndRules().GetRules() {
		if e, r, ok := findHeaderMatch(sub, name); ok {
			return e, r, true
		}
	}
	for _, sub := range p.GetOrRules().GetRules() {
		if e, r, ok := findHeaderMatch(sub, name); ok {
			return e, r, true
		}
	}
	return "", "", false
}

func regexMatchType() *agenticv1alpha2.HeaderMatchType {
	m := agenticv1alpha2.HeaderMatchRegularExpression
	return &m
}

func TestTranslateInlineAttributesToRBACPermission(t *testing.T) {
	tests := []struct {
		name  string
		auth  *agenticv1alpha2.AuthorizationRule
		check func(*testing.T, *rbacconfigv3.Permission)
	}{
		{
			name: "nil auth",
			auth: nil,
			check: func(t *testing.T, p *rbacconfigv3.Permission) {
				if p != nil {
					t.Errorf("expected nil permission for nil auth")
				}
			},
		},
		{
			name: "methods and paths",
			auth: &agenticv1alpha2.AuthorizationRule{
				Methods: []agenticv1alpha2.HTTPMethod{"GET", "POST"},
				Paths: []agenticv1alpha2.HTTPPathMatch{
					{Value: func(s string) *string { return &s }("/health")},
				},
			},
			check: func(t *testing.T, p *rbacconfigv3.Permission) {
				andRules := p.GetAndRules()
				if andRules == nil || len(andRules.GetRules()) != 2 {
					t.Fatalf("expected AndRules with 2 rules")
				}
			},
		},
		{
			name: "headers, hosts, and ports",
			auth: &agenticv1alpha2.AuthorizationRule{
				Headers: []agenticv1alpha2.HTTPHeaderMatch{
					{Name: "x-role", Value: "admin"},
				},
				Hosts: []agenticv1alpha2.Hostname{".example.com"},
				Ports: []agenticv1alpha2.PortNumber{8080},
			},
			check: func(t *testing.T, p *rbacconfigv3.Permission) {
				andRules := p.GetAndRules()
				if andRules == nil || len(andRules.GetRules()) != 3 {
					t.Fatalf("expected AndRules with 3 rules, got %v", p)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := translateInlineAttributesToRBACPermission(tt.auth)
			tt.check(t, got)
		})
	}
}

func TestTranslateAccessRuleToRBACPolicy(t *testing.T) {
	tr := &Translator{}
	rule := agenticv1alpha2.AccessRule{
		Name: "test-rule",
		Authorization: &agenticv1alpha2.AuthorizationRule{
			Type:    agenticv1alpha2.AuthorizationRuleTypeInline,
			Methods: []agenticv1alpha2.HTTPMethod{"GET"},
			Headers: []agenticv1alpha2.HTTPHeaderMatch{{Name: "x-example", Value: "v"}},
		},
	}
	policy := tr.translateAccessRuleToRBACPolicy("default", rule)
	if policy == nil {
		t.Fatalf("expected policy, got nil")
	}
	perms := policy.GetPermissions()
	if len(perms) != 1 {
		t.Fatalf("expected 1 combined permission, got %d", len(perms))
	}
	andRules := perms[0].GetAndRules()
	if andRules == nil || len(andRules.GetRules()) != 2 {
		t.Fatalf("expected combined AndRules with 2 rules")
	}
}
