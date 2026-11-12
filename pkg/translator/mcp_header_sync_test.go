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
	"strings"
	"testing"

	luav3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/lua/v3"

	"sigs.k8s.io/kube-agentic-networking/pkg/constants"
)

func TestBuildMCPHeaderSyncLuaFilter(t *testing.T) {
	f, err := buildMCPHeaderSyncLuaFilter()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.GetName() != constants.MCPHeaderSyncLuaFilterName {
		t.Errorf("name = %q, want %q", f.GetName(), constants.MCPHeaderSyncLuaFilterName)
	}

	lua := &luav3.Lua{}
	if err := f.GetTypedConfig().UnmarshalTo(lua); err != nil {
		t.Fatalf("typed config is not a Lua filter: %v", err)
	}
	src := lua.GetDefaultSourceCode().GetInlineString()

	// Client-supplied headers must always be stripped before anything else.
	for _, want := range []string{
		`headers:remove("mcp-method")`,
		`headers:remove("mcp-name")`,
		`dynamicMetadata():get("` + constants.MCPProxyFilterName + `")`,
		`headers:add("mcp-method"`,
		`headers:add("mcp-name"`,
	} {
		if !strings.Contains(src, want) {
			t.Errorf("script missing %q", want)
		}
	}
	if strings.Index(src, `headers:remove("mcp-method")`) > strings.Index(src, "dynamicMetadata()") {
		t.Error("headers must be removed before metadata is read")
	}
	if strings.Contains(src, "%!") {
		t.Errorf("script has a formatting error: %s", src)
	}
}
