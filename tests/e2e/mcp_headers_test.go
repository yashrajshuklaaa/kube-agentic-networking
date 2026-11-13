package e2e

import (
	"os"
	"strings"
)

// omitMCPHeaders makes the e2e helpers send body-only MCP requests, like clients
// that predate SEP-2243. With the gateway's header sync filter, policies that match
// on Mcp-Method/Mcp-Name must still work. Enable with E2E_OMIT_MCP_HEADERS=1.
var omitMCPHeaders = os.Getenv("E2E_OMIT_MCP_HEADERS") == "1"

// spoofMCPHeaders, when set, replaces the Mcp-* headers the helpers would derive
// from the request body, so tests can send headers that disagree with the body.
var spoofMCPHeaders map[string]string

// initializeMethodHeader returns the Mcp-Method header for the initialize request.
// When headers are omitted it returns a harmless dummy so the curl arguments stay paired.
func initializeMethodHeader() string {
	if omitMCPHeaders {
		return "X-Omitted-Mcp-Method: initialize"
	}
	return "Mcp-Method: initialize"
}

// adjustMCPHeaderArgs applies omitMCPHeaders and spoofMCPHeaders to curl "-H" arguments.
func adjustMCPHeaderArgs(args []string) []string {
	if !omitMCPHeaders && spoofMCPHeaders == nil {
		return args
	}
	out := make([]string, 0, len(args)+4)
	for i := 0; i < len(args); i++ {
		if args[i] == "-H" && i+1 < len(args) {
			h := strings.ToLower(args[i+1])
			if strings.HasPrefix(h, "mcp-method:") || strings.HasPrefix(h, "mcp-name:") {
				i++
				continue
			}
		}
		out = append(out, args[i])
	}
	for k, v := range spoofMCPHeaders {
		out = append(out, "-H", k+": "+v)
	}
	return out
}
