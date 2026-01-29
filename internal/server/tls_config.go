package server

import (
	"crypto/tls"
	"fmt"
	"strings"
)

// ParseCipherSuites converts a comma-separated list of cipher suite names to their IDs
func ParseCipherSuites(cipherSuitesStr string) ([]uint16, error) {
	if cipherSuitesStr == "" {
		return nil, nil
	}

	// Build a map of cipher suite names to IDs
	cipherSuiteMap := make(map[string]uint16)
	for _, suite := range tls.CipherSuites() {
		cipherSuiteMap[suite.Name] = suite.ID
	}
	for _, suite := range tls.InsecureCipherSuites() {
		cipherSuiteMap[suite.Name] = suite.ID
	}

	// Parse the comma-separated list
	names := strings.Split(cipherSuitesStr, ",")
	suites := make([]uint16, 0, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		id, ok := cipherSuiteMap[name]
		if !ok {
			return nil, fmt.Errorf("unknown cipher suite: %s", name)
		}
		suites = append(suites, id)
	}

	return suites, nil
}
