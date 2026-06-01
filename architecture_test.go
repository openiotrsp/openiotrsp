package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestArchitecture_NoProtocolInInternal(t *testing.T) {
	forbiddenUnderInternal := []string{
		"asn1", "euiccpkg", "esipa", "smdp", 
		"pki", "storage", "signing", "tenant", "api",
	}
	
	for _, pkg := range forbiddenUnderInternal {
		path := filepath.Join("internal", pkg)
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("Architecture violation: package %s must not live under internal/", pkg)
		}
	}
}