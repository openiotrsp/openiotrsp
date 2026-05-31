package openiotrsp

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProtocolPackagesAreNotInternal(t *testing.T) {
	t.Parallel()

	packages := []string{
		"asn1",
		"euiccpkg",
		"esipa",
		"smdp",
		"pki",
		"storage",
		"signing",
		"tenant",
		"api",
	}

	for _, pkg := range packages {
		pkg := pkg
		t.Run(pkg, func(t *testing.T) {
			t.Parallel()

			internalPath := filepath.Join("internal", pkg)
			if _, err := os.Stat(internalPath); err == nil {
				t.Fatalf("package %q must remain importable by enterprise modules, not under %q", pkg, internalPath)
			} else if !os.IsNotExist(err) {
				t.Fatalf("could not check %q: %v", internalPath, err)
			}
		})
	}
}
