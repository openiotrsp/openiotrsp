package pki

import (
	"errors"
	"os"
	"testing"
)

func TestLoadSGP26VariantONISTMaterialEIDMatchesDefault(t *testing.T) {
	t.Parallel()

	if _, err := ResolveFixturePath(DefaultSGP26Zip); err != nil {
		t.Skipf("SGP.26 fixture not present: %v", err)
	}
	material, err := LoadSGP26VariantONISTMaterial("")
	if err != nil {
		t.Fatalf("LoadSGP26VariantONISTMaterial() error = %v", err)
	}
	if material.EID != DefaultSGP26VariantONISTDemoEID {
		t.Fatalf("EID = %q, want %q", material.EID, DefaultSGP26VariantONISTDemoEID)
	}
	if material.EUICCKey == nil || len(material.EUICCCertificate) == 0 {
		t.Fatal("missing eUICC signing material")
	}
}

func TestResolveFixturePathMissing(t *testing.T) {
	t.Parallel()

	_, err := ResolveFixturePath("spec/does-not-exist.zip")
	if err == nil {
		t.Fatal("ResolveFixturePath() error = nil, want missing fixture error")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ResolveFixturePath() error = %v, want ErrNotExist", err)
	}
}
