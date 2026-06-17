package mockipa

import (
	"testing"

	"github.com/openiotrsp/openiotrsp/pki"
)

func TestLoadSGP26SoftwareFixtureEIDMatchesDemoDefault(t *testing.T) {
	t.Parallel()

	fixture, err := LoadSGP26SoftwareFixture("")
	if err != nil {
		t.Fatalf("LoadSGP26SoftwareFixture() error = %v", err)
	}
	if fixture.EID != pki.DefaultSGP26VariantONISTDemoEID {
		t.Fatalf("fixture.EID = %q, want %q", fixture.EID, pki.DefaultSGP26VariantONISTDemoEID)
	}
}
