package mockipa

import (
	"testing"

	"github.com/openiotrsp/openiotrsp/pki"
)

func TestLoadSGP26SoftwareFixtureEIDMatchesDemoDefault(t *testing.T) {
	t.Parallel()

	fixture := requireSGP26SoftwareFixture(t)
	if fixture.EID != pki.DefaultSGP26VariantONISTDemoEID {
		t.Fatalf("fixture.EID = %q, want %q", fixture.EID, pki.DefaultSGP26VariantONISTDemoEID)
	}
}

func requireSGP26SoftwareFixture(t *testing.T) *SGP26Fixture {
	t.Helper()
	if _, err := resolveFixturePath(pki.DefaultSGP26Zip); err != nil {
		t.Skipf("SGP.26 fixture not present at %s", pki.DefaultSGP26Zip)
	}
	fixture, err := LoadSGP26SoftwareFixture("")
	if err != nil {
		t.Fatalf("LoadSGP26SoftwareFixture() error = %v", err)
	}
	return fixture
}
