package pki_test

import (
	"testing"

	"github.com/openiotrsp/openiotrsp/pki"
)

func TestEIDHexFromCertificateMatchesSGP26VariantONISTDemo(t *testing.T) {
	t.Parallel()

	euiccDER := loadSGP26VariantONISTCertificates(t)["euicc"]
	eid, err := pki.EIDHexFromCertificate(euiccDER)
	if err != nil {
		t.Fatalf("EIDHexFromCertificate() error = %v", err)
	}
	if eid != pki.DefaultSGP26VariantONISTDemoEID {
		t.Fatalf("EIDHexFromCertificate() = %q, want %q", eid, pki.DefaultSGP26VariantONISTDemoEID)
	}
}
