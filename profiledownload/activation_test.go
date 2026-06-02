package profiledownload

import "testing"

func TestParseActivationCode(t *testing.T) {
	t.Parallel()

	activation, err := ParseActivationCode("LPA:1$smdpp.test.rsp.sysmocom.de$TS48V1-B-UNIQUE")
	if err != nil {
		t.Fatalf("ParseActivationCode() error = %v", err)
	}
	if activation.SMDPAddress != "smdpp.test.rsp.sysmocom.de" {
		t.Fatalf("SMDPAddress = %q", activation.SMDPAddress)
	}
	if activation.MatchingID != "TS48V1-B-UNIQUE" {
		t.Fatalf("MatchingID = %q", activation.MatchingID)
	}
	if activation.LPAString() != "LPA:1$smdpp.test.rsp.sysmocom.de$TS48V1-B-UNIQUE" {
		t.Fatalf("LPAString() = %q", activation.LPAString())
	}
	if activation.ProfileID() != "TS48V1-B-UNIQUE" {
		t.Fatalf("ProfileID() = %q", activation.ProfileID())
	}
}

func TestParseActivationCodeRejectsInvalid(t *testing.T) {
	t.Parallel()

	if _, err := ParseActivationCode("not-an-activation-code"); err == nil {
		t.Fatal("ParseActivationCode() succeeded for invalid code")
	}
}
