package euiccpkg

import "testing"

func TestValidateInitialEIMConfigurationDataRequiresFQDN(t *testing.T) {
	t.Parallel()

	signer := newTestSigner(t)
	config, err := NewInitialEIMConfigurationDataFromPublicKey("eim.example", "", 1, signer.PublicKey(), nil)
	if err != nil {
		t.Fatalf("NewInitialEIMConfigurationDataFromPublicKey() error = %v", err)
	}
	if err := ValidateInitialEIMConfigurationData(config); err == nil {
		t.Fatal("ValidateInitialEIMConfigurationData() error = nil, want missing FQDN error")
	}

	blank := " \t"
	config.EimFQDN = &blank
	if err := ValidateInitialEIMConfigurationData(config); err == nil {
		t.Fatal("ValidateInitialEIMConfigurationData() error = nil, want blank FQDN error")
	}

	fqdn := "eim.example"
	config.EimFQDN = &fqdn
	if err := ValidateInitialEIMConfigurationData(config); err != nil {
		t.Fatalf("ValidateInitialEIMConfigurationData() error = %v", err)
	}
}
