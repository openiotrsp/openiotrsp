package mockipa

import (
	"errors"
	"testing"
)

func TestIsChainNotPresentedError(t *testing.T) {
	t.Parallel()

	err := errors.New(`ESipa returned 400 Bad Request: handle ESipa request: eUICC chain not yet presented for 89049032123451234512345678901235: missing eUICC and EUM certificates`)
	if !IsChainNotPresentedError(err) {
		t.Fatalf("IsChainNotPresentedError() = false, want true")
	}
	ciErr := errors.New(`ESipa returned 400 Bad Request: validate eUICC certificate chain: pki: no trusted CI root for EUM certificate`)
	if !IsUntrustedCIError(ciErr) {
		t.Fatalf("IsUntrustedCIError() = false, want true")
	}
	if !IsRetriableESipaError(ciErr) {
		t.Fatalf("IsRetriableESipaError() = false, want true")
	}
}
