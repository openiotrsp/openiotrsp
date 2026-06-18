package mockipa

import "strings"

// IsChainNotPresentedError reports whether the eIM rejected an ESipa upload
// because the eUICC certificate chain has not been presented yet.
func IsChainNotPresentedError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "chain not yet presented") ||
		strings.Contains(msg, "missing euicc and eum certificates")
}

// IsUntrustedCIError reports whether the eIM trusts the presented chain but
// does not have the CI root needed to validate the SGP.26 test EUM certificate.
func IsUntrustedCIError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no trusted ci root") ||
		strings.Contains(msg, "eum certificate signature rejected by trusted ci root")
}

// IsCertificateChainValidationError reports eIM-side PKI trust failures after
// the IPA has presented EUM/eUICC certificates.
func IsCertificateChainValidationError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return IsUntrustedCIError(err) ||
		strings.Contains(msg, "validate euicc certificate chain")
}

// IsRetriableESipaError reports ESipa failures that should not stop polling.
func IsRetriableESipaError(err error) bool {
	return IsChainNotPresentedError(err) || IsCertificateChainValidationError(err)
}
