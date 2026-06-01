package euiccpkg

import (
	"errors"
	"fmt"
)

var (
	// ErrSignatureInvalid means a signed eUICC Package Result did not verify
	// against the supplied eUICC public key.
	ErrSignatureInvalid = errors.New("euiccpkg: eUICC signature invalid")
	// ErrTransactionMismatch means the result does not match the signed request.
	ErrTransactionMismatch = errors.New("euiccpkg: result transaction mismatch")
	// ErrCounterMismatch means the result counter does not match the signed request.
	ErrCounterMismatch = errors.New("euiccpkg: result counter mismatch")
)

// ResultCode is the domain form of SGP.32 PSMO result INTEGER values.
type ResultCode string

const (
	ResultOK                        ResultCode = "ok"
	ResultICCIDOrAIDNotFound        ResultCode = "iccid-or-aid-not-found"
	ResultProfileNotInDisabledState ResultCode = "profile-not-in-disabled-state"
	ResultProfileNotInEnabledState  ResultCode = "profile-not-in-enabled-state"
	ResultDisallowedByPolicy        ResultCode = "disallowed-by-policy"
	ResultCatBusy                   ResultCode = "cat-busy"
	ResultCommandError              ResultCode = "command-error"
	ResultRollbackNotAvailable      ResultCode = "rollback-not-available"
	ResultReturnFallbackProfile     ResultCode = "return-fallback-profile"
	ResultUndefinedError            ResultCode = "undefined-error"
	ResultUnknown                   ResultCode = "unknown"
)

// PackageError is the domain form of EuiccPackageErrorCode.
type PackageError string

const (
	PackageErrorInvalidEID             PackageError = "invalid-eid"
	PackageErrorReplay                 PackageError = "replay-error"
	PackageErrorCounterValueOutOfRange PackageError = "counter-value-out-of-range"
	PackageErrorSizeOverflow           PackageError = "size-overflow"
	PackageErrorECallActive            PackageError = "ecall-active"
	PackageErrorUndefined              PackageError = "undefined-error"
	PackageErrorUnknown                PackageError = "unknown"
)

// UnsignedPackageError is the domain form of EuiccPackageUnsignedErrorCode.
type UnsignedPackageError string

const (
	UnsignedPackageErrorSizeOverflow UnsignedPackageError = "size-overflow"
	UnsignedPackageErrorUndefined    UnsignedPackageError = "undefined-error"
	UnsignedPackageErrorMissing      UnsignedPackageError = "missing"
	UnsignedPackageErrorUnknown      UnsignedPackageError = "unknown"
)

// VerificationError reports structural verification failures while preserving a
// sentinel error for errors.Is checks.
type VerificationError struct {
	Kind error
	Msg  string
}

func (e *VerificationError) Error() string {
	if e.Msg == "" {
		return e.Kind.Error()
	}
	return fmt.Sprintf("%s: %s", e.Kind, e.Msg)
}

func (e *VerificationError) Unwrap() error {
	return e.Kind
}
