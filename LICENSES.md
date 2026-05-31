# Licenses

The project policy allows MIT, BSD, Apache 2.0, and ISC dependencies only.

Current Go module dependencies:

- `github.com/damonto/euicc-go`: replaced in `go.mod` with
  `github.com/openiotrsp/euicc-go`; the resolved fork is MIT.

The eUICC dependency must use the `github.com/openiotrsp/euicc-go` fork. Do not
import `github.com/damonto/euicc-go` directly.
