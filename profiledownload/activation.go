package profiledownload

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

// ActivationCode is the parsed SGP.22 activation-code form used by direct download.
type ActivationCode struct {
	SMDPAddress string
	MatchingID  string
	Raw         string
}

// ParseActivationCode parses "1$host$matchingId" and "LPA:1$host$matchingId".
func ParseActivationCode(value string) (ActivationCode, error) {
	raw := strings.TrimSpace(value)
	trimmed := strings.TrimPrefix(raw, "LPA:")
	parts := strings.Split(trimmed, "$")
	if len(parts) < 2 || parts[0] != "1" || strings.TrimSpace(parts[1]) == "" {
		return ActivationCode{}, errors.New("profiledownload: invalid activation code")
	}
	code := ActivationCode{
		SMDPAddress: strings.TrimSpace(parts[1]),
		Raw:         raw,
	}
	if len(parts) > 2 {
		code.MatchingID = strings.TrimSpace(parts[2])
	}
	return code, nil
}

// LPAString returns the activation code form expected by euicc-go's LPA package.
func (c ActivationCode) LPAString() string {
	if strings.HasPrefix(c.Raw, "LPA:") {
		return c.Raw
	}
	return "LPA:" + c.Raw
}

// ProfileID returns a stable local identifier for persisted demo state.
func (c ActivationCode) ProfileID() string {
	if c.MatchingID != "" {
		return c.MatchingID
	}
	sum := sha256.Sum256([]byte(c.Raw))
	return "profile-" + hex.EncodeToString(sum[:6])
}
