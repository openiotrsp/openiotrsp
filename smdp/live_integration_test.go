//go:build integration

package smdp

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/openiotrsp/openiotrsp/mockipa"
	"github.com/openiotrsp/openiotrsp/profiledownload"
)

const (
	liveSMDPEnv        = "OPENIOTRSP_LIVE_SMDP"
	sgp26FixtureZipEnv = "OPENIOTRSP_SGP26_FIXTURE_ZIP"
)

func TestLiveSysmocomSignedES9Flow(t *testing.T) {
	switch os.Getenv(liveSMDPEnv) {
	case "1":
	case "skip":
		t.Skipf("%s=skip explicitly skipped the live sysmocom SM-DP+ integration", liveSMDPEnv)
	default:
		t.Skipf("%s is not set; live sysmocom SM-DP+ integration not run", liveSMDPEnv)
	}
	if err := mockipa.ValidateSGP26SoftwareFixture(os.Getenv(sgp26FixtureZipEnv)); err != nil {
		t.Fatalf("live sysmocom signed-flow prerequisites not met: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	activation, err := profiledownload.ParseActivationCode("1$smdpp.test.rsp.sysmocom.de$TS48V1-B-UNIQUE")
	if err != nil {
		t.Fatalf("ParseActivationCode() error = %v", err)
	}
	// This drives the software eUICC through ES9+ with SGP.26-signed
	// AuthenticateServer/PrepareDownload/ProfileInstallationResult responses. The
	// BPP is captured but not decrypted or provisioned like real silicon, so this
	// proves the SM-DP+ interface path, not physical profile installation.
	result, err := (mockipa.SysmocomDownloader{}).Download(ctx, activation)
	if err != nil {
		t.Fatalf("live sysmocom signed ES9+ flow failed: %v", err)
	}
	t.Logf("validated live sysmocom signed ES9+ flow for profile %s at %s", result.ProfileID, result.SMDP)
}
