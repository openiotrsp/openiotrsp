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
	// This drives euicc-go through ES9+ with SGP.26-signed eUICC-side
	// AuthenticateServer/PrepareDownload responses. The software eUICC does not
	// decrypt or apply the returned BPP like real silicon; its ES10b load result is
	// simulated so this test proves the signed SM-DP+ handshake and binding path,
	// not physical profile installation.
	result, err := (mockipa.SysmocomDownloader{}).Download(ctx, activation)
	if err != nil {
		t.Fatalf("live sysmocom signed ES9+ flow failed: %v", err)
	}
	t.Logf("validated live sysmocom signed ES9+ flow for profile %s at %s", result.ProfileID, result.SMDP)
}
