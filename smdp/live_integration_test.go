//go:build integration

package smdp

import (
	"context"
	"io"
	"net/http"
	"os"
	"testing"
	"time"
)

const (
	liveSMDPEnv = "OPENIOTRSP_LIVE_SMDP"
	sysmocomURL = "https://smdpp.test.rsp.sysmocom.de"
)

func TestLiveSysmocomSMDPReachability(t *testing.T) {
	switch os.Getenv(liveSMDPEnv) {
	case "1":
	case "skip":
		t.Skipf("%s=skip explicitly skipped the live sysmocom SM-DP+ integration canary", liveSMDPEnv)
	default:
		t.Fatalf("%s must be set to 1 to run the live sysmocom SM-DP+ canary, or skip to acknowledge it is not being run", liveSMDPEnv)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, sysmocomURL, nil)
	if err != nil {
		t.Fatalf("create sysmocom request: %v", err)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("reach live sysmocom SM-DP+ at %s: %v", sysmocomURL, err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)

	if response.StatusCode >= http.StatusInternalServerError {
		t.Fatalf("live sysmocom SM-DP+ returned %s", response.Status)
	}
	t.Logf("reached live sysmocom SM-DP+ at %s: %s", sysmocomURL, response.Status)
}
