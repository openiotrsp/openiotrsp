package mockipa

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/damonto/euicc-go/driver"
	euichttp "github.com/damonto/euicc-go/http"
	"github.com/damonto/euicc-go/lpa"
	"github.com/openiotrsp/openiotrsp/profiledownload"
)

// DownloadResult describes the device-side outcome that is reported to the eIM.
type DownloadResult struct {
	ProfileID string
	SMDP      string
	LiveSMDP  bool
	Offline   bool
}

// Downloader performs the IPA-side direct download.
type Downloader interface {
	Download(ctx context.Context, activation profiledownload.ActivationCode) (DownloadResult, error)
}

// OfflineDownloader is the CI-only fallback. It is intentionally not a signing proof.
type OfflineDownloader struct{}

// Download returns a deterministic success result without contacting an SM-DP+.
func (OfflineDownloader) Download(ctx context.Context, activation profiledownload.ActivationCode) (DownloadResult, error) {
	if err := ctx.Err(); err != nil {
		return DownloadResult{}, err
	}
	return DownloadResult{
		ProfileID: activation.ProfileID(),
		SMDP:      activation.SMDPAddress,
		Offline:   true,
	}, nil
}

// SysmocomDownloader validates that the public sysmocom SM-DP+ is reachable.
//
// A full signed download still requires an SGP.26 test eUICC/APDU channel. The
// mock IPA keeps this mode explicit so the offline fallback cannot be mistaken
// for signature validation.
type SysmocomDownloader struct {
	HTTPClient *http.Client
	FixtureZip string
	IMEI       string
}

// Download executes euicc-go's ES9+ direct download against the live SM-DP+.
func (d SysmocomDownloader) Download(ctx context.Context, activation profiledownload.ActivationCode) (DownloadResult, error) {
	host := strings.TrimSpace(activation.SMDPAddress)
	if host == "" {
		return DownloadResult{}, fmt.Errorf("mockipa: missing SM-DP+ address")
	}
	fixture, err := LoadSGP26SoftwareFixture(d.FixtureZip)
	if err != nil {
		return DownloadResult{}, err
	}
	euicc, err := NewSoftwareEUICC(fixture)
	if err != nil {
		return DownloadResult{}, err
	}
	client := d.HTTPClient
	if client == nil {
		client = driver.NewHTTPClient(slog.Default(), 60*time.Second)
		client.Transport = statusBodyTransport{base: client.Transport}
	}
	imei := strings.TrimSpace(d.IMEI)
	if imei == "" {
		imei = "490154203237518"
	}
	var lpaActivation lpa.ActivationCode
	if err := lpaActivation.UnmarshalText([]byte(activation.LPAString())); err != nil {
		return DownloadResult{}, err
	}
	lpaActivation.IMEI = imei
	lpaClient := &lpa.Client{
		HTTP: &euichttp.Client{
			Client:               client,
			AdminProtocolVersion: "2.5.0",
		},
		APDU: euicc,
	}
	result, err := lpaClient.DownloadProfile(ctx, &lpaActivation, nil)
	if err != nil {
		return DownloadResult{}, err
	}
	profileID := activation.ProfileID()
	if result != nil && result.Notification != nil && len(result.Notification.ICCID) > 0 {
		profileID = result.Notification.ICCID.String()
	}
	return DownloadResult{
		ProfileID: profileID,
		SMDP:      activation.SMDPAddress,
		LiveSMDP:  true,
	}, nil
}

type statusBodyTransport struct {
	base http.RoundTripper
}

func (t statusBodyTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	response, err := base.RoundTrip(request)
	if err != nil || response == nil || response.StatusCode < http.StatusBadRequest {
		return response, err
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 1024))
	if readErr != nil {
		return nil, fmt.Errorf("SM-DP+ returned %s and body read failed: %w", response.Status, readErr)
	}
	return nil, fmt.Errorf("SM-DP+ returned %s: %s", response.Status, strings.TrimSpace(string(body)))
}
