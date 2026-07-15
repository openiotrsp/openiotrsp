package mockipa

import (
	"context"
	"testing"

	"github.com/openiotrsp/openiotrsp/profiledownload"
)

func TestOfflineDownloaderLocalMockActivationCode(t *testing.T) {
	t.Parallel()

	activation, err := profiledownload.ParseActivationCode("1$mock.smdp.local$8900d5cfec6099f3c8b6")
	if err != nil {
		t.Fatalf("ParseActivationCode() error = %v", err)
	}
	result, err := OfflineDownloader{}.Download(context.Background(), activation)
	if err != nil {
		t.Fatalf("Download() error = %v", err)
	}
	if result.ProfileID != "8900d5cfec6099f3c8b6" {
		t.Fatalf("ProfileID = %q, want matching ID from activation code", result.ProfileID)
	}
	if result.SMDP != "mock.smdp.local" {
		t.Fatalf("SMDP = %q, want mock.smdp.local", result.SMDP)
	}
	if !result.Offline {
		t.Fatal("Offline = false, want true")
	}
	if result.LiveSMDP {
		t.Fatal("LiveSMDP = true, want false")
	}
}

func TestIsLocalMockSMDP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		host string
		want bool
	}{
		{name: "mock host", host: "mock.smdp.local", want: true},
		{name: "local suffix", host: "smdp.example.local", want: true},
		{name: "local with port", host: "mock.smdp.local:443", want: true},
		{name: "sysmocom live", host: "smdpp.test.rsp.sysmocom.de", want: false},
		{name: "empty", host: "", want: false},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := IsLocalMockSMDP(tc.host); got != tc.want {
				t.Fatalf("IsLocalMockSMDP(%q) = %v, want %v", tc.host, got, tc.want)
			}
		})
	}
}

func TestProfileDownloadDownloaderSelectsOfflineForLocalMock(t *testing.T) {
	t.Parallel()

	activation := profiledownload.ActivationCode{SMDPAddress: "mock.smdp.local", MatchingID: "8900abc"}
	base := SysmocomDownloader{}
	selected := ProfileDownloadDownloader(base, false, activation, Client{})
	if _, ok := selected.(OfflineDownloader); !ok {
		t.Fatalf("downloader = %T, want OfflineDownloader", selected)
	}
}

func TestProfileDownloadDownloaderKeepsSysmocomForLiveHost(t *testing.T) {
	t.Parallel()

	activation := profiledownload.ActivationCode{SMDPAddress: "smdpp.test.rsp.sysmocom.de", MatchingID: "TS48V1-B-UNIQUE"}
	base := SysmocomDownloader{IMEI: "490154203237518"}
	selected := ProfileDownloadDownloader(base, false, activation, Client{})
	if _, ok := selected.(SysmocomDownloader); !ok {
		t.Fatalf("downloader = %T, want SysmocomDownloader", selected)
	}
}

func TestProfileDownloadDownloaderPrefersOfflineOverIndirectForLocalMock(t *testing.T) {
	t.Parallel()

	activation := profiledownload.ActivationCode{SMDPAddress: "mock.smdp.local", MatchingID: "8900abc"}
	base := SysmocomDownloader{}
	selected := ProfileDownloadDownloader(base, true, activation, Client{})
	if _, ok := selected.(OfflineDownloader); !ok {
		t.Fatalf("downloader = %T, want OfflineDownloader", selected)
	}
}
