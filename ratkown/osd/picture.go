package osd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"ratkown/ratkown/dhip"
	"ratkown/ratkown/net"
	"ratkown/ratkown/ui"
)

var logoSideRect = []int{6148, 3228, 7788, 4868}

type logoTrace struct {
	Serial     string          `json:"serial"`
	Note       string          `json:"note,omitempty"`
	LoginRetry int             `json:"login_retry,omitempty"`
	Attempts   []logoAttempt   `json:"attempts"`
	Discovery  []string        `json:"discovery,omitempty"`
	WebRoot    string          `json:"web_root,omitempty"`
	Before     json.RawMessage `json:"before,omitempty"`
	After      json.RawMessage `json:"after,omitempty"`
	Uploaded   bool            `json:"uploaded"`
	Applied    bool            `json:"applied"`
	PatchError string          `json:"patch_error,omitempty"`
}

type logoAttempt struct {
	Endpoint  string `json:"endpoint"`
	Field     string `json:"field"`
	Status    string `json:"status,omitempty"`
	Body      string `json:"body,omitempty"`
	NetError  string `json:"net_error,omitempty"`
	Accepted  bool   `json:"accepted"`
	BytesSent int    `json:"bytes_sent"`
}

func patchPictureTitle(s *dhip.Session, logoName string, id int) (bool, string, json.RawMessage) {
	vw, err := s.Get("VideoWidget", id)
	if err != nil {
		return false, fmt.Sprintf("get VideoWidget: %v", err), nil
	}
	table := vw.Nested
	patched := false
	for _, raw := range table {
		m, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if pt, ok := m["PictureTitle"].(map[string]any); ok {
			pt["Name"] = logoName
			pt["EncodeBlend"] = true
			pt["PreviewBlend"] = true
			pt["FrontColor"] = []any{255, 255, 255, 255}
			pt["BackColor"] = []any{0, 0, 0, 0}
			pt["Rect"] = []int{logoSideRect[0], logoSideRect[1], logoSideRect[2], logoSideRect[3]}
			patched = true
		}
	}
	if !patched {
		return false, "VideoWidget has no PictureTitle slot", nil
	}
	if err := s.SetBoth(nil, table); err != nil {
		if s.Conn != nil {
			if _, serr := dhip.SecuritySetConfig(s.Conn, s.Sess, s.Cookie, "VideoWidget", table); serr != nil {
				return false, fmt.Sprintf("%v / %v", err, serr), nil
			}
		} else {
			return false, err.Error(), nil
		}
	}
	time.Sleep(700 * time.Millisecond)
	if chk, cerr := s.Get("VideoWidget", id+1); cerr == nil {
		for _, raw := range chk.Nested {
			m, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			if pt, ok := m["PictureTitle"].(map[string]any); ok {
				var afterState json.RawMessage
				if raw2, jerr := json.Marshal(pt); jerr == nil {
					afterState = raw2
				}
				if n, _ := pt["Name"].(string); n == logoName {
					if eb, _ := pt["EncodeBlend"].(bool); eb {
						return true, "", afterState
					}
				}
				return false, "setConfig accepted but verify failed", afterState
			}
		}
	}
	return false, "setConfig accepted but verify failed", nil
}

func TryPictureTitle(tunnel *net.PTCPTunnel, login, pass, bmpPath, outDir, serial string) error {
	trace := logoTrace{Serial: serial}
	saveTrace := func() {
		if raw, jerr := json.MarshalIndent(trace, "", "  "); jerr == nil {
			os.WriteFile(filepath.Join(outDir, fmt.Sprintf("logo_%s.json", serial)), raw, 0644)
		}
	}

	wantName := ""
	var data []byte
	if bmpPath == "" {
		return fmt.Errorf("logo: no bmp file provided")
	}
	raw, rerr := os.ReadFile(bmpPath)
	if rerr != nil {
		return fmt.Errorf("logo read failed: %w", rerr)
	}
	if len(raw) < 64 || string(raw[0:2]) != "BM" {
		return fmt.Errorf("logo %s: not a valid BMP file", bmpPath)
	}
	data = raw
	wantName = filepath.Base(bmpPath)

	{
		var s *dhip.Session
		var sessErr error
		for try := 0; try < 3; try++ {
			sess, serr := dhip.NewRPC2Session(tunnel, login, pass)
			if serr == nil {
				s = sess
				ui.DebugLogf("logo", "%s > rpc2 login ok (try %d)", serial, try+1)
				break
			}
			sessErr = serr
			if strings.Contains(strings.ToLower(serr.Error()), "too many connections") {
				ui.DebugLogf("logo", "%s > rpc2 busy, wait %ds (try %d)", serial, 10*(try+1), try+1)
				trace.LoginRetry++
				time.Sleep(time.Duration(10*(try+1)) * time.Second)
				continue
			}
			ui.DebugLogf("logo", "%s > rpc2 login refused: %v", serial, serr)
			break
		}

		if s == nil {
			trace.Note = strings.TrimSpace(trace.Note + " | rpc2 session: " + sessErr.Error())
			saveTrace()
			return fmt.Errorf("logo not uploaded: rpc2 login failed: %v (see logo_%s.json)", sessErr, serial)
		}

		discoverUploadPaths(s, serial, &trace)

		hasUploadHint := false
		for _, d := range trace.Discovery {
			l := strings.ToLower(d)
			if strings.Contains(l, "upfile") || strings.Contains(l, "upload") || strings.Contains(l, ".cgi") || strings.Contains(l, "multipart") || strings.Contains(l, "form-data") {
				hasUploadHint = true
				break
			}
		}
		if !hasUploadHint {
			ui.DebugLogf("logo", "%s > no upload path in webui", serial)
		}

		uploaded := false
		var upErr error
		attNum := 0
		if hasUploadHint {
			for _, endpoint := range []string{"/RPC2_UpFile", "/RPC2_Upload"} {
				for _, fileField := range []string{"File", "file"} {
					attNum++
					ui.DebugLogf("logo", "%s > upload attempt %d/4: %s %s", serial, attNum, endpoint, fileField)
					body, status, perr := s.Conn.PostMultipart(endpoint, map[string]string{
						"action":      "logo",
						"displayName": wantName,
					}, fileField, wantName, data, s.Cookie)
					att := logoAttempt{Endpoint: endpoint, Field: fileField, BytesSent: len(data)}
					if perr != nil {
						att.NetError = perr.Error()
						upErr = perr
					} else {
						att.Status = status
						att.Body = trimDump(body)
						lower := strings.ToLower(body)
						badStatus := !strings.Contains(status, "200")
						badBody := strings.Contains(lower, "error") || strings.Contains(lower, "result\":false")
						if badStatus || badBody {
							if upErr == nil {
								upErr = fmt.Errorf("%s %s: %s %s", endpoint, fileField, status, trimDump(body))
							}
						} else {
							att.Accepted = true
							uploaded = true
						}
					}
					trace.Attempts = append(trace.Attempts, att)
					if uploaded {
						break
					}
				}
				if uploaded {
					break
				}
			}
		} else {
			upErr = fmt.Errorf("webui has no upload endpoint")
		}
		trace.Uploaded = uploaded
		if !uploaded {
			if upErr != nil {
				trace.Note = strings.TrimSpace(trace.Note + fmt.Sprintf(" | upload failed: %v", upErr))
			} else {
				trace.Note = strings.TrimSpace(trace.Note + " | upload failed")
			}
			s.Close()
			saveTrace()
			return fmt.Errorf("logo not uploaded: camera webui has no working upload endpoint (model may not support picture overlay; see logo_%s.json)", serial)
		}
		s.Close()
	}

	for _, port := range []int{5000, 37777} {
		ui.DebugLogf("logo", "%s > patching PictureTitle: name=%s via dhip:%d", serial, wantName, port)
		ds, derr := dhip.NewDHIPSession(tunnel, port, login, pass)
		if derr != nil {
			continue
		}
		if vwD, err := ds.Get("VideoWidget", 80); err == nil {
			if raw, jerr := json.Marshal(vwD.Nested); jerr == nil && len(trace.Before) == 0 {
				trace.Before = raw
			}
		}
		ok, perrText, afterState := patchPictureTitle(ds, wantName, 84)
		ds.Close()
		if len(afterState) > 0 {
			trace.After = afterState
		}
		if ok {
			trace.Applied = true
			trace.Note = strings.TrimSpace(trace.Note + fmt.Sprintf(" | applied via dhip:%d", port))
			trace.PatchError = ""
			ui.DebugLogf("logo", "%s > APPLIED via dhip:%d", serial, port)
			break
		}
		trace.PatchError = perrText
		ui.DebugLogf("logo", "%s > dhip:%d patch failed: %s", serial, port, perrText)
	}

	saveTrace()

	if !trace.Applied {
		if trace.PatchError == "" {
			trace.PatchError = "no transport available"
		}
		return fmt.Errorf("logo not applied: %s (see logo_%s.json)", trace.PatchError, serial)
	}
	return nil
}

func discoverUploadPaths(s *dhip.Session, serial string, trace *logoTrace) {
	var pageBody string
	for _, page := range []string{"/", "/index.html", "/index.htm"} {
		body, status, err := s.Conn.HTTPGet(page, s.Cookie)
		if err != nil || !strings.Contains(status, "200") || len(body) == 0 {
			continue
		}
		pageBody = body
		break
	}
	if pageBody == "" {
		return
	}

	pages := []struct {
		name string
		body string
	}{{"/", pageBody}}

	kws := []string{"upfile", "uploadfile", "upload", ".cgi", "multipart", "form-data", "logo", "picture"}
	for _, pg := range pages {
		lower := strings.ToLower(pg.body)
		for _, kw := range kws {
			idx := 0
			for found := 0; found < 4; found++ {
				i := strings.Index(lower[idx:], kw)
				if i < 0 {
					break
				}
				pos := idx + i
				start := pos - 100
				if start < 0 {
					start = 0
				}
				end := pos + 140
				if end > len(pg.body) {
					end = len(pg.body)
				}
				snip := strings.TrimSpace(pg.body[start:end])
				snip = strings.ReplaceAll(snip, "\n", " ")
				snip = strings.ReplaceAll(snip, "\r", " ")
				trace.Discovery = append(trace.Discovery, fmt.Sprintf("[%s] %s", pg.name, snip))
				idx = pos + len(kw)
			}
		}
	}
}

func trimDump(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	if len(s) > 400 {
		return s[:400]
	}
	return s
}
