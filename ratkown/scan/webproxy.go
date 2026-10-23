package scan

import (
	"bytes"
	"fmt"
	"io"
	mrand "math/rand"
	net "net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"ratkown/ratkown/dhip"
	dhnet "ratkown/ratkown/net"
	"ratkown/ratkown/ui"
)

const maxWebProxies = 10

type webProx struct {
	serial string
	port   int
	stop   func()
}

func (s *Scanner) addWebProxy(serial string, port int, stop func()) {
	s.webMu.Lock()
	defer s.webMu.Unlock()
	for len(s.webProxies) >= maxWebProxies {
		oldest := s.webProxies[0]
		oldest.stop()
		s.webProxies = s.webProxies[1:]
	}
	s.webProxies = append(s.webProxies, webProx{serial: serial, port: port, stop: stop})
}

func (s *Scanner) stopWebProxies() {
	s.webMu.Lock()
	defer s.webMu.Unlock()
	for _, p := range s.webProxies {
		p.stop()
	}
	s.webProxies = nil
}

func startWebProxy(tunnel *dhnet.PTCPTunnel, serial, login, pass string, outDir string) (int, func(), error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, nil, err
	}
	realm := mrand.Uint32()
	if err := tunnel.DoBindToPort(realm, 80); err != nil {
		ln.Close()
		return 0, nil, err
	}

	sessCookie := ""
	if s, serr := dhip.NewRPC2Session(tunnel, login, pass); serr == nil {
		sessCookie = s.Cookie
		ui.DebugLogf("web", "%s > web session cookie acquired", serial)
	} else {
		ui.DebugLogf("web", "%s > no web session (%v), serving raw", serial, serr)
	}

	stopped := make(chan struct{})
	reqMu := make(chan struct{}, 1)
	go func() {
		defer close(stopped)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go proxyOneConn(c, tunnel, realm, serial, reqMu, sessCookie, outDir)
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	stop := func() {
		ln.Close()
		tunnel.DisconnectRealm(realm)
		<-stopped
	}
	return port, stop, nil
}

func proxyOneConn(c net.Conn, tunnel *dhnet.PTCPTunnel, realm uint32, serial string, reqMu chan struct{}, fallbackCookie string, outDir string) {
	defer c.Close()

	rawReq, err := readHTTPRequest(c)
	if err != nil {
		return
	}
	req, norm := rebuildMinimalRequest(rawReq, fallbackCookie)

	reqMu <- struct{}{}
	c.SetDeadline(time.Now().Add(30 * time.Second))
	var resp []byte
	var rerr error
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			time.Sleep(300 * time.Millisecond)
		}
		resp, rerr = tunnel.DoHTTPOnRealm(realm, req, 6*time.Second)
		if rerr == nil {
			break
		}
	}
	<-reqMu
	if norm {
		ui.DebugLogf("web", "%s > %s (%d bytes req)", serial, firstLine(req), len(req))
	}
	if rerr != nil {
		ui.DebugLogf("web", "%s > 502: %v", serial, rerr)
		io.WriteString(c, fmt.Sprintf("HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\nratk0wn proxy: %v\r\n", len(fmt.Sprintf("ratk0wn proxy: %v\r\n", rerr)), rerr))
		return
	}
	clean := sanitizeHTTP(resp)
	if len(clean) == 0 {
		io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: 21\r\nConnection: close\r\n\r\nratk0wn proxy: bad\r\n")
		return
	}

	dumpN++
	if dumpN <= 8 && outDir != "" {
		reqLine := sanitizeName(firstLine(req))
		_ = reqLine
		os.WriteFile(filepath.Join(outDir, fmt.Sprintf("webdump_%s_%02d_req.txt", serial, dumpN)), req, 0644)
		os.WriteFile(filepath.Join(outDir, fmt.Sprintf("webdump_%s_%02d_raw.bin", serial, dumpN)), resp, 0644)
		os.WriteFile(filepath.Join(outDir, fmt.Sprintf("webdump_%s_%02d_clean.bin", serial, dumpN)), clean, 0644)
	}

	if !bytes.Equal(clean, resp) {
		ui.DebugLogf("web", "%s > sanitized %d -> %d bytes", serial, len(resp), len(clean))
	}
	c.Write(clean)
}

var dumpN int

func sanitizeName(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '/' || r == '\\' || r == ':' || r == '?' || r == '*' || r == '"' || r == '<' || r == '>' || r == '|' || r == ' ' {
			return '-'
		}
		return r
	}, s)
	if len(s) > 60 {
		s = s[:60]
	}
	return s
}

func rebuildMinimalRequest(raw []byte, fallbackCookie string) ([]byte, bool) {
	headEnd := bytes.Index(raw, []byte("\r\n\r\n"))
	if headEnd < 0 {
		return raw, false
	}
	head := string(raw[:headEnd])
	body := raw[headEnd+4:]

	lines := strings.Split(head, "\r\n")
	if len(lines) == 0 || !strings.Contains(lines[0], " HTTP/") {
		return raw, false
	}
	var out strings.Builder
	out.WriteString(lines[0] + "\r\n")
	out.WriteString("Host: 127.0.0.1\r\n")
	hasCookie := false
	for _, l := range lines[1:] {
		lower := strings.ToLower(l)
		if strings.HasPrefix(lower, "host:") || strings.HasPrefix(lower, "connection:") ||
			strings.HasPrefix(lower, "accept-encoding:") || strings.HasPrefix(lower, "keep-alive") ||
			strings.HasPrefix(lower, "content-length:") {
			continue
		}
		if strings.HasPrefix(lower, "cookie:") || strings.HasPrefix(lower, "content-type:") ||
			strings.HasPrefix(lower, "referer:") || strings.HasPrefix(lower, "authorization:") ||
			strings.HasPrefix(lower, "if-modified-since:") {
			if strings.HasPrefix(lower, "cookie:") {
				hasCookie = true
			}
			out.WriteString(l + "\r\n")
		}
	}
	if !hasCookie && fallbackCookie != "" {
		out.WriteString("Cookie: " + fallbackCookie + "\r\n")
	}
	out.WriteString("User-Agent: Mozilla/5.0\r\n")
	out.WriteString("Accept: */*\r\n")
	out.WriteString("Accept-Encoding: identity\r\n")
	out.WriteString("Connection: close\r\n")
	if len(body) > 0 {
		out.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(body)))
	}
	out.WriteString("\r\n")
	full := append([]byte(out.String()), body...)
	return full, true
}

func sanitizeHTTP(raw []byte) []byte {
	start := bytes.Index(raw, []byte("HTTP/"))
	if start < 0 {
		pfx := raw
		if len(pfx) > 48 {
			pfx = pfx[:48]
		}
		ui.DebugLogf("web", "no HTTP marker, head=%q", pfx)
		return nil
	}
	if start > 0 {
		raw = raw[start:]
	}
	headEnd := bytes.Index(raw, []byte("\r\n\r\n"))
	if headEnd < 0 {
		return raw
	}
	head := string(raw[:headEnd])
	lower := strings.ToLower(head)
	bodyOff := headEnd + 4
	if strings.Contains(lower, "content-length:") {
		for _, line := range strings.Split(head, "\r\n") {
			if strings.HasPrefix(strings.ToLower(line), "content-length:") {
				cl, _ := strconv.Atoi(strings.TrimSpace(line[15:]))
				if cl >= 0 && bodyOff+cl <= len(raw) {
					return raw[:bodyOff+cl]
				}
				break
			}
		}
	}
	if strings.Contains(lower, "connection: close") && !strings.Contains(lower, "content-length:") && !strings.Contains(lower, "transfer-encoding:") {
		return raw[:bodyOff]
	}
	return raw
}

func forceAcceptIdentity(req []byte) []byte {
	if i := bytes.Index(req, []byte("\r\n\r\n")); i > 0 {
		head := string(req[:i])
		lower := strings.ToLower(head)
		if strings.Contains(lower, "accept-encoding:") {
			return req
		}
		newHead := head + "\r\nAccept-Encoding: identity"
		out := append([]byte(newHead), req[i:]...)
		return out
	}
	return req
}

func firstLine(req []byte) string {
	if i := bytes.IndexByte(req, '\r'); i > 0 {
		return string(req[:i])
	}
	if i := bytes.IndexByte(req, '\n'); i > 0 {
		return string(req[:i])
	}
	if len(req) > 40 {
		return string(req[:40])
	}
	return string(req)
}

func readHTTPRequest(c net.Conn) ([]byte, error) {
	var buf bytes.Buffer
	peak := make([]byte, 4096)
	headEnd := -1
	deadline := time.Now().Add(15 * time.Second)
	for headEnd < 0 {
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("idle request timeout")
		}
		c.SetReadDeadline(time.Now().Add(8 * time.Second))
		n, err := c.Read(peak)
		if n > 0 {
			buf.Write(peak[:n])
		}
		if err != nil {
			return nil, err
		}
		headEnd = bytes.Index(buf.Bytes(), []byte("\r\n\r\n"))
		if buf.Len() > 1<<20 {
			return nil, fmt.Errorf("headers too large")
		}
	}
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	head := buf.Bytes()[:headEnd]
	rest := buf.Bytes()[headEnd+4:]

	cl := 0
	for _, line := range strings.Split(string(head), "\r\n") {
		l := strings.ToLower(line)
		if strings.HasPrefix(l, "content-length:") {
			v := strings.TrimSpace(line[len("content-length:"):])
			cl, _ = strconv.Atoi(v)
		}
	}
	if cl > 8<<20 {
		return nil, fmt.Errorf("body too large")
	}
	for len(rest) < cl {
		n, err := c.Read(peak)
		if n > 0 {
			rest = append(rest, peak[:n]...)
		}
		if err != nil {
			return nil, err
		}
	}

	out := append([]byte{}, head...)
	out = append(out, '\r', '\n', '\r', '\n')
	out = append(out, rest[:cl]...)
	return out, nil
}

func forceConnectionClose(req []byte) []byte {
	if i := bytes.Index(req, []byte("\r\n\r\n")); i > 0 {
		head := string(req[:i])
		lower := strings.ToLower(head)
		if j := strings.Index(lower, "connection:"); j >= 0 {
			lineEnd := strings.Index(head[j:], "\r\n")
			if lineEnd > 0 {
				return append(append([]byte{}, req[:j]...), append([]byte("Connection: close"), req[j+lineEnd:]...)...)
			}
		}
		newHead := head + "\r\nConnection: close"
		out := append([]byte(newHead), req[i:]...)
		return out
	}
	return req
}
