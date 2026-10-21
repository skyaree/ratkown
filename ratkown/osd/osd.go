package osd

import (
	"fmt"
	mrand "math/rand"
	"os"
	"strings"
	"time"
	"ratkown/ratkown/net"
	"ratkown/ratkown/dhip"
	"ratkown/ratkown/types"
)

const (
	osdChannelMaxChars = 32
	osdCustomMaxChars  = 22
	osdCustomMaxLines  = 5
)

func NormalizeOSDLines(custom []string) []string {
	var out []string
	for _, l := range custom {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if r := []rune(l); len(r) > osdCustomMaxChars {
			l = string(r[:osdCustomMaxChars])
		}
		out = append(out, l)
		if len(out) >= osdCustomMaxLines {
			break
		}
	}
	return out
}

func NormalizeOSDChannel(channel string) string {
	channel = strings.TrimSpace(channel)
	if r := []rune(channel); len(r) > osdChannelMaxChars {
		channel = string(r[:osdChannelMaxChars])
	}
	return channel
}

func pipeJoin(lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	if len(lines) > osdCustomMaxLines {
		lines = lines[len(lines)-osdCustomMaxLines:]
	}
	padded := make([]string, osdCustomMaxLines)
	copy(padded[osdCustomMaxLines-len(lines):], lines)
	return strings.Join(padded, "|")
}

type osdStyle struct {
	front, back  []int
	channelFront []int
}

var rainbowOSD = [][]int{
	{255, 60, 60, 255},  // red
	{255, 150, 20, 255},  // orange
	{255, 230, 0, 255},   // yellow
	{80, 255, 120, 255},  // green
	{60, 170, 255, 255},  // blue
	{200, 60, 255, 255},  // purple
	{255, 60, 170, 255},  // pink
}

func styleFromOverlay(o types.OverlayConfig) osdStyle {
	fix := func(c, def []int) []int {
		if len(c) != 4 {
			return def
		}
		return c
	}
	return osdStyle{
		front: fix(o.Color.Front, []int{255, 255, 255, 255}),
		back:  fix(o.Color.Back, []int{0, 0, 0, 128}),
	}
}

var quotePool []string

func loadQuotes() {
	if len(quotePool) > 0 {
		return
	}
	data, err := os.ReadFile("quote.txt")
	if err != nil {
		quotePool = []string{"ratk0wn owns u"}
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		l := strings.TrimSpace(line)
		if l != "" && !strings.HasPrefix(l, "#") {
			quotePool = append(quotePool, l)
		}
	}
	if len(quotePool) == 0 {
		quotePool = []string{"ratk0wn owns u"}
	}
}

var templateRng = mrand.New(mrand.NewSource(time.Now().UnixNano()))

func randToken(n int) string {
	chars := "abcdefghjkmnpqrstuvwxyz23456789"
	out := make([]byte, n)
	for i := range out {
		out[i] = chars[templateRng.Intn(len(chars))]
	}
	return string(out)
}

func ExpandOSDTemplate(text, serial, model, firmware, country string) string {
	loadQuotes()
	if country == "" {
		country = getCountryFromSerial(serial)
	}
	if serial == "" {
		serial = "unknown"
	}
	replacer := strings.NewReplacer(
		"{country}", country,
		"{s/n}", serial,
		"{serial}", serial,
		"{model}", model,
		"{firmware}", firmware,
		"{quote}", quotePool[templateRng.Intn(len(quotePool))],
		"{random}", randToken(6),
		"{serial_prefix}", serial[:10],
		"{date}", time.Now().Format("02.01"),
		"{time}", time.Now().Format("15:04"),
		"{br}", "\n",
	)
	return replacer.Replace(text)
}

func getCountryFromSerial(serial string) string {
	return ""
}

func StyleFromOverlaySerial(o types.OverlayConfig, serial string) osdStyle {
	st := styleFromOverlay(o)
	if !strings.EqualFold(strings.TrimSpace(o.ColorMode), "rainbow") {
		return st
	}
	h := 0
	for _, r := range serial {
		h = (h*31 + int(r)) % 9973
	}
	if h < 0 {
		h = -h
	}
	st.front = rainbowOSD[h%len(rainbowOSD)]
	st.channelFront = rainbowOSD[(h+3)%len(rainbowOSD)]
	return st
}

func rgbaAny(c []int) []any {
	out := make([]any, len(c))
	for i, n := range c {
		out[i] = n
	}
	return out
}

var bottomBoxRect = []int{5321, 7450, 7931, 7868}

func setIfExists(m map[string]any, key string, val any) {
	if _, ok := m[key]; ok {
		m[key] = val
	}
}

func buildTitleSet(vwTable, ctTable []any, channel string, lines []string, style osdStyle) (ctOut, vwOut []any) {
	if channel != "" {
		chFront := style.front
		if style.channelFront != nil {
			chFront = style.channelFront
		}
		entry := map[string]any{
			"Name":       channel,
			"FrontColor": rgbaAny(chFront),
		}
		if len(ctTable) == 0 {
			ctOut = []any{entry}
		} else {
			ctOut = make([]any, 0, len(ctTable))
			for _, raw := range ctTable {
				if _, ok := raw.(map[string]any); ok {
					ctOut = append(ctOut, entry)
				}
			}
		}
	}
	if channel == "" && len(lines) == 0 {
		return ctOut, nil
	}
	text := pipeJoin(lines)
	for _, raw := range vwTable {
		m, ok := raw.(map[string]any)
		if !ok {
			vwOut = append(vwOut, raw)
			continue
		}
		if w, ok := m["ChannelTitle"].(map[string]any); ok {
			w["EncodeBlend"] = true
			w["PreviewBlend"] = true
			if channel != "" {
				chFront := style.front
				if style.channelFront != nil {
					chFront = style.channelFront
				}
				w["FrontColor"] = rgbaAny(chFront)
				w["BackColor"] = rgbaAny(style.back)
			}
		}
		if covers, ok := m["Covers"].([]any); ok {
			for _, c := range covers {
				if cm, ok := c.(map[string]any); ok {
					cm["EncodeBlend"] = false
					cm["PreviewBlend"] = false
				}
			}
		}
		if ct, ok := m["CustomTitle"].([]any); ok && len(ct) > 0 {
			idx := 1
			if idx >= len(ct) {
				idx = 0
			}
			for j := range ct {
				sm, ok := ct[j].(map[string]any)
				if !ok {
					continue
				}
				if len(lines) > 0 && j == idx {
					sm["Text"] = text
					sm["EncodeBlend"] = true
					sm["PreviewBlend"] = true
					sm["FrontColor"] = rgbaAny(style.front)
					sm["BackColor"] = rgbaAny(style.back)
					setIfExists(sm, "TextAlign", 2)
					sm["Rect"] = append([]int(nil), bottomBoxRect...)
				} else {
					sm["Text"] = ""
					sm["EncodeBlend"] = false
					sm["PreviewBlend"] = false
				}
			}
		}
		vwOut = append(vwOut, m)
	}
	return ctOut, vwOut
}

func intListEqual(got any, want []int) bool {
	arr, ok := got.([]any)
	if !ok || len(arr) != len(want) {
		return false
	}
	for i, w := range want {
		var n int
		switch v := arr[i].(type) {
		case float64:
			n = int(v)
		case int:
			n = v
		case int64:
			n = int(v)
		default:
			return false
		}
		if n != w {
			return false
		}
	}
	return true
}

func verifyTitleState(label string, newSess func() (*dhip.Session, error), channel string, lines []string, style osdStyle) (bool, bool, bool) {
	ctOK, vwOK := channel == "", len(lines) == 0
	colChan, colCustom := channel == "", len(lines) == 0
	if ctOK && vwOK && colChan && colCustom {
		return true, true, true
	}
	s, err := newSess()
	if err != nil {
		return channel == "", len(lines) == 0, false
	}
	defer s.Close()
	if !ctOK {
		if d, err := s.Get("ChannelTitle", 50); err == nil {
			for _, raw := range d.Nested {
				if m, _ := raw.(map[string]any); m != nil {
					if n, _ := m["Name"].(string); n == channel {
						ctOK = true
						break
					}
				}
			}
		}
	}
	wantText := pipeJoin(lines)
	if d, err := s.Get("VideoWidget", 51); err == nil {
		for _, raw := range d.Nested {
			m, _ := raw.(map[string]any)
			if m == nil {
				continue
			}
			if w, ok := m["ChannelTitle"].(map[string]any); ok && channel != "" {
				colChan = intListEqual(w["FrontColor"], style.front) && intListEqual(w["BackColor"], style.back)
			}
			ct, _ := m["CustomTitle"].([]any)
			for _, sraw := range ct {
				sm, _ := sraw.(map[string]any)
				if sm == nil {
					continue
				}
				if t, _ := sm["Text"].(string); t != "" && t == wantText {
					vwOK = true
					colCustom = intListEqual(sm["FrontColor"], style.front) && intListEqual(sm["BackColor"], style.back)
				}
			}
		}
	}
	return ctOK, vwOK, colChan && colCustom
}

func applySingleShot(label string, newSess func() (*dhip.Session, error), channel string, lines []string, style osdStyle) error {
	s, err := newSess()
	if err != nil {
		return fmt.Errorf("%s session: %w", label, err)
	}
	defer s.Close()
	vwD, err := s.Get("VideoWidget", 10)
	if err != nil {
		return fmt.Errorf("%s get VideoWidget: %w", label, err)
	}
	ctD, err := s.Get("ChannelTitle", 11)
	if err != nil {
		return fmt.Errorf("%s get ChannelTitle: %w", label, err)
	}
	ctOut, vwOut := buildTitleSet(vwD.Nested, ctD.Nested, channel, lines, style)
	if len(ctOut) == 0 && len(vwOut) == 0 {
		return fmt.Errorf("%s: nothing to set", label)
	}
	time.Sleep(100 * time.Millisecond)
	setErr := s.SetBoth(ctOut, vwOut)
	if setErr == nil {
		ctOK, vwOK, _ := verifyTitleState(label, newSess, channel, lines, style)
		if !ctOK || !vwOK {
			return fmt.Errorf("%s: not verified (verified channel=%v video=%v)", label, ctOK, vwOK)
		}
		if cerr := applyColorPass(label, newSess, channel, lines, style); cerr != nil {
			return cerr
		}
		return nil
	}
	if !IsConnBreakErr(setErr) {
		return fmt.Errorf("%s: %w", label, setErr)
	}
	ctOK, vwOK, _ := verifyTitleState(label, newSess, channel, lines, style)
	if !ctOK || !vwOK {
		return fmt.Errorf("%s: %v (verified channel=%v video=%v)", label, setErr, ctOK, vwOK)
	}
	if cerr := applyColorPass(label, newSess, channel, lines, style); cerr != nil {
		return fmt.Errorf("%s: %v (%v)", label, setErr, cerr)
	}
	return nil
}

func applyColorPass(label string, newSess func() (*dhip.Session, error), channel string, lines []string, style osdStyle) error {
	s, err := newSess()
	if err != nil {
		return fmt.Errorf("%s colors session: %w", label, err)
	}
	defer s.Close()
	if _, _, colOK := verifyTitleState(label, newSess, channel, lines, style); colOK {
		return nil
	}
	var lastErr error = fmt.Errorf("%s: text applied but colors rejected", label)
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(2 * time.Second)
		}
		vwD, err := s.Get("VideoWidget", 60)
		if err != nil {
			lastErr = fmt.Errorf("%s colors get VideoWidget: %w", label, err)
			continue
		}
		vwOut := colorPatchTable(vwD.Nested, channel, lines, style)
		if len(vwOut) == 0 {
			return fmt.Errorf("%s: nothing to color", label)
		}
		if err := s.SetBoth(nil, vwOut); err != nil {
			if s.Conn != nil {
				if _, serr := dhip.SecuritySetConfig(s.Conn, s.Sess, s.Cookie, "VideoWidget", vwOut); serr == nil {
					if _, _, colOK := verifyTitleState(label, newSess, channel, lines, style); !colOK {
						lastErr = fmt.Errorf("%s colors: security rejected by verify (%v)", label, serr)
						continue
					} else {
						return nil
					}
				}
			}
			lastErr = fmt.Errorf("%s colors: %w", label, err)
			continue
		}
		if _, _, colOK := verifyTitleState(label, newSess, channel, lines, style); colOK {
			return nil
		}
		vwAlt := altColorPatchTable(vwD.Nested, channel, lines, style)
		if err := s.SetBoth(nil, vwAlt); err == nil {
			if _, _, colOK := verifyTitleState(label, newSess, channel, lines, style); colOK {
				return nil
			}
		}
	}
	return lastErr
}

func altColorPatchTable(vwTable []any, channel string, lines []string, style osdStyle) []any {
	wantText := pipeJoin(lines)
	var out []any
	for _, raw := range vwTable {
		m, ok := raw.(map[string]any)
		if !ok {
			out = append(out, raw)
			continue
		}
		if w, ok := m["ChannelTitle"].(map[string]any); ok && channel != "" {
			w["EncodeBlend"] = true
			w["PreviewBlend"] = true
			w["FrontColor"] = rgbaAny(style.front)
			w["TextColor"] = rgbaAny(style.front)
			w["Color"] = rgbaAny(style.front)
		}
		if ct, ok := m["CustomTitle"].([]any); ok {
			for _, sraw := range ct {
				sm, _ := sraw.(map[string]any)
				if sm == nil {
					continue
				}
				if t, _ := sm["Text"].(string); t != "" && t == wantText {
					sm["EncodeBlend"] = true
					sm["PreviewBlend"] = true
					sm["FrontColor"] = rgbaAny(style.front)
					sm["TextColor"] = rgbaAny(style.front)
					sm["Color"] = rgbaAny(style.front)
				}
			}
		}
		out = append(out, m)
	}
	return out
}

func colorPatchTable(vwTable []any, channel string, lines []string, style osdStyle) []any {
	wantText := pipeJoin(lines)
	var out []any
	patched := false
	for _, raw := range vwTable {
		m, ok := raw.(map[string]any)
		if !ok {
			out = append(out, raw)
			continue
		}
		if w, ok := m["ChannelTitle"].(map[string]any); ok && channel != "" {
			w["EncodeBlend"] = true
			w["PreviewBlend"] = true
			w["FrontColor"] = rgbaAny(style.front)
			w["BackColor"] = rgbaAny(style.back)
			patched = true
		}
		if ct, ok := m["CustomTitle"].([]any); ok {
			for _, sraw := range ct {
				sm, _ := sraw.(map[string]any)
				if sm == nil {
					continue
				}
				if t, _ := sm["Text"].(string); t != "" && t == wantText {
					sm["EncodeBlend"] = true
					sm["PreviewBlend"] = true
					sm["FrontColor"] = rgbaAny(style.front)
					sm["BackColor"] = rgbaAny(style.back)
					patched = true
				}
			}
		}
		out = append(out, m)
	}
	if !patched {
		return nil
	}
	return out
}

func IsConnBreakErr(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	for _, sub := range []string{"timeout", "eof", "reset", "broken pipe", "disconnected", "connection refused"} {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func tryOSDPort(getTunnel func() *net.PTCPTunnel, port int, login, pass, channel string, lines []string, style osdStyle) error {
	label := fmt.Sprintf("port %d", port)
	var newSess func() (*dhip.Session, error)
	if port == 80 {
		newSess = func() (*dhip.Session, error) { return dhip.NewRPC2Session(getTunnel(), login, pass) }
	} else {
		newSess = func() (*dhip.Session, error) { return dhip.NewDHIPSession(getTunnel(), port, login, pass) }
	}
	return applySingleShot(label, newSess, channel, lines, style)
}

func TryOSD(tunnel *net.PTCPTunnel, login, pass, channel string, custom []string, style osdStyle, redial func() (*net.PTCPTunnel, func(), bool)) error {
	channel = NormalizeOSDChannel(channel)
	lines := NormalizeOSDLines(custom)
	if channel == "" && len(lines) == 0 {
		return fmt.Errorf("nothing to set (channel and custom are empty)")
	}

	cur := tunnel
	var cleanups []func()
	defer func() {
		for _, c := range cleanups {
			c()
		}
	}()
	healCount := 0
	heal := func() bool {
		if redial == nil || healCount >= 5 {
			return false
		}
		healCount++
		nt, cleanup, ok := redial()
		if !ok {
			return false
		}
		cur = nt
		cleanups = append(cleanups, cleanup)
		return true
	}
	getTunnel := func() *net.PTCPTunnel { return cur }

	runPort := func(port int) error {
		if err := tryOSDPort(getTunnel, port, login, pass, channel, lines, style); err == nil {
			return nil
		} else {
			if IsConnBreakErr(err) && heal() {
				return tryOSDPort(getTunnel, port, login, pass, channel, lines, style)
			}
			return err
		}
	}

	const rounds = 3
	var lastErr error = fmt.Errorf("no attempts made")
	for round := 0; round < rounds; round++ {
		if round > 0 {
			time.Sleep(3 * time.Second)
		}
		if err := runPort(5000); err == nil {
			return nil
		} else {
			lastErr = err
		}
		if err := runPort(80); err == nil {
			return nil
		} else {
			lastErr = err
		}
		if err := tryOSDForce(getTunnel, login, pass, channel, lines, style); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}

	if werr := tryOSDWipe(getTunnel, login, pass); werr == nil {
		return fmt.Errorf("OSD wiped after retries (rejected: %v)", lastErr)
	}
	return fmt.Errorf("OSD skipped after %d rounds, 5000/80/security failed: %v", rounds, lastErr)
}

func tryOSDForce(getTunnel func() *net.PTCPTunnel, login, pass, channel string, lines []string, style osdStyle) error {
	s, err := dhip.NewRPC2Session(getTunnel(), login, pass)
	if err != nil {
		return fmt.Errorf("force session: %w", err)
	}
	defer s.Close()
	vwD, err := s.Get("VideoWidget", 10)
	if err != nil {
		return fmt.Errorf("force get VideoWidget: %w", err)
	}
	ctD, err := s.Get("ChannelTitle", 11)
	if err != nil {
		return fmt.Errorf("force get ChannelTitle: %w", err)
	}
	ctOut, vwOut := buildTitleSet(vwD.Nested, ctD.Nested, channel, lines, style)
	if len(ctOut) == 0 && len(vwOut) == 0 {
		return nil
	}
	var lastErr error
	if len(ctOut) > 0 {
		if _, err := dhip.SecuritySetConfig(s.Conn, s.Sess, s.Cookie, "ChannelTitle", ctOut); err != nil {
			lastErr = fmt.Errorf("force ChannelTitle: %w", err)
		}
	}
	if len(vwOut) > 0 {
		if _, err := dhip.SecuritySetConfig(s.Conn, s.Sess, s.Cookie, "VideoWidget", vwOut); err != nil {
			lastErr = fmt.Errorf("force VideoWidget: %w", err)
		}
	}
	if lastErr != nil {
		return lastErr
	}
	ctOK, vwOK, _ := verifyTitleState("force", func() (*dhip.Session, error) {
		return dhip.NewRPC2Session(getTunnel(), login, pass)
	}, channel, lines, style)
	if !ctOK || !vwOK {
		return fmt.Errorf("force applied but not verified (channel=%v video=%v)", ctOK, vwOK)
	}
	return nil
}

func tryOSDWipe(getTunnel func() *net.PTCPTunnel, login, pass string) error {
	s, err := dhip.NewRPC2Session(getTunnel(), login, pass)
	if err != nil {
		return fmt.Errorf("wipe session: %w", err)
	}
	defer s.Close()
	vwD, err := s.Get("VideoWidget", 12)
	if err != nil {
		return fmt.Errorf("wipe get VideoWidget: %w", err)
	}
	ctD, err := s.Get("ChannelTitle", 13)
	if err != nil {
		return fmt.Errorf("wipe get ChannelTitle: %w", err)
	}
	blankStyle := osdStyle{front: []int{255, 255, 255, 255}, back: []int{0, 0, 0, 0}}
	blankLines := []string{" ", " ", " ", " ", " "}
	ctOut, vwOut := buildTitleSet(vwD.Nested, ctD.Nested, " ", blankLines, blankStyle)
	if len(ctOut) == 0 && len(vwOut) == 0 {
		return nil
	}
	var lastErr error
	if len(ctOut) > 0 {
		if err := s.SetBoth(ctOut, nil); err != nil {
			if _, serr := dhip.SecuritySetConfig(s.Conn, s.Sess, s.Cookie, "ChannelTitle", ctOut); serr != nil {
				lastErr = fmt.Errorf("wipe ChannelTitle: %v / %v", err, serr)
			}
		}
	}
	if len(vwOut) > 0 {
		if err := s.SetBoth(nil, vwOut); err != nil {
			if _, serr := dhip.SecuritySetConfig(s.Conn, s.Sess, s.Cookie, "VideoWidget", vwOut); serr != nil {
				lastErr = fmt.Errorf("wipe VideoWidget: %v / %v", err, serr)
			}
		}
	}
	return lastErr
}
