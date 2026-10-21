package ui

import (
	"fmt"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"ratkown/ratkown/types"
)

const (
	tDim    = "\x1b[2m"
	tBold   = "\x1b[1m"
	tReset  = "\x1b[0m"
	tRed    = "\x1b[31m"
	tGreen  = "\x1b[32m"
	tYellow = "\x1b[33m"
	tMagenta= "\x1b[35m"
	tGray   = "\x1b[90m"
	tCyan   = "\x1b[96m"
	tBGreen = "\x1b[92m"
	tBYellow= "\x1b[93m"
	tBViolet= "\x1b[95m"
)

var allANSI = []string{tDim, tBold, tReset, tRed, tGreen, tYellow, tMagenta, tGray, tCyan, tBGreen, tBYellow, tBViolet}

var ratkoLogo = []string{
	"                                                   ",
	"                                mm                 ",
	"                        ##      ##                 ",
	"   ##m####   m#####m  #######   ## m##\"    m####m  ",
	"   ##\"       \" mmm##    ##      ##m##     ##\"  \"## ",
	"   ##       m##\"\"\"##    ##      ##\"##m    ##    ## ",
	"   ##       ##mmm###    ##mmm   ##  \"#m   \"##mm##\" ",
	"   \"\"        \"\"\"\" \"\"     \"\"\"\"   \"\"   \"\"\"    \"\"\"\"   ",
}

var rArt = []string{
	"       ______ ",
	"      / __  / ",
	"     / /_/ /  ",
	"    /  ___/  ",
	"   / /\\ \\    ",
	"  /_/  \\_\\   ",
}

var rPath = buildRPath()
var rIdx = buildRIndex()

func isInnerGlyph(y, x int) bool {
	if y == 1 && (x == 8 || x == 9) {
		return true
	}
	if y == 2 && (x == 7 || x == 8 || x == 9) {
		return true
	}
	return false
}

func buildRIndex() map[[2]int]int {
	m := make(map[[2]int]int, len(rPath))
	for i, d := range rPath {
		m[[2]int{d.y, d.x}] = i
	}
	return m
}

type rDot struct {
	x, y int
	ang  float64
}

func buildRPath() []rDot {
	var cells []rDot
	cy, cx := 2.5, 6.0
	for y, row := range rArt {
		for x, ch := range row {
			if ch == ' ' {
				continue
			}
			if isInnerGlyph(y, x) {
				continue
			}
			cells = append(cells, rDot{x: x, y: y,
				ang: math.Atan2(float64(y)-cy, (float64(x)-cx)*2.0)})
		}
	}
	sort.Slice(cells, func(i, j int) bool { return cells[i].ang < cells[j].ang })
	return cells
}

func rFrame(tick int, finished bool) []string {
	rows := make([]string, len(rArt))
	total := len(rPath)

	staticStyle := func(ch rune) string {
		return tDim + "\x1b[38;5;135m" + string(ch) + tReset
	}
	fullStyle := func(ch rune) string {
		if tick%2 == 0 {
			return tBold + tBViolet + string(ch) + tReset
		}
		return tBViolet + string(ch) + tReset
	}
	if finished {
		staticStyle = fullStyle
	}

	head := 0
	if total > 0 {
		head = tick % total
	}
	styleOf := func(k int) string {
		switch {
		case k == 0:
			return tBold + "\x1b[97m"
		case k <= 2:
			return tBViolet
		case k <= 4:
			return "\x1b[35m"
		default:
			return tGray
		}
	}

	for y := 0; y < len(rArt); y++ {
		var b strings.Builder
		for x := 0; x < 16; x++ {
			ch := ' '
			if x < len(rArt[y]) {
				ch = rune(rArt[y][x])
			}
			if ch == ' ' {
				b.WriteRune(' ')
				continue
			}
			if finished {
				b.WriteString(fullStyle(ch))
				continue
			}
			if isInnerGlyph(y, x) {
				b.WriteString(staticStyle(ch))
				continue
			}
			seg := -1
			for k := 0; k < 9; k++ {
				idx := head - k
				if idx < 0 {
					idx += total
				}
				if idx >= 0 && idx < total && rPath[idx].y == y && rPath[idx].x == x {
					seg = k
					break
				}
			}
			if seg < 0 {
				b.WriteRune(' ')
				continue
			}
			b.WriteString(styleOf(seg) + string(ch) + tReset)
		}
		rows[y] = b.String()
	}
	return rows
}

var rainbowPal = []string{"196", "202", "208", "214", "226", "190", "82", "76", "39", "45", "63", "129", "135", "165", "201", "213"}

var gradPal = []string{"231", "255", "254", "253", "252", "251", "250", "249", "248", "247", "246", "245"}

func gradientText(s string, tick int) string {
	var b strings.Builder
	for i, r := range s {
		if r == ' ' {
			b.WriteRune(' ')
			continue
		}
		c := gradPal[(i+tick)%len(gradPal)]
		fmt.Fprintf(&b, "\x1b[38;5;%sm%c\x1b[0m", c, r)
	}
	return b.String()
}

func rainbowText(s string, tick int) string {
	var b strings.Builder
	for i, r := range s {
		if r == ' ' {
			b.WriteRune(' ')
			continue
		}
		c := rainbowPal[(i+tick)%len(rainbowPal)]
		fmt.Fprintf(&b, "\x1b[38;5;%sm%c\x1b[0m", c, r)
	}
	return b.String()
}

const (
	kindFound   = 0
	kindWaste   = 1
	kindOwned   = 2
	kindOSDFail = 3
	kindInfo    = 4
)

type logEntry struct {
	kind int
	text string
}

type ownedRef struct {
	serial string
	idx    int
}

type scanTUI struct {
	mu        sync.Mutex
	enabled   bool
	utf8      bool
	w, h      int
	drawn     int
	lastH     int
	cfgLine   string
	log       []logEntry
	owned     map[string]*ownedRef
	logCap    int
	stats     struct {
		done, total, found, online, failed, owned, rate, checked int64
		elapsed                                               time.Duration
	}
	frameTick int
	finished  bool
	ptzUntil  time.Time
	ptzSerial string
	ptzModel  string
	closed    bool
	stopOnce  sync.Once
}

var activeTUI *scanTUI

func TUIInit() {
	t := &scanTUI{owned: map[string]*ownedRef{}, logCap: 128}
	force := os.Getenv("P2PWN_FORCE_TUI") != ""
	if !tuiIsTTY() && !force {
		return
	}
	t.enabled = true
	if force {
		t.utf8 = true
	} else {
		t.utf8 = tuiConsoleUTF8()
	}
	t.w, t.h = tuiTermSize()
	activeTUI = t
	go t.loop()
	if t.enabled {
		fmt.Print("\x1b[?25l")
	}
}

func TUISetupHeader(motd, cfg string, threads int, output string) {
	if activeTUI == nil {
		return
	}
	activeTUI.mu.Lock()
	defer activeTUI.mu.Unlock()
	motdPart := tCyan + "motd > " + tReset + tDim + motd + tReset
	cfgPart := tGray + "cfg > " + tReset + tBViolet + cfg + tReset
	threadsPart := tGray + "threads > " + tReset + tBold + strconv.Itoa(threads) + tReset
	outPart := tGray + "output > " + tReset + tBViolet + output + tGray + "/" + tReset
	activeTUI.cfgLine = strings.Join([]string{motdPart, cfgPart, threadsPart, outPart}, " ")
}

func (t *scanTUI) push(kind int, text string) {
	t.log = append(t.log, logEntry{kind: kind, text: text})
	if len(t.log) > t.logCap {
		cut := len(t.log) - t.logCap
		t.log = t.log[cut:]
		for s, ref := range t.owned {
			ref.idx -= cut
			if ref.idx < 0 {
				delete(t.owned, s)
			}
		}
	}
}

func TUIEventFound(serial string) {
	if activeTUI == nil {
		return
	}
	activeTUI.mu.Lock()
	defer activeTUI.mu.Unlock()
	activeTUI.push(kindFound, tBYellow+serial+tReset)
}

func TUIEventWaste(serial string) {
	if activeTUI == nil {
		return
	}
	activeTUI.mu.Lock()
	defer activeTUI.mu.Unlock()
	activeTUI.push(kindWaste, tDim+serial+tReset)
}

func TUIEventOnline(serial string) {}

func TUIEventOwned(serial, password string) {
	if activeTUI == nil {
		return
	}
	activeTUI.mu.Lock()
	defer activeTUI.mu.Unlock()
	if _, ok := activeTUI.owned[serial]; ok {
		return
	}
	okCh, _ := tickChars(activeTUI.utf8, true)
	text := fmt.Sprintf("%s pass:%s text:%s",
		tBGreen+serial+tReset, tBGreen+okCh+tReset, tDim+".."+tReset)
	activeTUI.push(kindOwned, text)
	activeTUI.owned[serial] = &ownedRef{serial: serial, idx: len(activeTUI.log) - 1}
	_ = password
}

func TUIMarkOSD(serial string, success bool, reason string) {
	if activeTUI == nil {
		return
	}
	activeTUI.mu.Lock()
	defer activeTUI.mu.Unlock()
	okCh, noCh := tickChars(activeTUI.utf8, true)
	if ref, ok := activeTUI.owned[serial]; ok && ref.idx >= 0 && ref.idx < len(activeTUI.log) {
		if success {
			activeTUI.log[ref.idx].text = fmt.Sprintf("%s pass:%s text:%s %s[done!]%s",
				tBGreen+serial+tReset, tBGreen+okCh+tReset, tBGreen+okCh+tReset, tBold+tBGreen, tReset)
		} else {
			short := reason
			if len(short) > 34 {
				short = short[:34]
			}
			activeTUI.log[ref.idx].text = fmt.Sprintf("%s pass:%s text:%s %s[%s]%s",
				tBGreen+serial+tReset, tBGreen+okCh+tReset, tRed+noCh+tReset, tRed, short, tReset)
		}
		return
	}
	if success {
		activeTUI.push(kindOwned, tBGreen+"osd "+okCh+" "+serial+tReset)
	} else {
		activeTUI.push(kindOSDFail, tRed+"osd "+noCh+" "+serial+tReset)
	}
}

func TUIMarkNuke(serial, op string, success bool, err error) {
	if activeTUI == nil {
		return
	}
	activeTUI.mu.Lock()
	defer activeTUI.mu.Unlock()
	okCh, noCh := tickChars(activeTUI.utf8, true)
	note := op
	if len(note) > 28 {
		note = note[:28]
	}
	if success {
		activeTUI.push(kindOwned, fmt.Sprintf("%s %s%s%s",
			tBGreen+"unmask "+okCh, tReset, tDim, serial+tReset))
	} else {
		reason := ""
		if err != nil {
			reason = err.Error()
			if len(reason) > 30 {
				reason = reason[:30]
			}
		}
		activeTUI.push(kindOSDFail, fmt.Sprintf("%s %s%s %s(%s)%s",
			tRed+"nuke "+noCh, tReset, serial, tDim, reason, tReset))
	}
	_ = note
}

func TUIStats(done, total, found, online, failed, owned, rate, checked int64, elapsed time.Duration) {
	if activeTUI == nil {
		return
	}
	activeTUI.mu.Lock()
	defer activeTUI.mu.Unlock()
	activeTUI.stats.done = done
	activeTUI.stats.total = total
	activeTUI.stats.found = found
	activeTUI.stats.online = online
	activeTUI.stats.failed = failed
	activeTUI.stats.owned = owned
	activeTUI.stats.rate = rate
	activeTUI.stats.checked = checked
	activeTUI.stats.elapsed = elapsed
}

func TUIPTZAlert(serial, model string) {
	if activeTUI == nil {
		return
	}
	if !types.IsPTZModel(model) {
		return
	}
	activeTUI.mu.Lock()
	defer activeTUI.mu.Unlock()
	activeTUI.ptzUntil = time.Now().Add(5 * time.Second)
	activeTUI.ptzSerial = serial
	activeTUI.ptzModel = model
	activeTUI.push(kindInfo, fmt.Sprintf("%s* PTZ!%s %s %s",
		tBold+tBViolet, tReset, serial, tDim+model+tReset))
}

func TUIActive() bool {
	return activeTUI != nil && activeTUI.enabled
}

func TUIShutdown() {
	if activeTUI == nil {
		return
	}
	activeTUI.stopOnce.Do(func() {
		activeTUI.mu.Lock()
		activeTUI.finished = true
		activeTUI.mu.Unlock()
		if activeTUI.enabled {
			activeTUI.render()
		}
		activeTUI.mu.Lock()
		activeTUI.closed = true
		activeTUI.mu.Unlock()
	})
	time.Sleep(600 * time.Millisecond)
	if activeTUI.enabled {
		fmt.Print("\x1b[?25h")
	}
}

func fmtDurationShort(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	total := int64(d.Seconds())
	h := total / 3600
	m := (total % 3600) / 60
	s := total % 60
	if h > 0 {
		return fmt.Sprintf("%dh %dm %02ds", h, m, s)
	}
	return fmt.Sprintf("%dm %02ds", m, s)
}

func (t *scanTUI) loop() {
	tick := time.NewTicker(320 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			t.mu.Lock()
			closed := t.closed
			t.mu.Unlock()
			if closed {
				return
			}
			t.render()
		}
	}
}

func centerLine(s string, w int) string {
	pad := (w - plainLen(s)) / 2
	if pad < 0 {
		pad = 0
	}
	return strings.Repeat(" ", pad) + cutANSI(s, w-pad)
}

func cutANSI(s string, max int) string {
	var b strings.Builder
	n := 0
	inESC := false
	sawStyle := false
	for _, r := range s {
		if inESC {
			b.WriteRune(r)
			if r == 'm' {
				inESC = false
			}
			continue
		}
		if r == 0x1b {
			b.WriteRune(r)
			inESC = true
			sawStyle = true
			continue
		}
		if n >= max {
			break
		}
		b.WriteRune(r)
		n++
	}
	if sawStyle && !strings.HasSuffix(b.String(), tReset) {
		b.WriteString(tReset)
	}
	return b.String()
}

func tickChars(utf8Mode bool, ok bool) (string, string) {
	if utf8Mode {
		if ok {
			return "✓", "✗"
		}
		return "..", "x"
	}
	if ok {
		return "v", "x"
	}
	return "..", "x"
}

func (t *scanTUI) barColor(pct float64) string {
	switch {
	case pct >= 95:
		return tBold + tBGreen
	case pct >= 75:
		return tBGreen
	case pct >= 40:
		return tCyan
	case pct >= 15:
		return tBYellow
	default:
		return tYellow
	}
}

func (t *scanTUI) eventPrefix(kind int) string {
	ok, _ := tickChars(t.utf8, true)
	_, no := tickChars(t.utf8, true)
	switch kind {
	case kindFound:
		return tGray + "» " + tReset
	case kindWaste:
		return tGray + "· " + tReset
	case kindOwned:
		return tBGreen + ok + " " + tReset
	case kindOSDFail:
		return tRed + no + " " + tReset
	default:
		return tCyan + "~ " + tReset
	}
}

func (t *scanTUI) render() {
	t.mu.Lock()
	defer t.mu.Unlock()

	w, h := tuiTermSize()
	if w != t.w || h != t.h {
		t.w, t.h = w, h
		t.drawn = 0
		if t.lastH > 0 {
			fmt.Print("\x1b[2J\x1b[H")
			t.lastH = 0
		}
	}

	lines := make([]string, 0, h+16)

	t.frameTick++
	art := rFrame(t.frameTick-1, t.finished)
	tick := t.frameTick
	st := t.stats

	brand := gradientText("ratk0wn by skver (fork p2pwn by thebadinteger)", tick)
	counters := fmt.Sprintf("%sonline%s >%d  %soffline%s >%d  %sratkowned%s >%d  %sfound%s >%d",
		tCyan, tReset, st.online,
		tGray, tReset, st.failed,
		tBGreen, tReset, st.owned,
		tBYellow, tReset, st.found)
	etaStr := "--"
	if st.rate > 0 {
		remain := float64(st.total-st.done) / float64(st.rate)
		if remain < 0 {
			remain = 0
		}
		etaStr = fmtDurationShort(time.Duration(remain * float64(time.Second)))
	}
	rates := fmt.Sprintf("%ss/n per second%s >%d  %ss/n checked%s >%d  %stime%s >%s  %seta%s ~%s",
		tCyan, tReset, st.rate,
		tBold, tReset, st.checked,
		tGray, tReset, fmtDurationShort(st.elapsed),
		tGray, tReset, etaStr)

	for r := 0; r < 6; r++ {
		left := ""
		if r < len(art) {
			left = art[r]
		}
		right := ""
		switch r {
		case 1:
			right = brand
		case 2:
			right = counters
		case 3:
			right = rates
		case 4:
			if t.cfgLine != "" {
				right = tDim + t.cfgLine + tReset
			}
		}
		pad := 16 - plainLen(left)
		if pad < 0 {
			pad = 0
		}
		row := "  " + left + strings.Repeat(" ", pad) + "   " + right
		lines = append(lines, cutANSI(row, w))
	}
	lines = append(lines, "")

	if t.ptzUntil.After(time.Now()) {
		remaining := time.Until(t.ptzUntil).Round(time.Second)
		ptzBanner := fmt.Sprintf(
			"[%sPTZ DETECTED%s] %s%s%s — %s%s (%v)",
			tBold+tBViolet, tReset,
			tBGreen, t.ptzSerial, tReset,
			tDim, t.ptzModel+tReset, remaining)
		lines = append(lines, cutANSI("  "+ptzBanner, w))
	}

	rows := h - len(lines) - 7
	if rows < 3 {
		rows = 3
	}
	if rows > 48 {
		rows = 48
	}
	start := len(t.log) - rows
	for i := 0; i < rows; i++ {
		idx := start + i
		if idx < 0 || idx >= len(t.log) {
			lines = append(lines, "")
			continue
		}
		e := t.log[idx]
		row := "  " + t.eventPrefix(e.kind) + e.text
		lines = append(lines, cutANSI(row, w))
	}
	lines = append(lines, "")

	pct := 0.0
	if st.total > 0 {
		pct = float64(st.done) / float64(st.total) * 100.0
	}
	if st.done >= st.total && st.total > 0 {
		pct = 100.0
	}
	scanPart := fmt.Sprintf("%sscan%s >%s%d%s",
		tBYellow, tReset, tBold, st.done, tReset)
	elapsed := FormatElapsed(st.elapsed)
	ratePart := fmt.Sprintf("%s %s/s [%s]%s", tDim, strconv.FormatInt(st.rate, 10), elapsed, tReset)
	pctStr := fmt.Sprintf("%.1f%%", pct)
	barWidth := w - 2 - plainLen(scanPart) - plainLen(ratePart) - len(pctStr) - 5
	if barWidth < 8 {
		barWidth = 8
	}
	filled := int(float64(barWidth) * pct / 100.0)
	if filled > barWidth {
		filled = barWidth
	}
	if filled < 0 {
		filled = 0
	}
	col := t.barColor(pct)
	bar := col + strings.Repeat("█", filled) + tGray + strings.Repeat("░", barWidth-filled) + tReset
	bottom := fmt.Sprintf("  %s%s|%s|%s %s %s", tBold, pctStr, bar, tReset, scanPart, ratePart)
	lines = append(lines, cutANSI(bottom, w))

	out := make([]byte, 0, 8192)
	if t.drawn > 0 {
		out = append(out, []byte(fmt.Sprintf("\x1b[%dA", len(lines)))...)
	}
	for _, ln := range lines {
		out = append(out, []byte("\r\x1b[2K"+ln+"\n")...)
	}
	os.Stdout.Write(out)
	t.drawn = len(lines)
	t.lastH = h
}

func plainLen(s string) int {
	plain := s
	for _, tag := range allANSI {
		plain = strings.ReplaceAll(plain, tag, "")
	}
	return len([]rune(plain))
}

func TUIThread(msg string) {
	if activeTUI != nil {
		activeTUI.mu.Lock()
		activeTUI.push(kindInfo, msg)
		activeTUI.mu.Unlock()
	}
}

func FormatElapsed(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	total := int64(d.Seconds())
	return fmt.Sprintf("%02d:%02d:%02d", total/3600, (total%3600)/60, total%60)
}
