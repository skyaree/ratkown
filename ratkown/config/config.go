package config

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"github.com/BurntSushi/toml"
	"ratkown/ratkown/types"
)

const DefaultConfigData = `[scan] # Scan configuration
timeout = 5000 # Connection timeout in milliseconds
retries = 3 # Number of retries on connect
generate = 1048576 # How many S/N to generate on prefix (1-1048576)
nurses = 200 # Number of workers for checking online S/N
governor = true # Enable/disable governor
maxrps = 3000 # Cap on concurrent online/offline checks

[pwn] # Usage of different protocols and methods
protocol.cgi = true # Web CGI protocol
protocol.sdk = true # 37777 SDK protocol
protocol.type1 = true # Type 1 protocol
methods.brute = true # Credentials bruteforce
methods.cve-2021-33044 = true # CVE-2021-33044
methods.cve-2021-33045 = true # CVE-2021-33045
methods.uau = true # Unauthenticated addUser
methods.antinuke = true # Auto-heal hostile covers + wrecked colors

[image]
snapshot = true # Take snapshots
cgi = true # Take snapshots with CGI
sdk = true # Take snapshots with SDK
rtsp = true # Take snapshots with RTSP

[brute] # Bruteforce configuration
type1.delay = 20 # Type 1 brute attempts delay in seconds
credentials = [
  { login = "admin", password = "admin" },
  { login = "admin", password = "admin123" },
  { login = "admin", password = "admin12345" },
  { login = "666666", password = "666666" },
  { login = "888888", password = "888888" },
] # Credentials list or '/path/to/wordlist' > login:password

[dummy] # Credentials for added dummy account
login = "p2pwn" # 5-32 alphanumeric characters
password = "p2password" # 8-32 alphanumeric characters
memo = "p2pwn" # Account note up to 32 characters

[overlay] # Custom overlay configuration
osd = false # Set OSD on pwned devices
channel = "p2pwn" # ChannelTitle (max 32 char)
custom = [
  "p2pwned",
  "device is vulnerable"
] # CustomTitle (up to 5 lines, max 22 char per line)
color.front = [255, 255, 255, 255] # OSD front color R G B A (0-255)
color.back = [0, 0, 0, 128] # OSD back color R G B A (0-255)

[nuke] # Experimental destructive options
delete = false # Delete all accounts except admin and dummy
video = 50 # Set all video settings to specified number (0-100)
box = false # Add box masks
coordinates.box = [
  [3383, 2047, 4649, 6245],
  [2620, 6145, 5362, 7411]
] # Box masks x1 y1 x2 y2 (up to 5 boxes)
disable = false # Disable P2P on the device when done
`

func ParseGenerateRanges(v interface{}) ([]types.Range, error) {
	switch val := v.(type) {
	case int:
		if val <= 0 || val > 1048576 {
			return nil, fmt.Errorf("invalid generate value")
		}
		return []types.Range{{0, val}}, nil
	case int64:
		return ParseGenerateRanges(int(val))
	case float64:
		return ParseGenerateRanges(int(val))
	case string:
		s := strings.TrimSpace(val)
		if s == "" || s == "all" {
			return []types.Range{{0, 1048576}}, nil
		}
		var ranges []types.Range
		for _, part := range strings.Split(s, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if strings.Contains(part, "-") {
				sub := strings.SplitN(part, "-", 2)
				start, err1 := strconv.Atoi(strings.TrimSpace(sub[0]))
				end, err2 := strconv.Atoi(strings.TrimSpace(sub[1]))
				if err1 != nil || err2 != nil || start < 0 || end > 1048576 || start >= end {
					return nil, fmt.Errorf("invalid range: %s", part)
				}
				ranges = append(ranges, types.Range{start, end})
			} else {
				idx, err := strconv.Atoi(part)
				if err != nil || idx < 0 || idx >= 1048576 {
					return nil, fmt.Errorf("invalid index: %s", part)
				}
				ranges = append(ranges, types.Range{idx, idx + 1})
			}
		}
		if len(ranges) == 0 {
			return nil, fmt.Errorf("empty generate spec")
		}
		return ranges, nil
	default:
		return nil, fmt.Errorf("invalid generate type")
	}
}

func LoadConfig(path string, isDefault bool) (*types.Config, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if isDefault {
			if err := os.WriteFile(path, []byte(DefaultConfigData), 0644); err != nil {
				return nil, fmt.Errorf("config not found and could not create default: %s", err)
			}
			return nil, fmt.Errorf("config not found, created default config.toml")
		} else {
			return nil, fmt.Errorf("config not found")
		}
	}

	var conf types.Config
	_, err := toml.DecodeFile(path, &conf)
	if err != nil {
		line := 1
		if pe, ok := err.(toml.ParseError); ok {
			line = pe.Position.Line
			return nil, fmt.Errorf("error in config on line %d: %s", line, pe.Message)
		}
		return nil, fmt.Errorf("error in config: %s", err)
	}

	timeoutMs, err := types.GetIntValue(conf.Scan.Timeout)
	if err != nil || timeoutMs <= 0 {
		return nil, fmt.Errorf("invalid timeout value in config")
	}

	_, err = types.GetIntValue(conf.Scan.Retries)
	if err != nil {
		return nil, fmt.Errorf("invalid retry value in config")
	}

	if _, err := ParseGenerateRanges(conf.Scan.Generate); err != nil {
		return nil, fmt.Errorf("invalid generate value in config: %s", err)
	}

	nursesVal, err := types.GetIntValue(conf.Scan.Nurses)
	if err != nil || nursesVal <= 0 {
		return nil, fmt.Errorf("invalid nurses value in config")
	}

	if conf.Scan.MaxRPS != nil {
		maxRPS, err := types.GetIntValue(conf.Scan.MaxRPS)
		if err != nil || maxRPS <= 0 {
			return nil, fmt.Errorf("invalid maxrps value in config")
		}
	}

	if conf.Scan.Governor != nil {
		if _, err := types.GetBoolValue(conf.Scan.Governor); err != nil {
			return nil, fmt.Errorf("invalid governor value in config")
		}
	}

	hasProtocol := false
	for _, enabled := range conf.Pwn.Protocol {
		if enabled {
			hasProtocol = true
			break
		}
	}
	if !hasProtocol {
		return nil, fmt.Errorf("at least one protocol must be enabled in config")
	}

	hasMethod := false
	for _, enabled := range conf.Pwn.Methods {
		if enabled {
			hasMethod = true
			break
		}
	}
	if !hasMethod {
		return nil, fmt.Errorf("at least one method must be enabled in config")
	}

	alphanum := regexp.MustCompile(`^[a-zA-Z0-9]+$`)
	if len(conf.Dummy.Login) < 5 || len(conf.Dummy.Login) > 32 || !alphanum.MatchString(conf.Dummy.Login) {
		return nil, fmt.Errorf("invalid dummy login format in config")
	}

	if len(conf.Dummy.Password) < 8 || len(conf.Dummy.Password) > 32 || !alphanum.MatchString(conf.Dummy.Password) {
		return nil, fmt.Errorf("invalid dummy password format in config")
	}

	if len(conf.Overlay.Custom) > 5 {
		return nil, fmt.Errorf("invalid overlay custom value in config (up to 5 lines)")
	}

	if len(conf.Dummy.Memo) > 32 {
		return nil, fmt.Errorf("invalid dummy memo format in config (up to 32 characters)")
	}

	if conf.Overlay.Color.Front, err = parseRGBA(conf.Overlay.Color.Front, "color.front", defaultRGBAFront); err != nil {
		return nil, err
	}
	if conf.Overlay.Color.Back, err = parseRGBA(conf.Overlay.Color.Back, "color.back", defaultRGBABack); err != nil {
		return nil, err
	}

	if conf.Nuke.BoxRects, err = parseBoxCoords(conf.Nuke.Coordinates.Box); err != nil {
		return nil, err
	}

	var defaultNukeFront = []int{0, 0, 0, 255}
	var defaultNukeBack = []int{0, 0, 0, 0}
	if conf.Nuke.MaskFront, err = parseRGBA(conf.Nuke.MaskFront, "mask_front", defaultNukeFront); err != nil {
		return nil, err
	}
	if conf.Nuke.MaskBack, err = parseRGBA(conf.Nuke.MaskBack, "mask_back", defaultNukeBack); err != nil {
		return nil, err
	}

	if !conf.Image.Rtsp && !conf.Image.Cgi && !conf.Image.Sdk {
		return nil, fmt.Errorf("at least one of rtsp cgi or sdk must be enabled in config")
	}

	creds, err := resolveCredentials(conf.Brute.Credentials, path)
	if err != nil {
		return nil, err
	}
	conf.Brute.Creds = creds

	conf.Path = path
	return &conf, nil
}

func resolveCredentials(v interface{}, configPath string) ([]types.Credential, error) {
	switch val := v.(type) {
	case nil:
		return nil, nil
	case []types.Credential:
		return val, nil
	case string:
		return loadWordlist(strings.TrimSpace(val), configPath)
	case []map[string]interface{}:
		return credsFromTables(val)
	case []interface{}:
		tables := make([]map[string]interface{}, 0, len(val))
		for _, item := range val {
			m, ok := item.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("invalid credentials entry in config")
			}
			tables = append(tables, m)
		}
		return credsFromTables(tables)
	default:
		return nil, fmt.Errorf("invalid credentials value in config")
	}
}

func credsFromTables(tables []map[string]interface{}) ([]types.Credential, error) {
	out := make([]types.Credential, 0, len(tables))
	for _, m := range tables {
		login, _ := m["login"].(string)
		password, _ := m["password"].(string)
		login = strings.TrimSpace(login)
		password = strings.TrimSpace(password)
		if login == "" {
			continue
		}
		out = append(out, types.Credential{Login: login, Password: password})
	}
	return out, nil
}

func loadWordlist(listPath, configPath string) ([]types.Credential, error) {
	raw, err := os.ReadFile(listPath)
	if err != nil && configPath != "" {
		alt := filepath.Join(filepath.Dir(configPath), listPath)
		raw, err = os.ReadFile(alt)
	}
	if err != nil {
		return nil, fmt.Errorf("read credentials wordlist: %w", err)
	}
	var out []types.Credential
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		login, password, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		login = strings.TrimSpace(login)
		password = strings.TrimSpace(password)
		if login == "" {
			continue
		}
		out = append(out, types.Credential{Login: login, Password: password})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("credentials wordlist has no usable entries")
	}
	return out, nil
}

var defaultRGBAFront = []int{255, 255, 255, 255}
var defaultRGBABack = []int{0, 0, 0, 128}

var defaultBoxRects = [][4]int{
	{3383, 2047, 4649, 6245},
	{2620, 6145, 5362, 7411},
}

func parseRGBA(v []int, name string, def []int) ([]int, error) {
	if v == nil {
		return append([]int(nil), def...), nil
	}
	if len(v) != 4 {
		return nil, fmt.Errorf("invalid overlay %s value in config (4 numbers 0-255)", name)
	}
	out := make([]int, 4)
	for i, n := range v {
		if n < 0 || n > 255 {
			return nil, fmt.Errorf("invalid overlay %s value in config (4 numbers 0-255)", name)
		}
		out[i] = n
	}
	return out, nil
}

func parseBoxCoords(v interface{}) ([][4]int, error) {
	if v == nil {
		return append([][4]int(nil), defaultBoxRects...), nil
	}
	arr, ok := v.([]interface{})
	if !ok || len(arr) > 5 {
		return nil, fmt.Errorf("invalid nuke coordinates.box value in config (up to 5 rects of 4 numbers)")
	}
	if len(arr) == 0 {
		return nil, nil
	}
	out := make([][4]int, 0, len(arr))
	for _, raw := range arr {
		inner, ok := raw.([]interface{})
		if !ok || len(inner) != 4 {
			return nil, fmt.Errorf("invalid nuke coordinates.box value in config (up to 5 rects of 4 numbers)")
		}
		var r [4]int
		for i, n := range inner {
			val, err := types.GetIntValue(n)
			if err != nil {
				return nil, fmt.Errorf("invalid nuke coordinates.box value in config (up to 5 rects of 4 numbers)")
			}
			r[i] = val
		}
		out = append(out, r)
	}
	return out, nil
}
