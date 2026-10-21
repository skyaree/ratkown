package types

import (
	"fmt"
	"strconv"
	"strings"
)

type ScanConfig struct {
	Timeout  interface{} `toml:"timeout"`
	Retries  interface{} `toml:"retries"`
	Generate interface{} `toml:"generate"`
	Nurses   interface{} `toml:"nurses"`
	MaxRPS   interface{} `toml:"maxrps"`
	Governor interface{} `toml:"governor"`
}

type PwnConfig struct {
	Protocol map[string]bool `toml:"protocol"`
	Methods  map[string]bool `toml:"methods"`
}

type ImageConfig struct {
	Snapshot bool `toml:"snapshot"`
	Rtsp     bool `toml:"rtsp"`
	Cgi      bool `toml:"cgi"`
	Sdk      bool `toml:"sdk"`
}

type NukeCoordsConfig struct {
	Box interface{} `toml:"box"`
}

type NukeConfig struct {
	Delete      bool             `toml:"delete"`
	Video       interface{}      `toml:"video"`
	Box         bool             `toml:"box"`
	Coordinates NukeCoordsConfig `toml:"coordinates"`
	BoxRects    [][4]int         `toml:"-"`
	Disable     bool             `toml:"disable"`
	MaskFront   []int            `toml:"mask_front"`
	MaskBack    []int            `toml:"mask_back"`
	Reboot      bool             `toml:"reboot"`
	RestoreVideo bool            `toml:"restore_video"`
}

type Credential struct {
	Login    string `toml:"login"`
	Password string `toml:"password"`
}

type BruteType1Config struct {
	Delay interface{} `toml:"delay"`
}

type BruteConfig struct {
	Type1       BruteType1Config `toml:"type1"`
	Credentials interface{}      `toml:"credentials"`
	Creds       []Credential     `toml:"-"`
}

type DummyConfig struct {
	Login    string `toml:"login"`
	Password string `toml:"password"`
	Memo     string `toml:"memo"`
}

type OverlayColorConfig struct {
	Front []int `toml:"front"`
	Back  []int `toml:"back"`
}

type OverlayConfig struct {
	Osd       bool               `toml:"osd"`
	Channel   string             `toml:"channel"`
	ColorMode string             `toml:"color_mode"`
	Color     OverlayColorConfig `toml:"color"`
	Custom    []string           `toml:"custom"`
}

type Config struct {
	Scan    ScanConfig    `toml:"scan"`
	Pwn     PwnConfig     `toml:"pwn"`
	Image   ImageConfig   `toml:"image"`
	Nuke    NukeConfig    `toml:"nuke"`
	Brute   BruteConfig   `toml:"brute"`
	Dummy   DummyConfig   `toml:"dummy"`
	Overlay OverlayConfig `toml:"overlay"`
	Path    string
}

type Range struct {
	Start int
	End   int
}

func GetIntValue(v interface{}) (int, error) {
	switch val := v.(type) {
	case int:
		return val, nil
	case int64:
		return int(val), nil
	case float64:
		return int(val), nil
	case string:
		return strconv.Atoi(val)
	default:
		return 0, fmt.Errorf("not an integer")
	}
}

func GetBoolValue(v interface{}) (bool, error) {
	switch val := v.(type) {
	case bool:
		return val, nil
	case int64:
		return val != 0, nil
	case float64:
		return val != 0, nil
	case string:
		return strconv.ParseBool(val)
	default:
		return false, fmt.Errorf("not a boolean")
	}
}

type ProvidedCred struct {
	Serial   string
	Login    string
	Password string
}

type ExploitResult struct {
	Method   string
	Login    string
	Password string
	Model    string
	Channels int
	IP       string
}

func IsNVRModel(model string) bool {
	m := strings.ToUpper(strings.TrimSpace(model))
	return strings.HasPrefix(m, "NVR") ||
		strings.HasPrefix(m, "DH-NVR") ||
		strings.HasPrefix(m, "DHI-NVR") ||
		strings.HasPrefix(m, "HCVR") ||
		strings.HasPrefix(m, "DH-HCVR") ||
		strings.HasPrefix(m, "DHI-HCVR")
}

func IsPTZModel(model string) bool {
	m := strings.ToUpper(strings.TrimSpace(model))
	if strings.HasPrefix(m, "SD") && len(m) > 2 && m[2] >= '0' && m[2] <= '9' {
		return true
	}
	if strings.HasPrefix(m, "DH-SD") || strings.HasPrefix(m, "DHI-SD") {
		return true
	}
	if strings.HasPrefix(m, "HSD") {
		return true
	}
	if strings.HasPrefix(m, "PT-PLATE") {
		return true
	}
	if strings.HasPrefix(m, "SPEEDDOME") || strings.HasPrefix(m, "SPEED DOME") {
		return true
	}
	return false
}

func (n NukeConfig) VideoLevel() int {
	if n.Video == nil {
		return 0
	}
	v, err := GetIntValue(n.Video)
	if err != nil || v <= 0 {
		return 0
	}
	return v
}

func (n NukeConfig) Enabled() bool {
	return n.Delete || n.Box || n.Disable || n.VideoLevel() > 0
}

