package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type NekoRayURLTestOptions struct {
	ProfilesDir string
	GroupID     int

	OnlyIDs []int

	TestURL     string
	Timeout     time.Duration
	Concurrency int
	CoreExePath string
	NekoRayDir  string
	UpdateOrder bool

	// Optional callback for long-running tests.
	// Called periodically as results come in.
	OnProgress func(tested int, total int, ok int)
}

type nekoRaySettings struct {
	TestURL          string `json:"test_url"`
	TestTimeout      int    `json:"test_dl_timeout"`
	TestConcurrent   int    `json:"test_concurrent"`
	InboundAddress   string `json:"inbound_address"`
	InboundSocksPort int    `json:"inbound_socks_port"`
}

type nekoRayProfileMeta struct {
	ID   int
	Gid  int
	Yc   int
	Type string
}

func LoadNekoRaySettingsFromProfilesDir(profilesDir string) (testURL string, timeout time.Duration, concurrency int, err error) {
	if profilesDir == "" {
		return "", 0, 0, errors.New("profilesDir is empty")
	}
	groupsDir := filepath.Clean(filepath.Join(profilesDir, "..", "groups"))
	settingsPath := filepath.Join(groupsDir, "nekobox.json")
	b, err := os.ReadFile(settingsPath)
	if err != nil {
		return "", 0, 0, err
	}

	var s nekoRaySettings
	if err := json.Unmarshal(b, &s); err != nil {
		return "", 0, 0, err
	}

	testURL = strings.TrimSpace(s.TestURL)
	if testURL == "" {
		testURL = "http://cp.cloudflare.com/"
	}
	if s.TestTimeout <= 0 {
		timeout = 30 * time.Second
	} else {
		timeout = time.Duration(s.TestTimeout) * time.Second
	}
	if s.TestConcurrent <= 0 {
		concurrency = 5
	} else {
		concurrency = s.TestConcurrent
	}

	return testURL, timeout, concurrency, nil
}

func LoadNekoRayInboundFromProfilesDir(profilesDir string) (listenAddress string, listenPort int, err error) {
	if profilesDir == "" {
		return "", 0, errors.New("profilesDir is empty")
	}

	groupsDir := filepath.Clean(filepath.Join(profilesDir, "..", "groups"))
	settingsPath := filepath.Join(groupsDir, "nekobox.json")
	b, err := os.ReadFile(settingsPath)
	if err != nil {
		return "", 0, err
	}

	var s nekoRaySettings
	if err := json.Unmarshal(b, &s); err != nil {
		return "", 0, err
	}

	listenAddress = strings.TrimSpace(s.InboundAddress)
	if listenAddress == "" {
		listenAddress = "127.0.0.1"
	}
	listenPort = s.InboundSocksPort
	if listenPort <= 0 {
		listenPort = 2080
	}

	return listenAddress, listenPort, nil
}

func FindNekoRayCoreExeFromProfilesDir(profilesDir string) (coreExe string, nekoRayDir string, err error) {
	if profilesDir == "" {
		return "", "", errors.New("profilesDir is empty")
	}
	nekoRayDir = filepath.Clean(filepath.Join(profilesDir, "..", ".."))
	coreExe = filepath.Join(nekoRayDir, "nekobox_core.exe")
	if _, err := os.Stat(coreExe); err == nil {
		return coreExe, nekoRayDir, nil
	}

	// Fallback: look for nekobox_core.exe in repo (portable folder names vary).
	repoRoot, wdErr := os.Getwd()
	if wdErr == nil {
		pattern := filepath.Join(repoRoot, "nekoray*", "nekoray", "nekobox_core.exe")
		matches, _ := filepath.Glob(pattern)
		sort.Strings(matches)
		for _, m := range matches {
			if _, err := os.Stat(m); err == nil {
				return m, filepath.Dir(m), nil
			}
		}
	}

	return "", "", fmt.Errorf("nekobox_core.exe not found near profiles dir: %s", profilesDir)
}

func NekoRayURLTestAndSort(opts NekoRayURLTestOptions) (tested int, ok int, err error) {
	if opts.ProfilesDir == "" {
		return 0, 0, errors.New("ProfilesDir is empty")
	}

	idSet := make(map[int]bool)
	for _, id := range opts.OnlyIDs {
		idSet[id] = true
	}

	profiles, err := loadNekoRayProfilesMeta(opts.ProfilesDir, opts.GroupID)
	if err != nil {
		return 0, 0, err
	}

	var idsToTest []int
	for _, p := range profiles {
		if p.Gid != opts.GroupID {
			continue
		}
		if len(idSet) > 0 && !idSet[p.ID] {
			continue
		}
		idsToTest = append(idsToTest, p.ID)
	}

	if len(idsToTest) == 0 {
		if opts.UpdateOrder {
			if err := sortNekoRayGroupByYC(opts.ProfilesDir, opts.GroupID); err != nil {
				return 0, 0, err
			}
		}
		return 0, 0, nil
	}

	// Defaults and settings (only needed if we're going to run tests).
	if opts.Concurrency <= 0 || opts.Timeout <= 0 || opts.TestURL == "" {
		testURL, timeout, concurrency, settingsErr := LoadNekoRaySettingsFromProfilesDir(opts.ProfilesDir)
		if settingsErr == nil {
			if opts.TestURL == "" {
				opts.TestURL = testURL
			}
			if opts.Timeout <= 0 {
				opts.Timeout = timeout
			}
			if opts.Concurrency <= 0 {
				opts.Concurrency = concurrency
			}
		}
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 5
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 30 * time.Second
	}
	if opts.TestURL == "" {
		opts.TestURL = "http://cp.cloudflare.com/"
	}

	if opts.CoreExePath == "" || opts.NekoRayDir == "" {
		coreExe, nekoRayDir, err := FindNekoRayCoreExeFromProfilesDir(opts.ProfilesDir)
		if err != nil {
			return 0, 0, err
		}
		opts.CoreExePath = coreExe
		opts.NekoRayDir = nekoRayDir
	}

	tempConfig, tagForID, cleanup, err := buildSingBoxConfigForProfiles(opts.ProfilesDir, opts.GroupID, idsToTest)
	if err != nil {
		return 0, 0, err
	}
	defer cleanup()

	jobs := make(chan int)
	type result struct {
		id      int
		latency int
		ok      bool
	}
	results := make(chan result)

	var wg sync.WaitGroup
	worker := func() {
		defer wg.Done()
		for id := range jobs {
			tag := tagForID[id]
			latency, ok := runSingBoxFetch(opts.CoreExePath, opts.NekoRayDir, tempConfig, opts.TestURL, tag, opts.Timeout)
			results <- result{id: id, latency: latency, ok: ok}
		}
	}

	workers := opts.Concurrency
	if workers > len(idsToTest) {
		workers = len(idsToTest)
	}
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go worker()
	}

	go func() {
		for _, id := range idsToTest {
			jobs <- id
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	for r := range results {
		tested++
		if r.ok {
			ok++
		} else {
			r.latency = -1
		}
		if err := updateNekoRayProfileYC(opts.ProfilesDir, r.id, r.latency); err != nil {
			return tested, ok, err
		}

		if opts.OnProgress != nil {
			// Throttle progress updates to avoid spamming logs.
			// Always call on the first and last item.
			total := len(idsToTest)
			if tested == 1 || tested == total || tested%25 == 0 {
				opts.OnProgress(tested, total, ok)
			}
		}
	}

	if opts.UpdateOrder {
		if err := sortNekoRayGroupByYC(opts.ProfilesDir, opts.GroupID); err != nil {
			return tested, ok, err
		}
	}

	return tested, ok, nil
}

func runSingBoxFetch(coreExe string, nekoRayDir string, configPath string, testURL string, outboundTag string, timeout time.Duration) (latencyMS int, ok bool) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	start := time.Now()
	cmd := exec.CommandContext(ctx, coreExe,
		"--disable-color",
		"-D", nekoRayDir,
		"-c", configPath,
		"tools", "fetch", testURL,
		"-o", outboundTag,
	)
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	_ = out
	if err != nil {
		return 0, false
	}
	return int(time.Since(start).Milliseconds()), true
}

func buildSingBoxConfigForProfiles(profilesDir string, groupID int, onlyIDs []int) (configPath string, tagForID map[int]string, cleanup func(), err error) {
	onlySet := make(map[int]bool)
	for _, id := range onlyIDs {
		onlySet[id] = true
	}

	files, err := filepath.Glob(filepath.Join(profilesDir, "*.json"))
	if err != nil {
		return "", nil, nil, err
	}

	tagForID = make(map[int]string)

	outbounds := []map[string]any{
		{"type": "direct", "tag": "direct"},
		{"type": "block", "tag": "block"},
	}

	for _, p := range files {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var raw rawProfileFile
		if err := json.Unmarshal(b, &raw); err != nil {
			continue
		}
		if raw.ID <= 0 && filepath.Base(p) == "0.json" {
			// keep id 0 too; no-op
		}
		if raw.Type == "" {
			continue
		}

		var meta struct {
			Gid int `json:"gid"`
			ID  int `json:"id"`
		}
		if err := json.Unmarshal(b, &meta); err != nil {
			continue
		}
		if meta.Gid != groupID {
			continue
		}
		if len(onlySet) > 0 && !onlySet[meta.ID] {
			continue
		}

		tag := "p" + strconv.Itoa(meta.ID)
		tagForID[meta.ID] = tag

		ob, err := singBoxOutboundFromNekoRayProfile(raw.Type, raw.Bean, tag)
		if err != nil {
			continue
		}
		outbounds = append(outbounds, ob)
	}

	cfg := map[string]any{
		"log": map[string]any{
			"disabled": true,
		},
		"route": map[string]any{
			"final": "direct",
		},
		"outbounds": outbounds,
	}

	tmpDir, err := os.MkdirTemp("", "v2raycollector-nekoray-*")
	if err != nil {
		return "", nil, nil, err
	}
	configPath = filepath.Join(tmpDir, "sing-box.json")
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		_ = os.RemoveAll(tmpDir)
		return "", nil, nil, err
	}
	data = append(data, '\n')
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		_ = os.RemoveAll(tmpDir)
		return "", nil, nil, err
	}

	cleanup = func() { _ = os.RemoveAll(tmpDir) }
	return configPath, tagForID, cleanup, nil
}

func singBoxOutboundFromNekoRayProfile(profileType string, beanRaw json.RawMessage, tag string) (map[string]any, error) {
	switch profileType {
	case "vless":
		var bean NekoRayVlessBean
		if err := json.Unmarshal(beanRaw, &bean); err != nil {
			return nil, err
		}
		return singBoxOutboundFromVless(bean, tag), nil
	case "trojan":
		var bean NekoRayTrojanBean
		if err := json.Unmarshal(beanRaw, &bean); err != nil {
			return nil, err
		}
		return singBoxOutboundFromTrojan(bean, tag), nil
	case "shadowsocks":
		var bean NekoRayShadowsocksBean
		if err := json.Unmarshal(beanRaw, &bean); err != nil {
			return nil, err
		}
		return singBoxOutboundFromShadowsocks(bean, tag), nil
	case "vmess":
		var bean NekoRayVmessBean
		if err := json.Unmarshal(beanRaw, &bean); err != nil {
			return nil, err
		}
		return singBoxOutboundFromVmess(bean, tag), nil
	default:
		return nil, fmt.Errorf("unsupported profile type: %s", profileType)
	}
}

func singBoxOutboundFromShadowsocks(bean NekoRayShadowsocksBean, tag string) map[string]any {
	return map[string]any{
		"type":        "shadowsocks",
		"tag":         tag,
		"server":      bean.Addr,
		"server_port": bean.Port,
		"method":      bean.Method,
		"password":    bean.Pass,
	}
}

func singBoxOutboundFromTrojan(bean NekoRayTrojanBean, tag string) map[string]any {
	ob := map[string]any{
		"type":        "trojan",
		"tag":         tag,
		"server":      bean.Addr,
		"server_port": bean.Port,
		"password":    bean.Pass,
	}
	if tls := singBoxTLS(bean.Stream); tls != nil {
		ob["tls"] = tls
	}
	if tr := singBoxTransport(bean.Stream); tr != nil {
		ob["transport"] = tr
	}
	return ob
}

func singBoxOutboundFromVless(bean NekoRayVlessBean, tag string) map[string]any {
	ob := map[string]any{
		"type":        "vless",
		"tag":         tag,
		"server":      bean.Addr,
		"server_port": bean.Port,
		"uuid":        bean.Pass,
		"encryption":  "none",
	}
	if tls := singBoxTLS(bean.Stream); tls != nil {
		ob["tls"] = tls
	}
	if tr := singBoxTransport(bean.Stream); tr != nil {
		ob["transport"] = tr
	}
	return ob
}

func singBoxOutboundFromVmess(bean NekoRayVmessBean, tag string) map[string]any {
	ob := map[string]any{
		"type":        "vmess",
		"tag":         tag,
		"server":      bean.Addr,
		"server_port": bean.Port,
		"uuid":        bean.Pass,
		"security":    firstNonEmpty(bean.Security, "auto"),
		"alter_id":    bean.AlterID,
	}
	if tls := singBoxTLS(bean.Stream); tls != nil {
		ob["tls"] = tls
	}
	if tr := singBoxTransport(bean.Stream); tr != nil {
		ob["transport"] = tr
	}
	return ob
}

func singBoxTLS(stream NekoRayStream) map[string]any {
	sec := strings.TrimSpace(strings.ToLower(stream.Sec))
	if sec != "tls" {
		return nil
	}
	serverName := strings.TrimSpace(firstNonEmpty(stream.Sni, stream.Host))
	tls := map[string]any{
		"enabled":  true,
		"insecure": stream.Insecure,
	}
	if serverName != "" {
		tls["server_name"] = serverName
	}
	if alpn := strings.TrimSpace(stream.ALPN); alpn != "" {
		parts := strings.Split(alpn, ",")
		var cleaned []string
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				cleaned = append(cleaned, p)
			}
		}
		if len(cleaned) > 0 {
			tls["alpn"] = cleaned
		}
	}
	return tls
}

func singBoxTransport(stream NekoRayStream) map[string]any {
	netType := strings.TrimSpace(strings.ToLower(stream.Net))
	switch netType {
	case "", "tcp":
		return nil
	case "ws", "websocket":
		path := stream.Path
		tr := map[string]any{
			"type": "ws",
		}
		if path != "" {
			tr["path"] = path
		}
		host := strings.TrimSpace(stream.Host)
		if host != "" {
			tr["headers"] = map[string]any{
				"Host": host,
			}
		}
		if ed := extractEarlyData(path); ed > 0 {
			tr["max_early_data"] = ed
			tr["early_data_header_name"] = "Sec-WebSocket-Protocol"
		}
		return tr
	case "grpc":
		serviceName := strings.TrimSpace(stream.ServiceName)
		if serviceName == "" {
			return nil
		}
		return map[string]any{
			"type":         "grpc",
			"service_name": serviceName,
		}
	default:
		return nil
	}
}

func extractEarlyData(path string) int {
	// NekoRay uses paths like "/?ed=2560"
	u, err := url.Parse("http://x" + path)
	if err != nil {
		return 0
	}
	ed := u.Query().Get("ed")
	if ed == "" {
		return 0
	}
	n, _ := strconv.Atoi(ed)
	return n
}

func updateNekoRayProfileYC(profilesDir string, id int, yc int) error {
	path := filepath.Join(profilesDir, fmt.Sprintf("%d.json", id))
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		return err
	}
	doc["yc"] = yc
	out, err := json.MarshalIndent(doc, "", "    ")
	if err != nil {
		return err
	}
	out = append(out, '\n')
	return os.WriteFile(path, out, 0644)
}

func loadNekoRayProfilesMeta(profilesDir string, groupID int) ([]nekoRayProfileMeta, error) {
	files, err := filepath.Glob(filepath.Join(profilesDir, "*.json"))
	if err != nil {
		return nil, err
	}
	var metas []nekoRayProfileMeta
	for _, p := range files {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var meta struct {
			Gid  int    `json:"gid"`
			ID   int    `json:"id"`
			Yc   int    `json:"yc"`
			Type string `json:"type"`
		}
		if err := json.Unmarshal(b, &meta); err != nil {
			continue
		}
		if meta.Gid != groupID {
			continue
		}
		metas = append(metas, nekoRayProfileMeta{
			ID:   meta.ID,
			Gid:  meta.Gid,
			Yc:   meta.Yc,
			Type: meta.Type,
		})
	}
	return metas, nil
}

func sortNekoRayGroupByYC(profilesDir string, groupID int) error {
	metas, err := loadNekoRayProfilesMeta(profilesDir, groupID)
	if err != nil {
		return err
	}
	sort.SliceStable(metas, func(i, j int) bool {
		ai := scoreYC(metas[i].Yc)
		aj := scoreYC(metas[j].Yc)
		if ai != aj {
			return ai < aj
		}
		if metas[i].Yc != metas[j].Yc {
			return metas[i].Yc < metas[j].Yc
		}
		return metas[i].ID < metas[j].ID
	})

	var order []int
	for _, m := range metas {
		order = append(order, m.ID)
	}

	groupPath := filepath.Clean(filepath.Join(profilesDir, "..", "groups", fmt.Sprintf("%d.json", groupID)))
	b, err := os.ReadFile(groupPath)
	if err != nil {
		return err
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		return err
	}
	doc["order"] = order
	out, err := json.MarshalIndent(doc, "", "    ")
	if err != nil {
		return err
	}
	out = append(out, '\n')
	return os.WriteFile(groupPath, out, 0644)
}

func scoreYC(yc int) int {
	// tested success: >0, untested: 0, failed: -1
	if yc > 0 {
		return 0
	}
	if yc == 0 {
		return 1
	}
	return 2
}
