package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type NekoRayAutoProxyOptions struct {
	ProfilesDir string
	GroupID     int

	VerifyURL string

	// Run URL test for all profiles in the group and reorder by latency.
	URLTest           bool
	URLTestURL        string
	URLTestTimeout    time.Duration
	URLTestConcurrent int

	EnableSystemProxy bool
	KeepProxyRunning  bool

	ListenAddress string
	ListenPort    int

	CoreStartTimeout time.Duration
	VerifyTimeout    time.Duration

	// Optional logger callback. Use this to surface progress in CLI mode.
	Logf func(format string, args ...any)
}

type NekoRayAutoProxyResult struct {
	ProxyURL  string
	ProfileID int
	Stop      func() error
}

func EnsureNekoRayProxyForURL(opts NekoRayAutoProxyOptions) (*NekoRayAutoProxyResult, error) {
	logf := opts.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}

	opts.VerifyURL = strings.TrimSpace(opts.VerifyURL)
	if opts.VerifyURL == "" {
		return nil, errors.New("VerifyURL is empty")
	}

	profilesDir := strings.TrimSpace(opts.ProfilesDir)
	if profilesDir == "" {
		if wd, err := os.Getwd(); err == nil {
			if dir, err := FindNekoRayProfilesDir(wd); err == nil && dir != "" {
				profilesDir = dir
			}
		}
	}
	if profilesDir == "" {
		return nil, errors.New("nekoray profiles dir not found")
	}

	coreExe, nekoRayDir, err := FindNekoRayCoreExeFromProfilesDir(profilesDir)
	if err != nil {
		return nil, err
	}

	if opts.ListenAddress == "" || opts.ListenPort <= 0 {
		addr, port, err := LoadNekoRayInboundFromProfilesDir(profilesDir)
		if err == nil {
			if opts.ListenAddress == "" {
				opts.ListenAddress = addr
			}
			if opts.ListenPort <= 0 {
				opts.ListenPort = port
			}
		}
	}
	if opts.ListenAddress == "" {
		opts.ListenAddress = "127.0.0.1"
	}
	if opts.ListenPort <= 0 {
		opts.ListenPort = 2080
	}
	if opts.CoreStartTimeout <= 0 {
		opts.CoreStartTimeout = 12 * time.Second
	}
	if opts.VerifyTimeout <= 0 {
		opts.VerifyTimeout = 15 * time.Second
	}

	logf("NekoRay auto-proxy: profilesDir=%s group=%d verify=%s listen=%s:%d", profilesDir, opts.GroupID, opts.VerifyURL, opts.ListenAddress, opts.ListenPort)

	prevHTTPProxy := os.Getenv("HTTP_PROXY")
	prevHTTPSProxy := os.Getenv("HTTPS_PROXY")

	restoreEnv := func() {
		if prevHTTPProxy == "" {
			_ = os.Unsetenv("HTTP_PROXY")
		} else {
			_ = os.Setenv("HTTP_PROXY", prevHTTPProxy)
		}
		if prevHTTPSProxy == "" {
			_ = os.Unsetenv("HTTPS_PROXY")
		} else {
			_ = os.Setenv("HTTPS_PROXY", prevHTTPSProxy)
		}
	}

	// Optional: URL test all profiles first to get a good ordering.
	if opts.URLTest {
		var restoreSystemProxy func() error
		if snap, err := GetSystemProxySnapshot(); err == nil && snap.Enabled {
			restore, err := DisableSystemProxy()
			if err == nil {
				restoreSystemProxy = restore
				logf("System Proxy temporarily disabled for URL test")
			} else {
				logf("Failed to disable System Proxy for URL test: %v", err)
			}
		}

		_ = os.Unsetenv("HTTP_PROXY")
		_ = os.Unsetenv("HTTPS_PROXY")

		testTimeout := opts.URLTestTimeout
		if testTimeout <= 0 && opts.URLTestConcurrent <= 0 && strings.TrimSpace(opts.URLTestURL) == "" {
			// Let NekoRayURLTestAndSort read defaults from nekobox.json.
			testTimeout = 0
		}

		logf("NekoRay URL test: starting...")
		tested, ok, testErr := NekoRayURLTestAndSort(NekoRayURLTestOptions{
			ProfilesDir: profilesDir,
			GroupID:     opts.GroupID,
			OnlyIDs:     nil,
			TestURL:     strings.TrimSpace(opts.URLTestURL),
			Timeout:     testTimeout,
			Concurrency: opts.URLTestConcurrent,
			CoreExePath: coreExe,
			NekoRayDir:  nekoRayDir,
			UpdateOrder: true,
			OnProgress: func(tested int, total int, ok int) {
				logf("NekoRay URL test: %d/%d ok=%d", tested, total, ok)
			},
		})
		if testErr != nil {
			logf("NekoRay URL test: failed: %v", testErr)
		} else {
			logf("NekoRay URL test: done tested=%d ok=%d", tested, ok)
		}

		restoreEnv()
		if restoreSystemProxy != nil {
			_ = restoreSystemProxy()
		}
	}

	metas, err := loadNekoRayProfilesMeta(profilesDir, opts.GroupID)
	if err != nil {
		return nil, err
	}
	if len(metas) == 0 {
		return nil, errors.New("no nekoray profiles found in group")
	}
	logf("NekoRay profiles loaded: %d", len(metas))

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

	if !isTCPPortAvailable(opts.ListenAddress, opts.ListenPort) {
		server := fmt.Sprintf("%s:%d", opts.ListenAddress, opts.ListenPort)
		proxyURL := fmt.Sprintf("http://%s", server)

		// If something is already listening here (like a running NekoRay instance),
		// just try to use it.
		if err := verifyViaProxy(proxyURL, opts.VerifyURL, opts.VerifyTimeout); err == nil {
			logf("NekoRay auto-proxy: using existing local proxy at %s", proxyURL)
			_ = os.Setenv("HTTP_PROXY", proxyURL)
			_ = os.Setenv("HTTPS_PROXY", proxyURL)

			var restoreSystemProxy func() error
			if opts.EnableSystemProxy {
				restore, err := EnableSystemProxy(server)
				if err == nil {
					restoreSystemProxy = restore
				} else {
					logf("NekoRay auto-proxy: failed enabling System Proxy: %v", err)
				}
			}

			stop := func() error {
				if opts.KeepProxyRunning {
					return nil
				}

				restoreEnv()
				if restoreSystemProxy != nil {
					_ = restoreSystemProxy()
				}
				return nil
			}

			return &NekoRayAutoProxyResult{
				ProxyURL:  proxyURL,
				ProfileID: -1,
				Stop:      stop,
			}, nil
		}

		// Pick a free port for a temporary local proxy.
		if free, err := pickFreeLocalPort(opts.ListenAddress); err == nil {
			opts.ListenPort = free
		}
	}

	server := fmt.Sprintf("%s:%d", opts.ListenAddress, opts.ListenPort)
	proxyURL := fmt.Sprintf("http://%s", server)

	for i, meta := range metas {
		logf("NekoRay auto-proxy: trying profile %d/%d id=%d yc=%d type=%s", i+1, len(metas), meta.ID, meta.Yc, meta.Type)
		cmd, cfgCleanup, err := startNekoRayCoreProxy(coreExe, nekoRayDir, profilesDir, meta.ID, opts.ListenAddress, opts.ListenPort)
		if err != nil {
			logf("NekoRay auto-proxy: failed starting core for profile id=%d: %v", meta.ID, err)
			continue
		}

		ok := false
		var restoreSystemProxy func() error

		if err := waitForTCP(server, opts.CoreStartTimeout); err == nil {
			_ = os.Setenv("HTTP_PROXY", proxyURL)
			_ = os.Setenv("HTTPS_PROXY", proxyURL)

			if err := verifyViaProxy(proxyURL, opts.VerifyURL, opts.VerifyTimeout); err == nil {
				ok = true
				if opts.EnableSystemProxy {
					restore, err := EnableSystemProxy(server)
					if err == nil {
						restoreSystemProxy = restore
					} else {
						logf("NekoRay auto-proxy: failed enabling System Proxy: %v", err)
					}
				}
			} else {
				logf("NekoRay auto-proxy: verify failed for profile id=%d: %v", meta.ID, err)
			}
		} else {
			logf("NekoRay auto-proxy: core did not listen for profile id=%d: %v", meta.ID, err)
		}

		if ok {
			stop := func() error {
				if opts.KeepProxyRunning {
					return nil
				}

				restoreEnv()

				if restoreSystemProxy != nil {
					_ = restoreSystemProxy()
				}
				if cmd.Process != nil {
					_ = cmd.Process.Kill()
					_, _ = cmd.Process.Wait()
				}
				cfgCleanup()
				return nil
			}

			return &NekoRayAutoProxyResult{
				ProxyURL:  proxyURL,
				ProfileID: meta.ID,
				Stop:      stop,
			}, nil
		}

		// Failed: cleanup and try next profile.
		restoreEnv()
		if restoreSystemProxy != nil {
			_ = restoreSystemProxy()
		}
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
		cfgCleanup()
	}

	restoreEnv()
	return nil, errors.New("failed to find a working nekoray profile for VerifyURL")
}

func isTCPPortAvailable(host string, port int) bool {
	ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}

func pickFreeLocalPort(host string) (int, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf("%s:0", host))
	if err != nil {
		return 0, err
	}
	defer ln.Close()

	addr := ln.Addr().String()
	_, portStr, ok := strings.Cut(addr, ":")
	if !ok {
		return 0, fmt.Errorf("unexpected listener addr: %s", addr)
	}
	p, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, err
	}
	return p, nil
}

func startNekoRayCoreProxy(coreExe string, nekoRayDir string, profilesDir string, profileID int, listenAddress string, listenPort int) (*exec.Cmd, func(), error) {
	configPath, cleanup, err := writeSingBoxProxyConfigForProfile(profilesDir, profileID, listenAddress, listenPort)
	if err != nil {
		return nil, func() {}, err
	}

	cmd := exec.Command(coreExe,
		"--disable-color",
		"-D", nekoRayDir,
		"-c", configPath,
		"run",
	)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard

	if err := cmd.Start(); err != nil {
		cleanup()
		return nil, func() {}, err
	}

	return cmd, cleanup, nil
}

func writeSingBoxProxyConfigForProfile(profilesDir string, profileID int, listenAddress string, listenPort int) (configPath string, cleanup func(), err error) {
	profilePath := filepath.Join(profilesDir, fmt.Sprintf("%d.json", profileID))
	b, err := os.ReadFile(profilePath)
	if err != nil {
		return "", func() {}, err
	}

	var raw rawProfileFile
	if err := json.Unmarshal(b, &raw); err != nil {
		return "", func() {}, err
	}

	outbound, err := singBoxOutboundFromNekoRayProfile(raw.Type, raw.Bean, "proxy")
	if err != nil {
		return "", func() {}, err
	}

	cfg := map[string]any{
		"log": map[string]any{
			"disabled": true,
		},
		"inbounds": []any{
			map[string]any{
				"type":        "mixed",
				"tag":         "mixed-in",
				"listen":      listenAddress,
				"listen_port": listenPort,
			},
		},
		"outbounds": []any{
			map[string]any{"type": "direct", "tag": "direct"},
			map[string]any{"type": "block", "tag": "block"},
			outbound,
		},
		"route": map[string]any{
			"final": "proxy",
		},
	}

	tmpDir, err := os.MkdirTemp("", "v2raycollector-nekoray-proxy-*")
	if err != nil {
		return "", func() {}, err
	}
	configPath = filepath.Join(tmpDir, "sing-box.json")

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		_ = os.RemoveAll(tmpDir)
		return "", func() {}, err
	}
	data = append(data, '\n')
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		_ = os.RemoveAll(tmpDir)
		return "", func() {}, err
	}

	cleanup = func() { _ = os.RemoveAll(tmpDir) }
	return configPath, cleanup, nil
}

func waitForTCP(address string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", address, 500*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for tcp listen: %s", address)
}

func verifyViaProxy(proxyURL string, verifyURL string, timeout time.Duration) error {
	proxy, err := url.Parse(proxyURL)
	if err != nil {
		return err
	}

	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = http.ProxyURL(proxy)
	tr.ForceAttemptHTTP2 = true

	c := &http.Client{
		Transport: tr,
		Timeout:   timeout,
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, verifyURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")

	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	_ = resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return nil
	}

	return fmt.Errorf("verify url returned status %d", resp.StatusCode)
}
