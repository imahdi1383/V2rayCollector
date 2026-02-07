//go:build windows

package collector

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
	"syscall"
)

type SystemProxySnapshot struct {
	Enabled       bool
	Server        string
	AutoConfigURL string
	ProxyOverride string
}

func GetSystemProxySnapshot() (SystemProxySnapshot, error) {
	return getSystemProxySnapshot()
}

func SystemProxyHTTPProxyURL(s SystemProxySnapshot) (string, bool) {
	if !s.Enabled {
		return "", false
	}
	raw := strings.TrimSpace(s.Server)
	if raw == "" {
		return "", false
	}

	// Possible values:
	// - "127.0.0.1:2080"
	// - "http=127.0.0.1:2080;https=127.0.0.1:2080"
	if strings.Contains(raw, "=") {
		httpHostPort := ""
		for _, entry := range strings.Split(raw, ";") {
			k, v, ok := strings.Cut(entry, "=")
			if !ok {
				continue
			}
			if strings.EqualFold(strings.TrimSpace(k), "http") {
				httpHostPort = strings.TrimSpace(v)
				break
			}
		}
		raw = httpHostPort
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	if strings.Contains(raw, "://") {
		return raw, true
	}
	return "http://" + raw, true
}

func EnableSystemProxy(server string) (restore func() error, err error) {
	prev, err := getSystemProxySnapshot()
	if err != nil {
		return nil, err
	}

	next := prev
	next.Enabled = true
	next.Server = server
	if err := setSystemProxySnapshot(next); err != nil {
		return nil, err
	}
	if err := applySystemProxySettings(); err != nil {
		return nil, err
	}

	return func() error {
		if err := setSystemProxySnapshot(prev); err != nil {
			return err
		}
		return applySystemProxySettings()
	}, nil
}

func DisableSystemProxy() (restore func() error, err error) {
	prev, err := getSystemProxySnapshot()
	if err != nil {
		return nil, err
	}

	next := prev
	next.Enabled = false
	if err := setSystemProxySnapshot(next); err != nil {
		return nil, err
	}
	if err := applySystemProxySettings(); err != nil {
		return nil, err
	}

	return func() error {
		if err := setSystemProxySnapshot(prev); err != nil {
			return err
		}
		return applySystemProxySettings()
	}, nil
}

func getSystemProxySnapshot() (SystemProxySnapshot, error) {
	key, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.QUERY_VALUE)
	if err != nil {
		return SystemProxySnapshot{}, err
	}
	defer key.Close()

	enabledDWORD, _, err := key.GetIntegerValue("ProxyEnable")
	if err != nil {
		enabledDWORD = 0
	}
	server, _, err := key.GetStringValue("ProxyServer")
	if err != nil {
		server = ""
	}
	autoConfigURL, _, err := key.GetStringValue("AutoConfigURL")
	if err != nil {
		autoConfigURL = ""
	}
	proxyOverride, _, err := key.GetStringValue("ProxyOverride")
	if err != nil {
		proxyOverride = ""
	}

	return SystemProxySnapshot{
		Enabled:       enabledDWORD != 0,
		Server:        server,
		AutoConfigURL: autoConfigURL,
		ProxyOverride: proxyOverride,
	}, nil
}

func setSystemProxySnapshot(s SystemProxySnapshot) error {
	key, _, err := registry.CreateKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()

	var enabled uint32
	if s.Enabled {
		enabled = 1
	} else {
		enabled = 0
	}
	if err := key.SetDWordValue("ProxyEnable", enabled); err != nil {
		return err
	}
	if err := key.SetStringValue("ProxyServer", s.Server); err != nil {
		return err
	}
	if err := key.SetStringValue("AutoConfigURL", s.AutoConfigURL); err != nil {
		return err
	}
	if err := key.SetStringValue("ProxyOverride", s.ProxyOverride); err != nil {
		return err
	}
	return nil
}

func applySystemProxySettings() error {
	wininet := syscall.NewLazyDLL("wininet.dll")
	internetSetOption := wininet.NewProc("InternetSetOptionW")

	const (
		internetOptionRefresh         = 37
		internetOptionSettingsChanged = 39
	)

	if r, _, callErr := internetSetOption.Call(0, internetOptionSettingsChanged, 0, 0); r == 0 {
		return fmt.Errorf("InternetSetOptionW(INTERNET_OPTION_SETTINGS_CHANGED) failed: %v", callErr)
	}
	if r, _, callErr := internetSetOption.Call(0, internetOptionRefresh, 0, 0); r == 0 {
		return fmt.Errorf("InternetSetOptionW(INTERNET_OPTION_REFRESH) failed: %v", callErr)
	}
	return nil
}
