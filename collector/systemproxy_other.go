//go:build !windows

package collector

type SystemProxySnapshot struct {
	Enabled       bool
	Server        string
	AutoConfigURL string
	ProxyOverride string
}

func GetSystemProxySnapshot() (SystemProxySnapshot, error) {
	return SystemProxySnapshot{}, nil
}

func SystemProxyHTTPProxyURL(s SystemProxySnapshot) (string, bool) {
	_ = s
	return "", false
}

func EnableSystemProxy(server string) (restore func() error, err error) {
	_ = server
	return func() error { return nil }, nil
}

func DisableSystemProxy() (restore func() error, err error) {
	return func() error { return nil }, nil
}
