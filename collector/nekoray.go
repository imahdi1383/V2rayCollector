package collector

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type NekoRayProfile struct {
	Bean    any            `json:"bean"`
	Gid     int            `json:"gid"`
	Id      int            `json:"id"`
	Traffic NekoRayTraffic `json:"traffic"`
	Type    string         `json:"type"`
	Yc      int            `json:"yc"`
}

type NekoRayTraffic struct {
	Dl int `json:"dl"`
	Ul int `json:"ul"`
}

type NekoRayStream struct {
	ALPN        string `json:"alpn,omitempty"`
	EdLen       int    `json:"ed_len"`
	Host        string `json:"host,omitempty"`
	Insecure    bool   `json:"insecure"`
	MuxS        int    `json:"mux_s"`
	Net         string `json:"net"`
	Path        string `json:"path,omitempty"`
	Sec         string `json:"sec,omitempty"`
	ServiceName string `json:"service_name,omitempty"`
	Sni         string `json:"sni,omitempty"`
}

type NekoRayTrojanBean struct {
	V      int           `json:"_v"`
	Addr   string        `json:"addr"`
	Name   string        `json:"name"`
	Pass   string        `json:"pass"`
	Port   int           `json:"port"`
	Stream NekoRayStream `json:"stream"`
}

type NekoRayVlessBean struct {
	V      int           `json:"_v"`
	Addr   string        `json:"addr"`
	Name   string        `json:"name"`
	Pass   string        `json:"pass"`
	Port   int           `json:"port"`
	Stream NekoRayStream `json:"stream"`
}

type NekoRayShadowsocksBean struct {
	V      int           `json:"_v"`
	Addr   string        `json:"addr"`
	Method string        `json:"method"`
	Name   string        `json:"name"`
	Pass   string        `json:"pass"`
	Port   int           `json:"port"`
	Stream NekoRayStream `json:"stream"`
	UOT    int           `json:"uot"`
}

type NekoRayVmessBean struct {
	V        int           `json:"_v"`
	Addr     string        `json:"addr"`
	AlterID  int           `json:"alter_id"`
	Name     string        `json:"name"`
	Pass     string        `json:"pass"`
	Port     int           `json:"port"`
	Security string        `json:"security"`
	Stream   NekoRayStream `json:"stream"`
}

type rawProfileFile struct {
	Type string          `json:"type"`
	ID   int             `json:"id"`
	Bean json.RawMessage `json:"bean"`
}

func FindNekoRayProfilesDir(repoRoot string) (string, error) {
	if repoRoot == "" {
		return "", errors.New("repoRoot is empty")
	}

	// Common layout when users drop the portable folder next to this repo:
	// nekoray-*/nekoray/config/profiles
	pattern := filepath.Join(repoRoot, "nekoray*", "nekoray", "config", "profiles")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return "", err
	}
	sort.Strings(matches)
	for _, dir := range matches {
		if stat, err := os.Stat(dir); err == nil && stat.IsDir() {
			return dir, nil
		}
	}
	return "", nil
}

func ExportMixedToNekoRayProfiles(mixedFilePath string, profilesDir string, groupID int) (added int, skipped int, err error) {
	if mixedFilePath == "" {
		return 0, 0, errors.New("mixedFilePath is empty")
	}

	if profilesDir == "" {
		repoRoot, err := os.Getwd()
		if err != nil {
			return 0, 0, err
		}
		profilesDir, err = FindNekoRayProfilesDir(repoRoot)
		if err != nil {
			return 0, 0, err
		}
	}

	if profilesDir == "" {
		return 0, 0, nil
	}

	if stat, statErr := os.Stat(profilesDir); statErr != nil || !stat.IsDir() {
		return 0, 0, fmt.Errorf("nekoray profiles dir not found: %s", profilesDir)
	}

	existingKeys, nextID, err := loadExistingNekoRayProfileKeys(profilesDir)
	if err != nil {
		return 0, 0, err
	}

	content, err := os.ReadFile(mixedFilePath)
	if err != nil {
		return 0, 0, err
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		node, key, parseErr := parseShareLinkToNekoRayBean(line)
		if parseErr != nil {
			// Ignore unknown/invalid lines in mixed files.
			continue
		}
		if existingKeys[key] {
			skipped++
			continue
		}

		profile := NekoRayProfile{
			Bean: node,
			Gid:  groupID,
			Id:   nextID,
			Traffic: NekoRayTraffic{
				Dl: 0,
				Ul: 0,
			},
			Type: profileTypeFromBean(node),
			Yc:   0,
		}

		outPath := filepath.Join(profilesDir, fmt.Sprintf("%d.json", nextID))
		data, err := json.MarshalIndent(profile, "", "    ")
		if err != nil {
			return added, skipped, err
		}
		data = append(data, '\n')
		if err := os.WriteFile(outPath, data, 0644); err != nil {
			return added, skipped, err
		}

		existingKeys[key] = true
		nextID++
		added++
	}

	return added, skipped, nil
}

func profileTypeFromBean(bean any) string {
	switch bean.(type) {
	case NekoRayVlessBean:
		return "vless"
	case NekoRayTrojanBean:
		return "trojan"
	case NekoRayShadowsocksBean:
		return "shadowsocks"
	case NekoRayVmessBean:
		return "vmess"
	default:
		return ""
	}
}

func loadExistingNekoRayProfileKeys(profilesDir string) (map[string]bool, int, error) {
	keys := make(map[string]bool)
	maxID := -1

	matches, err := filepath.Glob(filepath.Join(profilesDir, "*.json"))
	if err != nil {
		return nil, 0, err
	}

	for _, p := range matches {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var raw rawProfileFile
		if err := json.Unmarshal(b, &raw); err != nil {
			continue
		}
		if raw.ID > maxID {
			maxID = raw.ID
		}
		k, err := keyFromRawProfile(raw)
		if err != nil {
			continue
		}
		keys[k] = true
	}

	return keys, maxID + 1, nil
}

func keyFromRawProfile(raw rawProfileFile) (string, error) {
	switch raw.Type {
	case "vless":
		var bean NekoRayVlessBean
		if err := json.Unmarshal(raw.Bean, &bean); err != nil {
			return "", err
		}
		return keyForVless(bean), nil
	case "trojan":
		var bean NekoRayTrojanBean
		if err := json.Unmarshal(raw.Bean, &bean); err != nil {
			return "", err
		}
		return keyForTrojan(bean), nil
	case "shadowsocks":
		var bean NekoRayShadowsocksBean
		if err := json.Unmarshal(raw.Bean, &bean); err != nil {
			return "", err
		}
		return keyForShadowsocks(bean), nil
	case "vmess":
		var bean NekoRayVmessBean
		if err := json.Unmarshal(raw.Bean, &bean); err != nil {
			return "", err
		}
		return keyForVmess(bean), nil
	default:
		return "", fmt.Errorf("unsupported profile type: %s", raw.Type)
	}
}

func parseShareLinkToNekoRayBean(link string) (any, string, error) {
	link = strings.TrimSpace(link)
	switch {
	case strings.HasPrefix(link, "vless://"):
		bean, err := parseVlessLink(link)
		if err != nil {
			return nil, "", err
		}
		return bean, keyForVless(bean), nil
	case strings.HasPrefix(link, "trojan://"):
		bean, err := parseTrojanLink(link)
		if err != nil {
			return nil, "", err
		}
		return bean, keyForTrojan(bean), nil
	case strings.HasPrefix(link, "ss://"):
		bean, err := parseShadowsocksLink(link)
		if err != nil {
			return nil, "", err
		}
		return bean, keyForShadowsocks(bean), nil
	case strings.HasPrefix(link, "vmess://"):
		bean, err := parseVmessLink(link)
		if err != nil {
			return nil, "", err
		}
		return bean, keyForVmess(bean), nil
	default:
		return nil, "", fmt.Errorf("unsupported link scheme")
	}
}

func parseVlessLink(link string) (NekoRayVlessBean, error) {
	base, name := splitLinkName(link)
	u, err := url.Parse(base)
	if err != nil {
		return NekoRayVlessBean{}, err
	}
	if u.User == nil {
		return NekoRayVlessBean{}, errors.New("missing user info")
	}

	pass := u.User.Username()
	addr := u.Hostname()
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return NekoRayVlessBean{}, fmt.Errorf("invalid port: %w", err)
	}

	q := u.Query()

	stream := NekoRayStream{
		EdLen:    0,
		Insecure: parseBool(q.Get("allowInsecure"), q.Get("allow_insecure"), q.Get("insecure")),
		MuxS:     0,
		Net:      firstNonEmpty(q.Get("type"), q.Get("network"), "tcp"),
		Path:     q.Get("path"),
		Sec:      q.Get("security"),
		Sni:      firstNonEmpty(q.Get("sni"), q.Get("serverName"), q.Get("servername"), q.Get("peer")),
		Host:     q.Get("host"),
	}
	stream.ServiceName = firstNonEmpty(q.Get("serviceName"), q.Get("service_name"))

	return NekoRayVlessBean{
		V:      0,
		Addr:   addr,
		Name:   name,
		Pass:   pass,
		Port:   port,
		Stream: stream,
	}, nil
}

func parseTrojanLink(link string) (NekoRayTrojanBean, error) {
	base, name := splitLinkName(link)
	u, err := url.Parse(base)
	if err != nil {
		return NekoRayTrojanBean{}, err
	}
	if u.User == nil {
		return NekoRayTrojanBean{}, errors.New("missing user info")
	}

	pass := u.User.Username()
	addr := u.Hostname()
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return NekoRayTrojanBean{}, fmt.Errorf("invalid port: %w", err)
	}

	q := u.Query()

	stream := NekoRayStream{
		ALPN:     q.Get("alpn"),
		EdLen:    0,
		Insecure: parseBool(q.Get("allowInsecure"), q.Get("allow_insecure"), q.Get("insecure")),
		MuxS:     0,
		Net:      firstNonEmpty(q.Get("type"), q.Get("network"), "tcp"),
		Sec:      q.Get("security"),
		Sni:      firstNonEmpty(q.Get("sni"), q.Get("serverName"), q.Get("servername"), q.Get("peer")),
		Host:     q.Get("host"),
		Path:     q.Get("path"),
	}
	stream.ServiceName = firstNonEmpty(q.Get("serviceName"), q.Get("service_name"))

	return NekoRayTrojanBean{
		V:      0,
		Addr:   addr,
		Name:   name,
		Pass:   pass,
		Port:   port,
		Stream: stream,
	}, nil
}

func parseShadowsocksLink(link string) (NekoRayShadowsocksBean, error) {
	base, name := splitLinkName(link)
	raw := strings.TrimPrefix(base, "ss://")

	at := strings.LastIndex(raw, "@")
	if at == -1 {
		return NekoRayShadowsocksBean{}, errors.New("invalid ss link: missing @")
	}
	credsPart := raw[:at]
	hostPart := raw[at+1:]

	hostOnly := hostPart
	if qIdx := strings.Index(hostOnly, "?"); qIdx != -1 {
		hostOnly = hostOnly[:qIdx]
	}

	hostURL, err := url.Parse("http://" + hostOnly)
	if err != nil {
		return NekoRayShadowsocksBean{}, err
	}
	addr := hostURL.Hostname()
	port, err := strconv.Atoi(hostURL.Port())
	if err != nil {
		return NekoRayShadowsocksBean{}, fmt.Errorf("invalid port: %w", err)
	}

	method, password, err := parseShadowsocksCreds(credsPart, hostOnly)
	if err != nil {
		return NekoRayShadowsocksBean{}, err
	}

	stream := NekoRayStream{
		EdLen:    0,
		Insecure: false,
		MuxS:     0,
		Net:      "tcp",
	}

	return NekoRayShadowsocksBean{
		V:      0,
		Addr:   addr,
		Method: method,
		Name:   name,
		Pass:   password,
		Port:   port,
		Stream: stream,
		UOT:    0,
	}, nil
}

func parseShadowsocksCreds(credsPart string, hostOnly string) (string, string, error) {
	// SIP002 supports multiple formats; NekoRay accepts common ones.
	// Try base64 first.
	if decodedBytes, err := decodeBase64Any(credsPart); err == nil {
		decoded := strings.TrimSpace(string(decodedBytes))

		// Some variants include "@host:port" inside the decoded string.
		if strings.Contains(decoded, "@") {
			left, _, ok := strings.Cut(decoded, "@")
			if ok {
				decoded = left
			}
		}

		method, pass, ok := strings.Cut(decoded, ":")
		if !ok {
			return "", "", errors.New("invalid ss creds: missing ':'")
		}
		return method, pass, nil
	}

	// Fallback: non-base64 "method:password".
	unescaped, _ := url.PathUnescape(credsPart)
	method, pass, ok := strings.Cut(unescaped, ":")
	if !ok {
		return "", "", errors.New("invalid ss creds")
	}
	_ = hostOnly
	return method, pass, nil
}

func parseVmessLink(link string) (NekoRayVmessBean, error) {
	raw := strings.TrimSpace(strings.TrimPrefix(link, "vmess://"))
	if raw == "" {
		return NekoRayVmessBean{}, errors.New("empty vmess payload")
	}
	decodedBytes, err := decodeBase64Any(raw)
	if err != nil {
		return NekoRayVmessBean{}, err
	}

	var data map[string]any
	if err := json.Unmarshal(decodedBytes, &data); err != nil {
		return NekoRayVmessBean{}, err
	}

	addr := anyToString(data["add"])
	port := anyToInt(data["port"])
	pass := anyToString(data["id"])
	name := strings.TrimSpace(anyToString(data["ps"]))
	alterID := anyToInt(data["aid"])
	security := anyToString(data["scy"])
	if security == "" {
		security = "auto"
	}

	netType := anyToString(data["net"])
	host := anyToString(data["host"])
	path := anyToString(data["path"])
	tls := anyToString(data["tls"])
	sni := anyToString(data["sni"])
	alpn := anyToString(data["alpn"])

	stream := NekoRayStream{
		ALPN:     alpn,
		EdLen:    0,
		Host:     host,
		Insecure: parseBool(anyToString(data["allowInsecure"]), anyToString(data["allow_insecure"]), anyToString(data["insecure"])),
		MuxS:     0,
		Net:      firstNonEmpty(netType, "tcp"),
		Path:     path,
		Sec:      normalizeVmessTLS(tls),
		Sni:      sni,
	}

	return NekoRayVmessBean{
		V:        0,
		Addr:     addr,
		AlterID:  alterID,
		Name:     name,
		Pass:     pass,
		Port:     port,
		Security: security,
		Stream:   stream,
	}, nil
}

func normalizeVmessTLS(tlsField string) string {
	tlsField = strings.TrimSpace(strings.ToLower(tlsField))
	if tlsField == "" || tlsField == "none" {
		return ""
	}
	// common vmess share links use "tls" here.
	return tlsField
}

func splitLinkName(link string) (base string, name string) {
	base, frag, ok := strings.Cut(link, "#")
	if !ok {
		return strings.TrimSpace(link), ""
	}

	base = strings.TrimSpace(base)
	name = strings.TrimSpace(frag)
	if unescaped, err := url.PathUnescape(name); err == nil {
		name = strings.TrimSpace(unescaped)
	}
	return base, name
}

func parseBool(values ...string) bool {
	for _, v := range values {
		v = strings.TrimSpace(strings.ToLower(v))
		if v == "" {
			continue
		}
		if v == "1" || v == "true" || v == "yes" {
			return true
		}
		if v == "0" || v == "false" || v == "no" {
			return false
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func decodeBase64Any(input string) ([]byte, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil, errors.New("empty base64 input")
	}

	if b, err := base64.RawStdEncoding.DecodeString(input); err == nil {
		return b, nil
	}
	if b, err := base64.RawURLEncoding.DecodeString(input); err == nil {
		return b, nil
	}

	padded := input
	if m := len(padded) % 4; m != 0 {
		padded += strings.Repeat("=", 4-m)
	}
	if b, err := base64.StdEncoding.DecodeString(padded); err == nil {
		return b, nil
	}
	if b, err := base64.URLEncoding.DecodeString(padded); err == nil {
		return b, nil
	}

	return nil, errors.New("invalid base64")
}

func anyToString(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case json.Number:
		return t.String()
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		return fmt.Sprint(v)
	}
}

func anyToInt(v any) int {
	switch t := v.(type) {
	case nil:
		return 0
	case float64:
		return int(t)
	case json.Number:
		i, _ := t.Int64()
		return int(i)
	case string:
		i, _ := strconv.Atoi(strings.TrimSpace(t))
		return i
	default:
		i, _ := strconv.Atoi(anyToString(v))
		return i
	}
}

func keyForVless(bean NekoRayVlessBean) string {
	type k struct {
		Addr        string `json:"addr"`
		Port        int    `json:"port"`
		Pass        string `json:"pass"`
		Net         string `json:"net"`
		Sec         string `json:"sec"`
		Sni         string `json:"sni"`
		Host        string `json:"host"`
		Path        string `json:"path"`
		ServiceName string `json:"service_name"`
		Insecure    bool   `json:"insecure"`
	}
	payload, _ := json.Marshal(k{
		Addr:        bean.Addr,
		Port:        bean.Port,
		Pass:        bean.Pass,
		Net:         bean.Stream.Net,
		Sec:         bean.Stream.Sec,
		Sni:         bean.Stream.Sni,
		Host:        bean.Stream.Host,
		Path:        bean.Stream.Path,
		ServiceName: bean.Stream.ServiceName,
		Insecure:    bean.Stream.Insecure,
	})
	return "vless:" + sha256Hex(payload)
}

func keyForTrojan(bean NekoRayTrojanBean) string {
	type k struct {
		Addr        string `json:"addr"`
		Port        int    `json:"port"`
		Pass        string `json:"pass"`
		Net         string `json:"net"`
		Sec         string `json:"sec"`
		Sni         string `json:"sni"`
		ALPN        string `json:"alpn"`
		Host        string `json:"host"`
		Path        string `json:"path"`
		ServiceName string `json:"service_name"`
		Insecure    bool   `json:"insecure"`
	}
	payload, _ := json.Marshal(k{
		Addr:        bean.Addr,
		Port:        bean.Port,
		Pass:        bean.Pass,
		Net:         bean.Stream.Net,
		Sec:         bean.Stream.Sec,
		Sni:         bean.Stream.Sni,
		ALPN:        bean.Stream.ALPN,
		Host:        bean.Stream.Host,
		Path:        bean.Stream.Path,
		ServiceName: bean.Stream.ServiceName,
		Insecure:    bean.Stream.Insecure,
	})
	return "trojan:" + sha256Hex(payload)
}

func keyForShadowsocks(bean NekoRayShadowsocksBean) string {
	type k struct {
		Addr   string `json:"addr"`
		Port   int    `json:"port"`
		Method string `json:"method"`
		Pass   string `json:"pass"`
	}
	payload, _ := json.Marshal(k{
		Addr:   bean.Addr,
		Port:   bean.Port,
		Method: bean.Method,
		Pass:   bean.Pass,
	})
	return "shadowsocks:" + sha256Hex(payload)
}

func keyForVmess(bean NekoRayVmessBean) string {
	type k struct {
		Addr        string `json:"addr"`
		Port        int    `json:"port"`
		Pass        string `json:"pass"`
		AlterID     int    `json:"alter_id"`
		Security    string `json:"security"`
		Net         string `json:"net"`
		Sec         string `json:"sec"`
		Sni         string `json:"sni"`
		ALPN        string `json:"alpn"`
		Host        string `json:"host"`
		Path        string `json:"path"`
		ServiceName string `json:"service_name"`
		Insecure    bool   `json:"insecure"`
	}
	payload, _ := json.Marshal(k{
		Addr:        bean.Addr,
		Port:        bean.Port,
		Pass:        bean.Pass,
		AlterID:     bean.AlterID,
		Security:    bean.Security,
		Net:         bean.Stream.Net,
		Sec:         bean.Stream.Sec,
		Sni:         bean.Stream.Sni,
		ALPN:        bean.Stream.ALPN,
		Host:        bean.Stream.Host,
		Path:        bean.Stream.Path,
		ServiceName: bean.Stream.ServiceName,
		Insecure:    bean.Stream.Insecure,
	})
	return "vmess:" + sha256Hex(payload)
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
