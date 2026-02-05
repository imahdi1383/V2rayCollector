package collector

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestParseShareLinksToBeans(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		link string
		want any
	}{
		{
			name: "trojan",
			link: "trojan://telegram-id-privatevpns@51.44.32.14:22222?security=tls&sni=trojan.burgerip.co.uk&alpn=http/1.1&allowInsecure=1&type=tcp#@Vip_Security%20join%20us%20-%20454",
			want: NekoRayTrojanBean{
				V:    0,
				Addr: "51.44.32.14",
				Name: "@Vip_Security join us - 454",
				Pass: "telegram-id-privatevpns",
				Port: 22222,
				Stream: NekoRayStream{
					ALPN:     "http/1.1",
					EdLen:    0,
					Insecure: true,
					MuxS:     0,
					Net:      "tcp",
					Sec:      "tls",
					Sni:      "trojan.burgerip.co.uk",
				},
			},
		},
		{
			name: "shadowsocks",
			link: "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTprMXY1ZzlGZWZkb08=@57.129.140.88:8388#[%F0%9F%8F%81]t.me/ConfigsHub",
			want: NekoRayShadowsocksBean{
				V:      0,
				Addr:   "57.129.140.88",
				Method: "chacha20-ietf-poly1305",
				Name:   "[🏁]t.me/ConfigsHub",
				Pass:   "k1v5g9FefdoO",
				Port:   8388,
				Stream: NekoRayStream{EdLen: 0, Insecure: false, MuxS: 0, Net: "tcp"},
				UOT:    0,
			},
		},
		{
			name: "vless",
			link: "vless://96d9bcb0-9ad2-48be-85a2-a9ab3a005261@8.6.112.0:2083?security=tls&sni=ds1-mx-fn154-protection.iranlease.com&allowInsecure=1&type=ws&path=/?ed%3D2560&host=ds1-mx-fn154-protection.iranlease.com&encryption=none#@Vip_Security%20join%20us%20-%20547",
			want: NekoRayVlessBean{
				V:    0,
				Addr: "8.6.112.0",
				Name: "@Vip_Security join us - 547",
				Pass: "96d9bcb0-9ad2-48be-85a2-a9ab3a005261",
				Port: 2083,
				Stream: NekoRayStream{
					EdLen:    0,
					Host:     "ds1-mx-fn154-protection.iranlease.com",
					Insecure: true,
					MuxS:     0,
					Net:      "ws",
					Path:     "/?ed=2560",
					Sec:      "tls",
					Sni:      "ds1-mx-fn154-protection.iranlease.com",
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			bean, _, err := parseShareLinkToNekoRayBean(tt.link)
			if err != nil {
				t.Fatalf("parseShareLinkToNekoRayBean error: %v", err)
			}

			gotJSON, _ := json.Marshal(bean)
			wantJSON, _ := json.Marshal(tt.want)
			if string(gotJSON) != string(wantJSON) {
				t.Fatalf("bean mismatch\n got: %s\nwant: %s", gotJSON, wantJSON)
			}
		})
	}
}

func TestParseVmessLink(t *testing.T) {
	t.Parallel()

	vmessPayload := map[string]any{
		"v":    "2",
		"ps":   "My Node",
		"add":  "1.2.3.4",
		"port": "443",
		"id":   "11111111-2222-3333-4444-555555555555",
		"aid":  "0",
		"scy":  "auto",
		"net":  "ws",
		"type": "none",
		"host": "example.com",
		"path": "/ws",
		"tls":  "tls",
		"sni":  "example.com",
		"alpn": "h2",
	}
	raw, _ := json.Marshal(vmessPayload)
	encoded := base64.RawStdEncoding.EncodeToString(raw)
	link := "vmess://" + encoded

	bean, err := parseVmessLink(link)
	if err != nil {
		t.Fatalf("parseVmessLink error: %v", err)
	}

	if bean.Addr != "1.2.3.4" || bean.Port != 443 || bean.Pass != "11111111-2222-3333-4444-555555555555" {
		t.Fatalf("unexpected base fields: %+v", bean)
	}
	if bean.AlterID != 0 || bean.Security != "auto" {
		t.Fatalf("unexpected vmess fields: %+v", bean)
	}
	if bean.Stream.Net != "ws" || bean.Stream.Sec != "tls" || bean.Stream.Host != "example.com" || bean.Stream.Path != "/ws" || bean.Stream.ALPN != "h2" {
		t.Fatalf("unexpected stream fields: %+v", bean.Stream)
	}
}

func TestExportMixedToNekoRayProfiles_DedupAndID(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	profilesDir := filepath.Join(tmp, "profiles")
	if err := os.MkdirAll(profilesDir, 0755); err != nil {
		t.Fatal(err)
	}

	// existing profile id=2 so next should be 3
	existing := NekoRayProfile{
		Bean: NekoRayVlessBean{
			V:    0,
			Addr: "8.6.112.0",
			Name: "existing",
			Pass: "96d9bcb0-9ad2-48be-85a2-a9ab3a005261",
			Port: 2083,
			Stream: NekoRayStream{
				EdLen:    0,
				Host:     "ds1-mx-fn154-protection.iranlease.com",
				Insecure: true,
				MuxS:     0,
				Net:      "ws",
				Path:     "/?ed=2560",
				Sec:      "tls",
				Sni:      "ds1-mx-fn154-protection.iranlease.com",
			},
		},
		Gid:     0,
		Id:      2,
		Traffic: NekoRayTraffic{Dl: 0, Ul: 0},
		Type:    "vless",
		Yc:      0,
	}
	existingBytes, _ := json.MarshalIndent(existing, "", "    ")
	existingBytes = append(existingBytes, '\n')
	if err := os.WriteFile(filepath.Join(profilesDir, "2.json"), existingBytes, 0644); err != nil {
		t.Fatal(err)
	}

	// mixed contains one duplicate + one new
	mixed := filepath.Join(tmp, "mixed_iran.txt")
	dup := "vless://96d9bcb0-9ad2-48be-85a2-a9ab3a005261@8.6.112.0:2083?security=tls&sni=ds1-mx-fn154-protection.iranlease.com&allowInsecure=1&type=ws&path=/?ed%3D2560&host=ds1-mx-fn154-protection.iranlease.com&encryption=none#dup\n"
	newNode := "trojan://pass@1.1.1.1:443?security=tls&sni=example.com&allowInsecure=1&type=tcp#new\n"
	if err := os.WriteFile(mixed, []byte(dup+newNode), 0644); err != nil {
		t.Fatal(err)
	}

	addedIDs, skipped, err := ExportMixedToNekoRayProfiles(mixed, profilesDir, 0)
	if err != nil {
		t.Fatalf("ExportMixedToNekoRayProfiles error: %v", err)
	}
	if len(addedIDs) != 1 || skipped != 1 {
		t.Fatalf("unexpected counts: added=%d skipped=%d", len(addedIDs), skipped)
	}

	if _, err := os.Stat(filepath.Join(profilesDir, "3.json")); err != nil {
		t.Fatalf("expected new profile 3.json: %v", err)
	}
}
