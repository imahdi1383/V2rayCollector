package collector

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestNekoRaySortGroupByYC_UpdatesOrder(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	profilesDir := filepath.Join(tmp, "profiles")
	groupsDir := filepath.Join(tmp, "groups")

	if err := os.MkdirAll(profilesDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(groupsDir, 0755); err != nil {
		t.Fatal(err)
	}

	writeProfile := func(id int, yc int) {
		p := map[string]any{
			"bean":    map[string]any{"_v": 0, "addr": "1.1.1.1", "name": "n", "pass": "p", "port": 1, "stream": map[string]any{"ed_len": 0, "insecure": false, "mux_s": 0, "net": "tcp"}},
			"gid":     0,
			"id":      id,
			"traffic": map[string]any{"dl": 0, "ul": 0},
			"type":    "trojan",
			"yc":      yc,
		}
		b, _ := json.MarshalIndent(p, "", "    ")
		b = append(b, '\n')
		if err := os.WriteFile(filepath.Join(profilesDir, fmt.Sprintf("%d.json", id)), b, 0644); err != nil {
			t.Fatal(err)
		}
	}

	// profiles: id=1 untested (0), id=2 ok (200), id=3 failed (-1)
	writeProfile(1, 0)
	writeProfile(2, 200)
	writeProfile(3, -1)

	group := map[string]any{"id": 0, "name": "Default", "order": []int{1, 2, 3}}
	gb, _ := json.MarshalIndent(group, "", "    ")
	gb = append(gb, '\n')
	if err := os.WriteFile(filepath.Join(groupsDir, "0.json"), gb, 0644); err != nil {
		t.Fatal(err)
	}

	// OnlyIDs doesn't match any profile -> skips testing, but should still sort by existing yc.
	_, _, err := NekoRayURLTestAndSort(NekoRayURLTestOptions{
		ProfilesDir: profilesDir,
		GroupID:     0,
		OnlyIDs:     []int{9999},
		UpdateOrder: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	updated, err := os.ReadFile(filepath.Join(groupsDir, "0.json"))
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(updated, &out); err != nil {
		t.Fatal(err)
	}
	raw, ok := out["order"].([]any)
	if !ok || len(raw) != 3 {
		t.Fatalf("unexpected order: %#v", out["order"])
	}
	got := []int{int(raw[0].(float64)), int(raw[1].(float64)), int(raw[2].(float64))}
	want := []int{2, 1, 3}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected order: got=%v want=%v", got, want)
		}
	}
}
