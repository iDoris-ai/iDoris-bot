package gateway

import (
	"path/filepath"
	"testing"
)

func TestPathsForDefaultKeepsHistoricalNames(t *testing.T) {
	home := filepath.Join(string(filepath.Separator), "h")
	for _, cfg := range []string{"", filepath.Join(home, ".idoris", "vpn.json")} {
		p := PathsFor(home, cfg)
		if p.Token != filepath.Join(home, ".idoris", "enroll.token") || p.Plan != filepath.Join(home, ".idoris", "gateway-plan.json") {
			t.Fatalf("cfg %q: %+v", cfg, p)
		}
	}
}

func TestPathsForScopesTokenAndPlanToTheConfig(t *testing.T) {
	home := filepath.Join(string(filepath.Separator), "h")
	a := PathsFor(home, filepath.Join(home, "orgA", "vpn.json"))
	b := PathsFor(home, filepath.Join(home, "orgB", "vpn.json"))
	c := PathsFor(home, filepath.Join(home, "orgA", "other.json"))
	if a.Token == b.Token || a.Token == c.Token || a.Plan == b.Plan || a.Plan == c.Plan {
		t.Fatalf("paths collide: %+v %+v %+v", a, b, c)
	}
	if a.Token == PathsFor(home, "").Token {
		t.Fatal("a non-default config must not reuse the default token file")
	}
	if filepath.Dir(a.Token) != filepath.Dir(a.Config) {
		t.Fatalf("token should sit next to its config: %+v", a)
	}
}
