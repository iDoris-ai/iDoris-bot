package gateway

import (
	"path/filepath"
	"strings"
)

// Paths are the files one enrollment identity owns. They are derived from the
// config file so two configs never share a token or a plan.
type Paths struct {
	Config string
	Token  string
	Plan   string
}

// DefaultConfigName is the config file the wizard and the web UI use when the
// operator gives none.
const DefaultConfigName = "vpn.json"

// PathsFor returns the paths for configPath. An empty configPath, or a config
// whose path is <dir>/.idoris/vpn.json (including the default under home),
// keeps the historical plan name gateway-plan.json. Its token follows the
// same <filename>.enroll-token rule as every other config, so the default
// file is vpn.json.enroll-token. enroll.token is the legacy shared name and
// is not claimed. Any other config owns sidecars named from the whole file
// name, extension included, so office.json and office.conf do not share a
// token or a plan: office.json.enroll-token and office.json.gateway-plan.json.
func PathsFor(home, configPath string) Paths {
	base := filepath.Join(home, ".idoris")
	def := filepath.Join(base, DefaultConfigName)
	configPath = strings.TrimSpace(configPath)
	cleaned := ""
	if configPath != "" {
		cleaned = filepath.Clean(configPath)
	}
	if configPath == "" || cleaned == filepath.Clean(def) || historicalDefaultConfig(cleaned) {
		dir := base
		cfg := def
		if historicalDefaultConfig(cleaned) {
			dir = filepath.Dir(cleaned)
			cfg = cleaned
		}
		return Paths{
			Config: cfg,
			Token:  filepath.Join(dir, DefaultConfigName+".enroll-token"),
			Plan:   filepath.Join(dir, "gateway-plan.json"),
		}
	}
	name := filepath.Base(cleaned)
	if name == "" || name == "." || name == string(filepath.Separator) {
		name = "config"
	}
	return Paths{
		Config: cleaned,
		Token:  filepath.Join(filepath.Dir(cleaned), name+".enroll-token"),
		Plan:   filepath.Join(filepath.Dir(cleaned), name+".gateway-plan.json"),
	}
}

// historicalDefaultConfig reports a path that is the historical default config
// even when home is not available to compare against.
func historicalDefaultConfig(cleaned string) bool {
	return cleaned != "" && filepath.Base(cleaned) == DefaultConfigName && filepath.Base(filepath.Dir(cleaned)) == ".idoris"
}
