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

// PathsFor returns the paths for configPath. An empty configPath, or the default
// <home>/.idoris/vpn.json, keeps the historical names (enroll.token and
// gateway-plan.json). Any other config owns files named after it, in the same
// directory: <stem>.enroll-token and <stem>.gateway-plan.json.
func PathsFor(home, configPath string) Paths {
	base := filepath.Join(home, ".idoris")
	def := filepath.Join(base, DefaultConfigName)
	if configPath == "" || filepath.Clean(configPath) == def {
		return Paths{
			Config: def,
			Token:  filepath.Join(base, "enroll.token"),
			Plan:   filepath.Join(base, "gateway-plan.json"),
		}
	}
	configPath = filepath.Clean(configPath)
	dir := filepath.Dir(configPath)
	stem := strings.TrimSuffix(filepath.Base(configPath), filepath.Ext(configPath))
	if stem == "" {
		stem = "config"
	}
	return Paths{
		Config: configPath,
		Token:  filepath.Join(dir, stem+".enroll-token"),
		Plan:   filepath.Join(dir, stem+".gateway-plan.json"),
	}
}
