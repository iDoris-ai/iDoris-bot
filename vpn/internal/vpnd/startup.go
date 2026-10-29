package vpnd

import (
	"errors"
	"fmt"
	"strings"
)

// EnrollUnreachableWarning is shown while startup discovery failed and the
// daemon is continuing with a previously trusted or pinned control URL.
// Enrollment is contacted again only when a login is actually required.
const EnrollUnreachableWarning = "enrollment service is unreachable; continuing with the saved control URL and the existing node identity. A new login is attempted only when this node actually needs one"

// ResolveStartupControl picks the control URL to run with.
//
// discoveredOK means /v1/discover returned a URL. A pinned URL that does not
// match that discovery is refused. When discovery failed, a saved URL is used
// only if config does not pin a different one. degraded is true when the URL
// was not confirmed by discovery on this start. The caller persists the URL
// only after a successful discovery.
func ResolveStartupControl(pinned, discovered, saved string, discoveredOK bool) (url string, degraded bool, err error) {
	pinned = strings.TrimSpace(pinned)
	discovered = strings.TrimSpace(discovered)
	saved = strings.TrimSpace(saved)
	if discoveredOK {
		if discovered == "" {
			return "", false, errors.New("enrollment discovery returned an empty control url")
		}
		if pinned != "" && !SameControlURL(pinned, discovered) {
			return "", false, fmt.Errorf("enrollment service points at %s but config pins %s; refusing", discovered, pinned)
		}
		if pinned != "" {
			return pinned, false, nil
		}
		return discovered, false, nil
	}
	if pinned != "" && saved != "" && !SameControlURL(pinned, saved) {
		return "", false, fmt.Errorf("enrollment service is unreachable and config pins %s which differs from the saved control URL %s; refusing", pinned, saved)
	}
	if pinned != "" {
		return pinned, true, nil
	}
	if saved != "" {
		return saved, true, nil
	}
	return "", false, errors.New("enrollment service is unreachable and no control URL is pinned or saved")
}

// RoleWhileEnrollDown keeps the identity that was bound at the last successful
// discovery. An empty or unknown saved role leaves the configured role alone.
func RoleWhileEnrollDown(configRole, savedRole string) string {
	savedRole = strings.ToLower(strings.TrimSpace(savedRole))
	if savedRole == "" || !ValidRole(savedRole) {
		return configRole
	}
	return savedRole
}
