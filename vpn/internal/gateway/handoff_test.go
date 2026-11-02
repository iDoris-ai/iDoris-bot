package gateway

import (
	"strings"
	"testing"
)

func TestR4WPlanHandoffOwner(t *testing.T) {
	base := PlanHandoff{Regular: true, Mode: 0o600, UID: 1000, Root: true, SudoUID: "1000"}
	if err := CheckPlanHandoff(base); err != nil {
		t.Fatal(err)
	}
	rootOwned := base
	rootOwned.UID = 0
	rootOwned.SudoUID = ""
	if err := CheckPlanHandoff(rootOwned); err != nil {
		t.Fatal(err)
	}
	foreign := base
	foreign.UID = 1001
	if err := CheckPlanHandoff(foreign); err == nil || !strings.Contains(err.Error(), "uid 1001") {
		t.Fatalf("foreign owner: %v", err)
	}
	notRoot := base
	notRoot.Root = false
	if err := CheckPlanHandoff(notRoot); err == nil {
		t.Fatal("SUDO_UID was honoured for a non-root process")
	}
	wide := base
	wide.Mode = 0o666
	if err := CheckPlanHandoff(wide); err == nil || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("mode: %v", err)
	}
	link := base
	link.Symlink = true
	link.Regular = false
	if err := CheckPlanHandoff(link); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink: %v", err)
	}
	looseDir := base
	looseDir.DirWritable = true
	if err := CheckPlanHandoff(looseDir); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("directory: %v", err)
	}
}
