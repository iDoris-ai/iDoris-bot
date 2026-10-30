//go:build unix

package main

import (
	"errors"
	"os"
)

func requireRoot() error {
	if os.Geteuid() != 0 {
		return errors.New("service install --system must run as root; re-run with sudo")
	}
	return nil
}
