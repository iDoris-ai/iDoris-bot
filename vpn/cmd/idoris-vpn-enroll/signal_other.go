//go:build !unix

package main

import "os"

func notifyReload(chan<- os.Signal) {}
