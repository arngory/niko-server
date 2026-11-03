//go:build linux

// niko-server is the data plane of a raycontrol node (arngory/niko
// docs/server/SPEC.md):
//
//	niko-server front   -c front.json      # multiplexers (R1: DNS on UDP 53)
//	niko-server backend -c backend.json    # one protocol (R1: dnstt, masterdns)
//	niko-server check   -c FILE [--json]   # validate without running
//
// Exit codes: 0 fine, 1 the config is wrong, 2 the environment failed (sockets,
// files, the protocol stopped).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/arngory/niko-server/nikoserver"
)

var version = "dev"

const (
	exitOK     = 0
	exitConfig = 1
	exitEnv    = 2
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(exitConfig)
	}
	command := os.Args[1]
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	configPath := flags.String("c", "", "config file")
	jsonOutput := flags.Bool("json", false, "check: errors as JSON")
	switch command {
	case "version", "--version", "-v":
		fmt.Println("niko-server", version)
		return
	case "keygen":
		// test and manual setups; raycontrol makes the node's keys itself
		if len(os.Args) != 3 || os.Args[2] != "dnstt" {
			fmt.Fprintln(os.Stderr, "usage: niko-server keygen dnstt")
			os.Exit(exitConfig)
		}
		private, public, err := nikoserver.DNSTTKeypair()
		if err != nil {
			fmt.Fprintln(os.Stderr, "niko-server:", err)
			os.Exit(exitEnv)
		}
		fmt.Printf("private %s\npublic %s\n", private, public)
		return
	case "front", "backend", "check":
	default:
		usage()
		os.Exit(exitConfig)
	}
	if err := flags.Parse(os.Args[2:]); err != nil || *configPath == "" {
		usage()
		os.Exit(exitConfig)
	}
	config, configErrors, err := nikoserver.Load(*configPath)
	if command == "check" {
		os.Exit(check(err, configErrors, *jsonOutput))
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "niko-server:", err)
		os.Exit(exitEnv)
	}
	if len(configErrors) > 0 {
		for _, e := range configErrors {
			fmt.Fprintln(os.Stderr, "niko-server: config:", e.Error())
		}
		os.Exit(exitConfig)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	switch c := config.(type) {
	case *nikoserver.FrontConfig:
		if command != "front" {
			fmt.Fprintln(os.Stderr, "niko-server: this is a front config, run: niko-server front")
			os.Exit(exitConfig)
		}
		log := nikoserver.NewLogger(c.Log.Level, nil)
		watchHUP(log, "the front has no users or keys: change routes with a restart")
		err = nikoserver.RunFront(ctx, c, log)
	case *nikoserver.BackendConfig:
		if command != "backend" {
			fmt.Fprintln(os.Stderr, "niko-server: this is a backend config, run: niko-server backend")
			os.Exit(exitConfig)
		}
		log := nikoserver.NewLogger(c.Log.Level, nil)
		watchHUP(log, "the "+c.Kind+" backend has no users: a new key takes a restart")
		err = nikoserver.RunBackend(ctx, c, log)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "niko-server:", err)
		os.Exit(exitEnv)
	}
}

// watchHUP answers SIGHUP. The DNS tunnels keep no per-user state to reload.
func watchHUP(log *nikoserver.Logger, note string) {
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			log.Infof("SIGHUP: nothing to reload (%s)", note)
		}
	}()
}

func check(err error, configErrors []nikoserver.ConfigError, asJSON bool) int {
	code := exitOK
	if err != nil {
		code = exitEnv
		configErrors = append(configErrors, nikoserver.ConfigError{Path: "", Err: err.Error()})
	} else if len(configErrors) > 0 {
		code = exitConfig
	}
	if asJSON {
		if configErrors == nil {
			configErrors = []nikoserver.ConfigError{}
		}
		json.NewEncoder(os.Stdout).Encode(configErrors)
		return code
	}
	for _, e := range configErrors {
		fmt.Fprintln(os.Stderr, e.Error())
	}
	if code == exitOK {
		fmt.Println("ok")
	}
	return code
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: niko-server front|backend|check -c FILE [--json]   (niko-server version)")
}
