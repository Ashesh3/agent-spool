// Command spool-relay serves a spool mailbox domain over SSH.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"spool/internal/relay"
	"spool/internal/sshserver"

	"golang.org/x/crypto/ssh"
)

const usage = "spool-relay [serve] [--json]"

func main() {
	args := os.Args[1:]
	asJSON := slices.Contains(args, "--json")
	args = slices.DeleteFunc(args, func(s string) bool { return s == "--json" })
	if err := run(args, asJSON); err != nil {
		if asJSON {
			_ = json.NewEncoder(os.Stderr).Encode(map[string]string{"error": err.Error()})
		} else {
			fmt.Fprintln(os.Stderr, err)
		}
		os.Exit(1)
	}
}

func run(args []string, asJSON bool) error {
	command := "serve"
	if len(args) > 1 {
		return errors.New(usage)
	}
	if len(args) == 1 {
		command = args[0]
	}
	switch command {
	case "help", "--help", "-h":
		if asJSON {
			return json.NewEncoder(os.Stdout).Encode(map[string]string{"usage": usage})
		}
		fmt.Println(usage)
		return nil
	case "serve":
		s, err := loadSettings()
		if err != nil {
			return err
		}
		return serve(s, asJSON)
	default:
		return errors.New(usage)
	}
}

func serve(s settings, asJSON bool) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	app, err := relay.Open(s.Config)
	if err != nil {
		return err
	}
	defer app.Close()
	hostKey, err := loadHostKey(s.DataDir, s.hostKeyFile)
	if err != nil {
		return fmt.Errorf("host key: %w", err)
	}
	if err := app.Sweep(ctx); err != nil {
		return fmt.Errorf("startup sweep: %w", err)
	}
	emit := func(event, detail string) {
		if asJSON {
			_ = json.NewEncoder(os.Stderr).Encode(map[string]string{"event": event, "detail": detail})
		} else {
			log.Printf("%s: %s", event, detail)
		}
	}
	listener, err := net.Listen("tcp", s.listen)
	if err != nil {
		return err
	}
	emit("host_key", strings.TrimSpace(string(ssh.MarshalAuthorizedKey(hostKey.PublicKey()))))
	emit("host_fingerprint", ssh.FingerprintSHA256(hostKey.PublicKey()))
	emit("listening", listener.Addr().String())

	sweepCtx, cancel := context.WithCancel(ctx)
	swept := make(chan struct{})
	go func() {
		defer close(swept)
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := app.Sweep(sweepCtx); err != nil && sweepCtx.Err() == nil {
					emit("cleanup error", err.Error())
				}
			case <-sweepCtx.Done():
				return
			}
		}
	}()
	err = sshserver.Serve(ctx, listener, app, hostKey, s.allowed)
	cancel()
	<-swept
	if ctx.Err() != nil && errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}
