// Command wire-relay serves one private wire address domain.
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"syscall"
	"time"

	"wire/internal/relay"
)

const usage = "wire-relay [serve|keygen] [--json]"

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
	case "keygen":
		var buf [32]byte
		rand.Read(buf[:])
		key := "gk_" + hex.EncodeToString(buf[:])
		if asJSON {
			return json.NewEncoder(os.Stdout).Encode(map[string]string{"gate_key": key})
		}
		_, err := fmt.Fprintln(os.Stdout, key)
		return err
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
	app, err := relay.Open(s.Config)
	if err != nil {
		return err
	}
	defer app.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := app.Sweep(ctx); err != nil {
		return fmt.Errorf("startup sweep: %w", err)
	}
	server := &http.Server{
		Addr: s.listen, Handler: app,
		TLSConfig:                    &tls.Config{MinVersion: tls.VersionTLS12},
		DisableGeneralOptionsHandler: true, // OPTIONS * must pass through the gate, too.
		ReadHeaderTimeout:            10 * time.Second, ReadTimeout: 5 * time.Minute,
		WriteTimeout: 5 * time.Minute, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10,
	}
	emit := func(event, detail string) {
		if asJSON {
			_ = json.NewEncoder(os.Stderr).Encode(map[string]string{"event": event, "detail": detail})
		} else {
			log.Printf("%s: %s", event, detail)
		}
	}
	// Load the certificate and acquire the port before reporting readiness.
	cert, err := tls.LoadX509KeyPair(s.cert, s.key)
	if err != nil {
		return fmt.Errorf("load TLS certificate: %w", err)
	}
	server.TLSConfig.Certificates = []tls.Certificate{cert}
	listener, err := tls.Listen("tcp", s.listen, server.TLSConfig)
	if err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	emit("listening", listener.Addr().String())
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case err := <-done:
			return err
		case <-ticker.C:
			if err := app.Sweep(ctx); err != nil && ctx.Err() == nil {
				emit("cleanup error", err.Error())
			}
		case <-ctx.Done():
			shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := server.Shutdown(shutdown); err != nil {
				_ = server.Close()
				return err
			}
			return nil
		}
	}
}
