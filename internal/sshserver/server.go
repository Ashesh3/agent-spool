// Package sshserver exposes the mailbox as an SSH exec application. It does
// not invoke programs, read the operating system's accounts, or open tunnels.
package sshserver

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"spool/internal/relay"
)

const (
	maxConnections = 64
	maxHandshakes  = 16
	maxSessions    = 4 // per authenticated connection
	handshakeTime  = 15 * time.Second
	connectionTime = 10 * time.Minute
	ownerExtension = "spool-owner"
	inboxExtension = "spool-inbox-key"
)

// closeOnDone interrupts even a connection blocked in a pre-authentication
// read. The returned function closes on early return and joins any callback.
func closeOnDone(ctx context.Context, c io.Closer) func() {
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		c.Close()
		close(done)
	})
	return func() {
		if stop() {
			c.Close()
		} else {
			<-done
		}
	}
}

// Serve owns ln and its connections. It returns nil on context cancellation
// only after all sessions have stopped using app. allowed is read-only.
func Serve(ctx context.Context, ln net.Listener, app *relay.Relay, hostKey ssh.Signer, allowed map[string]bool) error {
	ctx, cancel := context.WithCancel(ctx)
	closeListener := closeOnDone(ctx, ln)
	var workers sync.WaitGroup
	defer func() {
		cancel()
		closeListener()
		workers.Wait()
	}()
	if app == nil || hostKey == nil || len(allowed) == 0 {
		return errors.New("SSH server requires a mailbox, host key and public key allowlist")
	}
	algs := ssh.SupportedAlgorithms()
	base := ssh.ServerConfig{
		Config:                  ssh.Config{KeyExchanges: algs.KeyExchanges, Ciphers: algs.Ciphers, MACs: algs.MACs},
		PublicKeyAuthAlgorithms: algs.PublicKeyAuths,
	}
	base.AddHostKey(hostKey)
	connections := make(chan struct{}, maxConnections)
	handshakes := make(chan struct{}, maxHandshakes)
	for {
		raw, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case connections <- struct{}{}:
		default:
			raw.Close()
			continue
		}
		select {
		case handshakes <- struct{}{}:
		default:
			<-connections
			raw.Close()
			continue
		}
		workers.Go(func() {
			defer func() { <-connections }()
			serveConnection(ctx, raw, &base, allowed, app, handshakes)
		})
	}
}

func handshake(ctx context.Context, raw net.Conn, base *ssh.ServerConfig, allowed map[string]bool, app *relay.Relay) (*ssh.ServerConn, <-chan ssh.NewChannel, <-chan *ssh.Request, error) {
	ctx, cancel := context.WithTimeout(ctx, handshakeTime)
	defer cancel()
	deadline, _ := ctx.Deadline()
	if err := raw.SetDeadline(deadline); err != nil {
		return nil, nil, nil, err
	}
	cfg := *base
	cfg.PublicKeyCallback = func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		denied := errors.New("authentication denied")
		if _, cert := key.(*ssh.Certificate); cert {
			return nil, denied
		}
		owner := ssh.FingerprintSHA256(key)
		if !allowed[owner] {
			return nil, denied
		}
		var inbox relay.InboxKey
		if meta.User() != relay.ManagementUser {
			var err error
			inbox, err = app.ResolveInbox(ctx, owner, meta.User())
			if err != nil {
				return nil, denied
			}
		}
		// This callback may be an unsigned probe. Do not charge or otherwise
		// mutate state. NewServerConn returns only the verified key's permissions.
		return &ssh.Permissions{Extensions: map[string]string{ownerExtension: owner, inboxExtension: string(inbox)}}, nil
	}
	return ssh.NewServerConn(raw, &cfg)
}

func serveConnection(ctx context.Context, raw net.Conn, base *ssh.ServerConfig, allowed map[string]bool, app *relay.Relay, handshakes <-chan struct{}) {
	ctx, cancel := context.WithTimeout(ctx, connectionTime)
	closeSocket := closeOnDone(ctx, raw)
	defer func() { cancel(); closeSocket() }()
	conn, channels, globals, err := handshake(ctx, raw, base, allowed, app)
	<-handshakes
	if err != nil {
		return
	}
	// The context closes the socket at its hard lifetime even when the peer
	// stops reading stdout, leaves an upload unfinished, or never sends exec.
	if err := raw.SetDeadline(time.Time{}); err != nil {
		return
	}
	owner := conn.Permissions.Extensions[ownerExtension]
	inbox := relay.InboxKey(conn.Permissions.Extensions[inboxExtension])
	if conn.User() != relay.ManagementUser && inbox == "" {
		return
	}
	var workers sync.WaitGroup
	workers.Go(func() { ssh.DiscardRequests(globals) })
	slots := make(chan struct{}, maxSessions)
	for next := range channels {
		if next.ChannelType() != "session" || len(next.ExtraData()) != 0 {
			next.Reject(ssh.Prohibited, "only session channels are supported")
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			next.Reject(ssh.ResourceShortage, "too many open sessions")
			continue
		}
		ch, reqs, err := next.Accept()
		if err != nil {
			<-slots
			continue
		}
		s := session{app: app, owner: owner, inbox: inbox, ch: ch}
		workers.Go(func() {
			defer func() { <-slots }()
			s.serve(ctx, reqs)
		})
	}
	cancel()
	workers.Wait()
}
