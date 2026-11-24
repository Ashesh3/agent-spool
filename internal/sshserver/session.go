package sshserver

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"sync"

	"golang.org/x/crypto/ssh"
	"spool/internal/relay"
)

type session struct {
	app   *relay.Relay
	owner string         // verified signing key fingerprint, never an exec argument
	inbox relay.InboxKey // pinned at authentication; empty for the management login
	ch    ssh.Channel
}

type usageError string

func (e usageError) Error() string { return string(e) }

func (s *session) serve(ctx context.Context, requests <-chan *ssh.Request) {
	ctx, cancel := context.WithCancel(ctx)
	var worker sync.WaitGroup
	started := false
	// Keep draining requests even while stdin or stdout is blocked, and hold
	// the session slot until the peer acknowledges CHANNEL_CLOSE. Otherwise
	// extra requests can stall the SSH mux or unclosed channels can accumulate.
	for req := range requests {
		if req.Type != "exec" || started {
			req.Reply(false, nil)
			continue
		}
		started = true
		allowed := s.app.Allow(s.owner)
		// RFC 4254 §6.5: exactly one SSH string; never accept a length mismatch
		// or trailing bytes as an alternative encoding of the same command.
		p := req.Payload
		if len(p) < 4 || binary.BigEndian.Uint32(p[:4]) != uint32(len(p)-4) {
			req.Reply(false, nil)
			s.ch.Close()
			continue
		}
		if err := req.Reply(true, nil); err != nil {
			s.ch.Close()
			continue
		}
		worker.Go(func() {
			var err error
			switch {
			case !allowed:
				err = relay.RequestError("request rate limit exceeded")
			case len(p)-4 > 8192:
				err = usageError("command is too long")
			default:
				err = s.run(ctx, string(p[4:]))
			}
			s.finish(err)
		})
	}
	cancel()
	worker.Wait()
}

func (s *session) result(value any, err error) error {
	if err != nil {
		return err
	}
	return json.NewEncoder(s.ch).Encode(value)
}

func (s *session) finish(err error) {
	var status uint32
	if err != nil {
		status = 1
		message := "internal mailbox error"
		var usage usageError
		var request relay.RequestError
		switch {
		case errors.As(err, &usage):
			status, message = 2, usage.Error()
		case errors.As(err, &request):
			message = request.Error()
		}
		json.NewEncoder(s.ch.Stderr()).Encode(struct {
			Error string `json:"error"`
		}{message})
	}
	s.ch.CloseWrite()
	var payload [4]byte
	binary.BigEndian.PutUint32(payload[:], status)
	s.ch.SendRequest("exit-status", false, payload[:])
	s.ch.Close()
}
