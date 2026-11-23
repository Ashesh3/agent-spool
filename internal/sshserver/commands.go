package sshserver

import (
	"context"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"spool/internal/relay"
)

const (
	managementCommands = usageError("spool commands: create, list, pubkey")
	inboxCommands      = usageError("inbox commands: put, send, poll, get, delete")
	sendUsage          = usageError("usage: send <recipient> [--attach <id>]... [--reply-to <message_id>] [--encoding plain|age]")
	pollUsage          = usageError("usage: poll [--since <cursor>] [--limit <1..100>]")
)

// OpenSSH sends a single string, not argv. There is no shell, quoting,
// expansion or escaping. put's entire remainder is the literal filename.
func (s *session) run(ctx context.Context, line string) error {
	if !utf8.ValidString(line) || strings.ContainsFunc(line, func(r rune) bool { return r != '\t' && unicode.IsControl(r) }) {
		return usageError("command must be a single UTF-8 line")
	}
	line = strings.TrimLeft(line, " \t")
	verb, rest := line, ""
	if i := strings.IndexAny(line, " \t"); i >= 0 {
		verb, rest = line[:i], line[i+1:]
	}
	if s.user != "spool" && verb == "put" {
		if len(rest) == 0 {
			return usageError("usage: put <basename>")
		}
		return s.result(s.app.Put(ctx, s.owner, s.user, rest, s.ch))
	}
	args := strings.FieldsFunc(rest, func(r rune) bool { return r == ' ' || r == '\t' })
	if s.user == "spool" {
		return s.manage(ctx, verb, args)
	}
	switch verb {
	case "send":
		opts, err := sendOptions(args)
		if err != nil {
			return err
		}
		return s.result(s.app.Send(ctx, s.owner, s.user, opts, s.ch))
	case "poll":
		since, limit, err := pollOptions(args)
		if err != nil {
			return err
		}
		return s.app.Poll(ctx, s.owner, s.user, since, limit, s.ch)
	case "get":
		if len(args) != 1 || !operand(args[0]) {
			return usageError("usage: get <attachment_id>")
		}
		return s.app.Get(ctx, s.owner, s.user, args[0], s.ch)
	case "delete":
		if len(args) != 1 || !messageID(args[0]) {
			return usageError("usage: delete <message_id>")
		}
		err := s.app.Delete(ctx, s.owner, s.user, args[0])
		return s.result(struct {
			Deleted string `json:"deleted"`
		}{args[0]}, err)
	default:
		return inboxCommands
	}
}

func (s *session) manage(ctx context.Context, verb string, args []string) error {
	switch verb {
	case "create":
		var key string
		switch {
		case len(args) == 0:
		case len(args) == 2 && args[0] == "--public-key" && operand(args[1]):
			key = args[1]
		default:
			return usageError("usage: create [--public-key <age recipient>]")
		}
		return s.result(s.app.Create(ctx, s.owner, key))
	case "list":
		if len(args) != 0 {
			return usageError("usage: list")
		}
		inboxes, err := s.app.List(ctx, s.owner)
		if inboxes == nil {
			inboxes = []relay.Inbox{}
		}
		return s.result(struct {
			Inboxes []relay.Inbox `json:"inboxes"`
		}{inboxes}, err)
	case "pubkey":
		if len(args) != 1 || !operand(args[0]) {
			return usageError("usage: pubkey <recipient>")
		}
		key, err := s.app.PublicKey(ctx, args[0])
		return s.result(struct {
			PublicKey string `json:"public_key"`
		}{key}, err)
	default:
		return managementCommands
	}
}

func operand(s string) bool { return len(s) > 0 && s[0] != '-' }

func decimal(s string) (int64, bool) {
	if len(s) == 0 || s[0] < '0' || s[0] > '9' {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	return n, err == nil
}

func messageID(s string) bool {
	n, ok := decimal(s)
	return ok && n > 0
}

func sendOptions(args []string) (relay.SendOptions, error) {
	var opts relay.SendOptions
	if len(args)%2 != 1 || !operand(args[0]) {
		return opts, sendUsage
	}
	opts.To = args[0]
	for i := 1; i < len(args); i += 2 {
		flag, value := args[i], args[i+1]
		if !operand(value) {
			return opts, sendUsage
		}
		switch flag {
		case "--attach":
			opts.Attachments = append(opts.Attachments, value)
		case "--reply-to":
			if opts.ReplyTo != "" || !messageID(value) {
				return opts, sendUsage
			}
			opts.ReplyTo = value
		case "--encoding":
			if opts.Encoding != "" || (value != "plain" && value != "age") {
				return opts, sendUsage
			}
			opts.Encoding = value
		default:
			return opts, sendUsage
		}
	}
	if opts.Encoding == "" {
		opts.Encoding = "plain"
	}
	return opts, nil
}

func pollOptions(args []string) (int64, int, error) {
	var since int64
	limit := 50
	var hasSince, hasLimit bool
	if len(args)%2 != 0 {
		return 0, 0, pollUsage
	}
	for i := 0; i < len(args); i += 2 {
		n, ok := decimal(args[i+1])
		if !ok {
			return 0, 0, pollUsage
		}
		switch args[i] {
		case "--since":
			if hasSince {
				return 0, 0, pollUsage
			}
			hasSince, since = true, n
		case "--limit":
			if hasLimit || n < 1 || n > 100 {
				return 0, 0, pollUsage
			}
			hasLimit, limit = true, int(n)
		default:
			return 0, 0, pollUsage
		}
	}
	return since, limit, nil
}
