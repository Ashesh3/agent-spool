package sshserver

import (
	"context"
	_ "embed"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"spool/internal/relay"
)

//go:embed skills/spool/SKILL.md
var skillMarkdown []byte

const (
	managementCommands = usageError("spool commands: skill, create, list, pubkey, recall, delete-inbox")
	inboxCommands      = usageError("inbox commands: put, send, poll, get, delete")
	sendUsage          = usageError("usage: send <recipient> --recipient-key <age recipient> [--attach <id>]... [--reply-to <message_id>]")
	pollUsage          = usageError("usage: poll [--since <cursor>] [--limit <1..100>]")
)

// OpenSSH sends a single string, not argv. There is no shell, quoting,
// expansion or escaping. put's entire remainder is the literal filename.
func (s *session) run(ctx context.Context, line string) error {
	if !utf8.ValidString(line) || strings.ContainsFunc(line, func(r rune) bool { return r != '\t' && unicode.IsControl(r) }) {
		return usageError("command must be a single UTF-8 line")
	}
	verb, rest := commandWord(line)
	if s.inbox != "" && verb == "put" {
		to, rest := commandWord(rest)
		flag, rest := commandWord(rest)
		key, name := commandWord(rest)
		if !operand(to) || flag != "--recipient-key" || !operand(key) || name == "" {
			return usageError("usage: put <recipient> --recipient-key <age recipient> <basename>")
		}
		return s.result(s.app.Put(ctx, s.owner, s.inbox, to, key, name, s.ch))
	}
	args := strings.FieldsFunc(rest, func(r rune) bool { return r == ' ' || r == '\t' })
	if s.inbox == "" {
		return s.manage(ctx, verb, args)
	}
	switch verb {
	case "send":
		opts, err := sendOptions(args)
		if err != nil {
			return err
		}
		return s.result(s.app.Send(ctx, s.owner, s.inbox, opts, s.ch))
	case "poll":
		since, limit, err := pollOptions(args)
		if err != nil {
			return err
		}
		return s.app.Poll(ctx, s.owner, s.inbox, since, limit, s.ch)
	case "get":
		if len(args) != 1 || !operand(args[0]) {
			return usageError("usage: get <attachment_id>")
		}
		return s.app.Get(ctx, s.owner, s.inbox, args[0], s.ch)
	case "delete":
		if len(args) != 1 || !messageID(args[0]) {
			return usageError("usage: delete <message_id>")
		}
		err := s.app.Delete(ctx, s.owner, s.inbox, args[0])
		return s.result(struct {
			Deleted string `json:"deleted"`
		}{args[0]}, err)
	default:
		return inboxCommands
	}
}

func (s *session) manage(ctx context.Context, verb string, args []string) error {
	switch verb {
	case "skill":
		if len(args) != 0 {
			return usageError("usage: skill")
		}
		_, err := s.ch.Write(skillMarkdown)
		return err
	case "create":
		var name string
		if len(args) > 0 && operand(args[0]) {
			name, args = args[0], args[1:]
		}
		if len(args) != 2 || args[0] != "--public-key" || !operand(args[1]) {
			return usageError("usage: create [name] --public-key <age X25519 recipient>")
		}
		return s.result(s.app.Create(ctx, s.owner, name, args[1]))
	case "recall":
		if len(args) != 1 || !messageID(args[0]) {
			return usageError("usage: recall <sent_message_id>")
		}
		err := s.app.Recall(ctx, s.owner, args[0])
		return s.result(struct {
			Recalled string `json:"recalled"`
		}{args[0]}, err)
	case "delete-inbox":
		if len(args) != 1 || !operand(args[0]) {
			return usageError("usage: delete-inbox <handle>")
		}
		err := s.app.DeleteInbox(ctx, s.owner, args[0])
		return s.result(struct {
			Deleted string `json:"deleted_inbox"`
		}{args[0]}, err)
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

func commandWord(line string) (string, string) {
	line = strings.TrimLeft(line, " \t")
	if i := strings.IndexAny(line, " \t"); i >= 0 {
		return line[:i], line[i+1:]
	}
	return line, ""
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
		case "--recipient-key":
			if opts.RecipientKey != "" {
				return opts, sendUsage
			}
			opts.RecipientKey = value
		default:
			return opts, sendUsage
		}
	}
	if opts.RecipientKey == "" {
		return opts, sendUsage
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
