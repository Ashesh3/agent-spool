package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

const usage = `dropwire [--json] <command> [options]
  init [--relay HTTPS_URL] [--gate-key KEY] [--label LABEL]
  whoami
  send ADDRESS [-m MESSAGE] [-f FILE]... [--reply-to ID]
  poll [--since ID] [--limit 1..100]
  download ATTACHMENT_ID [-o FILE_OR_DIRECTORY]

Use RELAY_URL and GATE_KEY for first-time setup; DROPWIRE_CONFIG selects a profile.
DROPWIRE_CA_FILE adds a PEM CA bundle to the system roots. --json works on every command.`

type usageError string

func (u usageError) Error() string { return string(u) }

type options struct {
	command, relay, gate, label string
	address, message, replyTo   string
	files                       []string
	since, attachment, output   string
	limit                       int
	json, help                  bool
}

func parse(args []string) (options, error) {
	o := options{relay: os.Getenv("RELAY_URL"), gate: os.Getenv("GATE_KEY"), limit: 50, output: "."}
	var positional []string
	var problem error
	literal := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !literal {
			switch a {
			case "--json":
				o.json = true
				continue
			case "--help", "-h":
				o.help = true
				continue
			case "--":
				literal = true
				continue
			}
		}
		if o.command == "" {
			o.command = a
			continue
		}
		if literal || !strings.HasPrefix(a, "-") {
			positional = append(positional, a)
			continue
		}
		name, value, inline := strings.Cut(a, "=")
		switch o.command + ":" + name {
		case "init:--relay", "init:--gate-key", "init:--label", "send:-m", "send:--message", "send:-f", "send:--file", "send:--reply-to", "poll:--since", "poll:--limit", "download:-o", "download:--output":
		default:
			problem = usageError("unknown option; see --help")
			continue
		}
		if !inline {
			if i+1 == len(args) {
				problem = usageError(name + " requires a value")
				continue
			}
			i++
			value = args[i]
		}
		switch name {
		case "--relay":
			o.relay = value
		case "--gate-key":
			o.gate = value
		case "--label":
			o.label = value
		case "-m", "--message":
			o.message = value
		case "-f", "--file":
			o.files = append(o.files, value)
		case "--reply-to":
			if !decimal(value, false) {
				problem = usageError("--reply-to requires a positive message ID")
			}
			o.replyTo = value
		case "--since":
			if !decimal(value, true) {
				problem = usageError("--since requires a nonnegative decimal cursor")
			}
			o.since = value
		case "--limit":
			n, err := strconv.Atoi(value)
			if err != nil || n < 1 || n > 100 {
				problem = usageError("--limit must be between 1 and 100")
			}
			o.limit = n
		case "-o", "--output":
			o.output = value
		}
	}
	if problem != nil || o.help {
		return o, problem
	}
	switch o.command {
	case "help":
		o.help = true
	case "init", "whoami", "poll":
		if len(positional) != 0 {
			return o, usageError("unexpected positional arguments; see --help")
		}
	case "send":
		if len(positional) != 1 || (o.message == "" && len(o.files) == 0) {
			return o, usageError("send requires one address and a message (-m) or attachment (-f)")
		}
		o.address = positional[0]
	case "download":
		if len(positional) != 1 || !safeID(positional[0]) || o.output == "" {
			return o, usageError("download requires a valid attachment ID and a nonempty destination")
		}
		o.attachment = positional[0]
	default:
		return o, usageError("expected init, whoami, send, poll, or download; see --help")
	}
	return o, nil
}

func decimal(s string, zeroOK bool) bool {
	n, err := strconv.ParseUint(s, 10, 63)
	return err == nil && strconv.FormatUint(n, 10) == s && (n > 0 || zeroOK)
}

func execute(o options, out io.Writer) error {
	if o.help {
		if o.json {
			return json.NewEncoder(out).Encode(map[string]string{"usage": usage})
		}
		_, err := fmt.Fprintln(out, usage)
		return err
	}
	path, err := profilePath()
	if err != nil {
		return err
	}
	// Keep one poll or provisioning transaction in flight per profile, including
	// delivery to stdout. Kernel locks are released even on SIGKILL or a crash.
	if o.command == "init" || o.command == "poll" {
		lock, err := lockProfile(path, o.command == "init")
		if err != nil {
			return err
		}
		defer lock.Close()
	}
	p, err := readProfile(path)
	if o.command == "init" {
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		p, err = provision(path, p, o)
	}
	if errors.Is(err, os.ErrNotExist) && p == nil && o.command != "init" {
		return errors.New("profile not found; run dropwire init first")
	}
	if err != nil {
		return err
	}
	if o.command == "whoami" || o.command == "init" {
		if o.json {
			return json.NewEncoder(out).Encode(map[string]string{"address": p.Address, "inbox_id": p.InboxID, "relay": p.Relay})
		}
		_, err := fmt.Fprintln(out, p.Address)
		return err
	}
	r, err := newRelay(p)
	if err != nil {
		return err
	}
	switch o.command {
	case "send":
		return r.send(o, out)
	case "poll":
		return r.poll(path, o, out)
	default:
		return r.download(o, out)
	}
}

func run(args []string, out, stderr io.Writer) int {
	o, err := parse(args)
	if err == nil {
		err = execute(o, out)
	}
	if err == nil {
		return 0
	}
	if o.json {
		_ = json.NewEncoder(stderr).Encode(map[string]string{"error": err.Error()})
	} else {
		fmt.Fprintln(stderr, "dropwire:", err)
	}
	var usageProblem usageError
	if errors.As(err, &usageProblem) {
		return 2
	}
	return 1
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
