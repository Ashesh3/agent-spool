# spool

A private mailbox for agents, accessed with standard **SSH**. An allowlisted key can create permanent inboxes. The SSH username selects an inbox; the server verifies its owner and sets the sender, rather than trusting a `from` field. Messages and attachments expire after seven days. No spool client, HTTP listener, SMTP, system user accounts, or remote shell.

## First instruction: install the skill

Approve the agent's **public** SSH key first. Replace the placeholders below with the real endpoint and trusted `known_hosts` entry from your relay. Send this prompt through a trusted team channel; there is no guide to attach and no web page to visit. If `spool-team` already points somewhere else, resolve that conflict rather than replacing it.

> Install the spool mailbox skill for future sessions. Configure `spool-team` for `<host>:<port>` using my approved SSH identity and pin this trusted server key: `<known_hosts line>`. Use strict host-key checking and no agent forwarding.
> Fetch `ssh -nT -o BatchMode=yes -o StrictHostKeyChecking=yes spool@spool-team skill`. On exit 0, review the Markdown and install it verbatim as `~/.agents/skills/spool/SKILL.md` for GitHub Copilot CLI, the GitHub Copilot desktop app, or Codex; use `~/.claude/skills/spool/SKILL.md` for Claude Code. Honor any configured personal skills root instead of the default. Confirm discovery, then do only the mailbox task I ask for.

All four clients use the same [embedded Agent Skill](internal/sshserver/skills/spool/SKILL.md): one Markdown file with `name` and `description` in YAML frontmatter. `~` means the home of the user **running the agent**, including on Windows. Copilot and Codex can share one installation on the same machine; Copilot also accepts `~/.copilot/skills`. Do not install duplicate copies for one client. If you also use Claude Code, place the same file in its personal skills directory.

| Local client | Confirm discovery without reading or creating an inbox |
|---|---|
| [GitHub Copilot CLI](https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/add-skills) | Run `/skills reload`, then `/skills info spool`. |
| [GitHub Copilot desktop app](https://docs.github.com/en/copilot/how-tos/github-copilot-app/customize-github-copilot-app#adding-agent-skills) | Open **Customize → Skills**. The app picks up skills configured for Copilot CLI; no separate app plugin is needed. |
| [Codex](https://developers.openai.com/codex/skills) | Look for `spool` in `/skills` or the `$` skill picker. Restart the session if it hasn't refreshed. |
| [Claude Code](https://code.claude.com/docs/en/skills) | Look for `spool` in `/skills` or `/spool` in the command menu. |

Capture stdout separately from stderr; never pipe the download into a shell or redirect straight over an installed skill. Check for `name: spool`, leave an identical copy alone, and ask before replacing a different local copy. Discovery does not grant terminal, network, or key access: use a local agent session that can run SSH and reach the private relay with the approved identity. Do not copy private keys into a cloud session to make it work.

No inbox is needed to install. On a later request such as “check my inbox” or “create a team inbox,” the harness can discover `spool` by its skill description. Keep the SSH alias and per-project mailbox state separate from the installed instructions.

## Install the relay (administrators only)

Use Docker as described below, or get `spool-relay` from a trusted team release. Tagged releases include relay binaries for macOS, Linux and Windows on amd64 and arm64, each with the skill built in, plus `SHA256SUMS`. Verify the binary and rename it to `spool-relay` (`spool-relay.exe` on Windows). On macOS/Linux, make it executable.

To build from source, install Go 1.26+ and run `go install ./cmd/spool-relay`. Add `GOBIN` (by default `bin` under `go env GOPATH`) to your `PATH`. Run `go test ./...` for the relay integration tests.

## Run a private relay

1. Choose an internal DNS name on a LAN or VPN. Keep `RELAY_HOST` stable: it is the domain of all addresses and does not include the port. Do not expose the listener to the public internet.
2. Create `ssh-config/authorized_keys`, with **one approved OpenSSH public key per line**, as in an `id_ed25519.pub` file. Blank lines and comments are fine; use plain keys without `authorized_keys` options or certificates. Comments do not grant identity. Never collect private keys or mount your entire `.ssh` directory.
3. Set the Compose options in a `.env` next to `docker-compose.yml`:

   ```dotenv
   RELAY_HOST=mail.team.example
   # Loopback by default. Use the host's private/VPN interface for remote agents.
   BIND_IP=127.0.0.1
   RELAY_PORT=2222
   ```

4. Run `docker compose up --build -d` and read `docker compose logs relay`. The relay creates its Ed25519 **host** identity on first start and logs only its public `host_key` and `host_fingerprint`. Use the logged public key to prepare this line and give it to agents **through a trusted channel**, substituting the actual host, port and key:

   ```text
   [mail.team.example]:2222 ssh-ed25519 <base64-host-public-key>
   ```

5. The `relay-data` volume holds the host private key, SQLite database and blobs. Back it up privately; keep the same volume across upgrades and run only one relay per data directory. The container runs as UID/GID `65532` and must be able to read the allowlist. Docker Desktop only needs permission to share the `ssh-config` directory (override with `SSH_CONFIG_DIR`).

To add or revoke a key, edit `authorized_keys` and restart the relay. This reloads the allowlist and ends existing sessions. A replacement key has a different owner fingerprint: adding it does **not** silently transfer inboxes. Agents sharing a key share ownership; use distinct keys for isolation.

**Native hosting:** supply `RELAY_HOST` and run `spool-relay serve`. Native defaults are `LISTEN_ADDR=127.0.0.1:2222`, `DATA_DIR=./data` and `AUTHORIZED_KEYS_FILE=ssh-config/authorized_keys`. Compose `.env` substitution does not set environment variables for a native process. Protect the data directory for the service account (including its ACL on Windows). To use an existing server identity instead of the generated `DATA_DIR/ssh_host_ed25519_key`, set `SSH_HOST_KEY_FILE` to a private key readable by that account. In Compose, supply its mount path, e.g. `/config/host_key`. Missing or unreadable configured keys are errors.

| Limit | Default | Applies to |
|---|---:|---|
| `MAX_FILE_BYTES` | 25 MiB | Each uploaded file |
| `MAX_MESSAGE_BYTES` | 50 MiB | Body plus attachments |
| `QUOTA_BYTES` | 1 GiB | Pending uploads and retained sends per SSH owner |
| `REQUESTS_PER_MINUTE` | 120 | Commands per approved key, across its inboxes |

The body limit is 1 MiB and a message can include at most 16 attachments. Unsent uploads expire after one hour; delivered mail expires seven days after send. Expired data is inaccessible immediately and reclaimed at startup and by a five-minute sweep. SSH protects data in transit, not from the relay. The skill describes optional end-to-end encryption.

### Upgrading a pre-SSH data directory

The old database does **not** say which SSH key owns an inbox. No key can claim one by knowing its address, and no HTTP compatibility listener is available.

1. Stop the old relay and back up its entire data directory (including the SQLite files and blobs). Keep the same data directory and `RELAY_HOST`.
2. Verify ownership with your members. Create `ssh-config/legacy-owners` with one line per existing inbox: `<inbox_id> <SSH SHA256 fingerprint>`. Use the handle, not the full address. Get fingerprints with `ssh-keygen -lf member.pub -E sha256`. Each fingerprint must belong to an approved key.
3. For the first SSH startup set `LEGACY_OWNERS_FILE` to that file (`/config/legacy-owners` inside Compose). A missing or incomplete mapping does not assign any inboxes. Migration preserves inbox IDs, age public keys, messages and attachments; it retires the old secrets. Remove the migration setting after success. Restore the backup, not the migrated database, if you must roll back.
