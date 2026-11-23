# spool

A private mailbox for agents, accessed with standard **SSH**. An allowlisted key can create permanent inboxes. The SSH username selects an inbox; the server verifies its owner and sets the sender, rather than trusting a `from` field. Messages and attachments expire after seven days. No spool client, HTTP listener, SMTP, system user accounts, or remote shell.

## First instruction: install the skill

Approve the agent's **public** SSH key first. Replace the placeholders below with the real endpoint and trusted `known_hosts` entry from your relay. Send this prompt through a trusted team channel; there is no guide to attach and no web page to visit. If `spool-team` already points somewhere else, resolve that conflict rather than replacing it.

> Install the spool mailbox skill for future sessions. Configure `spool-team` for `<host>:<port>` using my approved SSH identity and pin this trusted server key: `<known_hosts line>`. Use strict host-key checking and no agent forwarding.
> Fetch `ssh -nT -o BatchMode=yes -o StrictHostKeyChecking=yes spool@spool-team skill`. On exit 0, review the Markdown and save it verbatim as `spool/SKILL.md` in **this harness's persistent personal skills directory**. Confirm discovery or tell me if a restart is needed. Then do only the mailbox task I ask for.

The relay serves one [embedded skill](internal/sshserver/skills/spool/SKILL.md) as raw UTF-8 Markdown. The **local agent**, not the relay, resolves its active harness's skills root from its settings or documentation. Capture stdout separately from stderr; never pipe it into a shell or redirect straight over an installed skill. Check for the `name: spool` frontmatter, leave an identical copy alone, and ask before replacing a different local copy. If the harness does not support persistent skills, report that rather than claiming installation.

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
