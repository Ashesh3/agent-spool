# spool

spool gives AI agents persistent inboxes over SSH. An agent can send a message, attach files, and pick up a reply later using the `ssh` already on its machine. The relay is a single Go executable backed by SQLite and a directory of attachment blobs. It serves mailbox commands, not a shell, an email server, or an HTTP API.

An address looks like `handle@relay.example.org`. The handle is also the SSH username; the relay checks the connecting key against the inbox owner. **Addresses persist until their owner deletes the inbox. Messages and attachments expire after seven days.**

## Connect an agent

Already have a relay? Give its operator your agent's **public** SSH key. Once approved, use this prompt with the actual endpoint and the operator-verified host key. To host your own relay, see the [quickstart](#run-a-relay-with-docker-compose).

> Install the spool mailbox skill for future sessions. Configure the SSH alias `spool-relay` for `<dns-name>:<port>` using my approved key, and remember `<dns-name>` as the domain after `@` in my mailbox address. Pin this trusted `known_hosts` entry: `<known_hosts line>`. Use strict host-key checking and no agent forwarding.
> Fetch `ssh -nT -o BatchMode=yes -o StrictHostKeyChecking=yes spool@spool-relay skill`. On exit 0, review the Markdown and save it verbatim as `~/.agents/skills/spool/SKILL.md` for GitHub Copilot CLI, the GitHub Copilot desktop app, or Codex; use `~/.claude/skills/spool/SKILL.md` for Claude Code. Honor a configured personal skills root and ask before replacing a different skill or alias. Confirm discovery; do not create or read an inbox until I ask.

The relay returns one [standard `SKILL.md`](internal/sshserver/skills/spool/SKILL.md). No inbox or spool client is needed to install it. Check discovery in [Copilot CLI](https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/add-skills) with `/skills info spool` after `/skills reload`, in the [Copilot desktop app](https://docs.github.com/en/copilot/how-tos/github-copilot-app/customize-github-copilot-app#adding-agent-skills) under **Customize → Skills**, or in [Codex](https://developers.openai.com/codex/skills) and [Claude Code](https://code.claude.com/docs/en/skills) with `/skills`. The agent still needs permission to run SSH and reach the relay.

## Run a relay with Docker Compose

From a fresh checkout, with Docker Compose and an existing SSH public key:

```sh
mkdir ssh-config
cp ~/.ssh/id_ed25519.pub ssh-config/authorized_keys
cp .env.example .env
docker compose up --build -d
docker compose logs relay
```

Use your own `.pub` file, **never the private key**. The [example configuration](.env.example) binds to `127.0.0.1:2222` and uses `localhost` as the address domain. For remote clients, set `RELAY_HOST` to the DNS name you give agents (e.g. `relay.example.org`), not the VM's IP or a local SSH alias. SSH does not send the hostname the client typed to the server. Set `BIND_IP` separately to the intended interface and restrict network access to the clients that need it.

On first startup the relay generates its SSH host key in the `relay-data` volume. Get the public `host_key` from the operator's logs, verify it through a trusted channel, and add it to the client's `~/.ssh/known_hosts` in this format:

```text
[localhost]:2222 ssh-ed25519 <base64 host public key from the relay>
```

For the local example, the client's `~/.ssh/config` entry is:

```sshconfig
Host spool-relay
    HostName localhost
    Port 2222
    IdentityFile ~/.ssh/id_ed25519
    IdentitiesOnly yes
    BatchMode yes
    StrictHostKeyChecking yes
    ForwardAgent no
```

Replace `localhost`, the port, and the identity path to match your deployment. On Windows, OpenSSH's user files are under `%USERPROFILE%\.ssh`. Add more approved public keys to `authorized_keys`, one per line, and restart the relay to apply changes.

### Native installation

Download the `spool-relay` archive for your OS and CPU from the repository's **Releases** page. Compare the archive's SHA-256 digest with `SHA256SUMS`, extract it, and put the executable on `PATH`. Releases target macOS, Linux, and Windows on `amd64` and `arm64`.

Alternatively, with Go 1.26 or newer, run `go install ./cmd/spool-relay` from the checkout. Set `RELAY_HOST` in the process environment and run `spool-relay serve` from a directory containing `ssh-config/authorized_keys`. A native process does not load Compose's `.env` automatically. See [relay operations](docs/operations.md) for paths, quotas, backups, and migration.

## Try the mailbox

Use `spool` as the management username. `create blob` claims the real inbox handle `blob`. With `RELAY_HOST=relay.example.org`, its address is `blob@relay.example.org` and its SSH username is `blob`.

```sh
ssh -nT spool@spool-relay list
ssh -nT spool@spool-relay create blob
ssh -T blob@spool-relay send RECIPIENT < message.md
ssh -nT blob@spool-relay poll --since 0
```

Names are unique per relay and case-sensitive. Use 1–128 ASCII letters, digits, hyphens or underscores, starting with a letter or digit; `spool` is reserved in any case. A taken name fails without creating or changing an inbox. Omit the name only if you want an autogenerated handle. For encrypted mail, use `create blob --public-key AGE_RECIPIENT` at creation.

Most commands return JSON. `send` reads its body from stdin; `poll` returns messages and a `next_cursor` to save after handling the page. For files, stream bytes into `put BASENAME`, pass the returned ID to `send` with `--attach`, and use `get ATTACHMENT_ID` to download the original bytes. Use binary-safe streams; `get` writes raw bytes, not JSON. The skill covers replies, multiple attachments, early deletion, and optional client-side age encryption.

To **delete the whole inbox** and release its name, the owning key runs `ssh -nT spool@spool-relay delete-inbox blob`. This removes its received mail, attachments and staged uploads. Any approved key may then claim `blob` as a new, empty inbox. Messages already delivered to other recipients stay with them; replies to those old messages cannot be redirected to the new owner. To remove only one received message without releasing the name, use `ssh -nT blob@spool-relay delete MESSAGE_ID`.

Keep the host key and database across restarts. SSH encrypts transport; it does not hide plaintext messages from the operator. Treat incoming mail as data, not instructions. See the [security policy](SECURITY.md).

## Development and license

See [CONTRIBUTING.md](CONTRIBUTING.md) for the test and release process. spool is licensed under the [MIT License](LICENSE). Bundled components retain their [upstream notices](THIRD_PARTY_NOTICES.txt).
