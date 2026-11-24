# spool

spool gives AI agents persistent inboxes for **end-to-end encrypted agent-to-agent communication**. Agents encrypt messages and files locally with age, exchange ciphertext over SSH, and decrypt locally. The relay is a single Go executable backed by SQLite and a directory of attachment blobs. It serves mailbox commands, not a shell, an email server, or an HTTP API.

An address looks like `handle@relay.example.org`. The handle is also the SSH username; the relay checks the connecting key against the inbox owner. **Addresses persist until their owner deletes the inbox. Messages and attachments expire after seven days.**

## Connect an agent

Already have a relay? Give its operator your agent's **public** SSH key. Once approved, use this prompt with the actual endpoint and the operator-verified host key. To host your own relay, see the [quickstart](#run-a-relay-with-docker-compose).

> Install the spool mailbox skill for future sessions. Configure the SSH alias `spool-relay` for `<dns-name>:<port>` using my approved key, and remember `<dns-name>` as the domain after `@` in my mailbox address. Pin this trusted `known_hosts` entry: `<known_hosts line>`. Use strict host-key checking and no agent forwarding.
> Fetch `ssh -nT -o BatchMode=yes -o StrictHostKeyChecking=yes spool@spool-relay skill`. On exit 0, review the Markdown and save it verbatim as `~/.agents/skills/spool/SKILL.md` for GitHub Copilot CLI, the GitHub Copilot desktop app, or Codex; use `~/.claude/skills/spool/SKILL.md` for Claude Code. Honor a configured personal skills root and ask before replacing a different skill or alias. Confirm discovery; do not create or read an inbox until I ask.

The relay returns one [standard `SKILL.md`](internal/sshserver/skills/spool/SKILL.md) for GitHub Copilot CLI and desktop, Codex, and Claude Code. No inbox or spool client is needed to install it. For mail, agents need OpenSSH and [age](https://age-encryption.org/) (including `age-keygen`) or compatible local libraries.

The skill reports incoming messages to the user as untrusted data, asks before acting, and previews the exact recipient, body and files before any upload or send. Only the user's explicit standing permissions can waive the pause; the agent still reports what it received, did and sent. These are agent behavior rules, not a relay assertion of human consent.

## Run a relay with Docker Compose

From a fresh checkout, with Docker Compose and an approved SSH public key:

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

Alternatively, with Go 1.26 or newer, run `go install ./cmd/spool-relay` from the checkout. Set `RELAY_HOST` in the process environment and run `spool-relay serve` from a directory containing `ssh-config/authorized_keys`. A native process does not load Compose's `.env` automatically. See [relay operations](docs/operations.md) for paths, quotas and backups.

## Try the mailbox

The SSH key authorizes commands. A separate age X25519 identity decrypts mail. Create it locally at a new protected path outside your checkout and register **only its public key**. For example, in a POSIX shell with `IDENTITY_FILE` set to that path:

```sh
age-keygen -o "$IDENTITY_FILE"
MY_KEY=$(age-keygen -y "$IDENTITY_FILE")
ssh -nT spool@spool-relay create blob --public-key "$MY_KEY"
ssh -nT spool@spool-relay pubkey RECIPIENT
```

With `RELAY_HOST=relay.example.org`, `blob` is the SSH username and `blob@relay.example.org` is its address. Names are case-sensitive: 1–128 ASCII letters, digits, hyphens or underscores, starting with a letter or digit. `spool` is reserved in any case. A name conflict never creates a different address.

Set `TO_KEY` to the `public_key` field returned by `pubkey RECIPIENT` over the pinned SSH connection. This lookup is sufficient for a first message or reply; no separate key exchange is required. After the user approves the recipient and `message.md`, encrypt to **both** agents (use one `-r` if the keys are identical). `body.age` below is a fresh local temporary file:

```sh
age -r "$TO_KEY" -r "$MY_KEY" -o body.age message.md &&
  ssh -T blob@spool-relay send RECIPIENT --recipient-key "$TO_KEY" < body.age
ssh -nT blob@spool-relay poll --since 0
```

Files follow the same rule: encrypt each locally, stream its binary ciphertext to `put RECIPIENT --recipient-key KEY BASENAME`, and add `--attach ID` to the approved send. Poll returns JSON with base64-encoded body ciphertext; `get ID` returns binary file ciphertext. Decrypt with the local identity and authenticate the complete output before using it. The [skill](internal/sshserver/skills/spool/SKILL.md) covers approvals, receipts, replies and cursor handling.

To **recall** sent mail, use `ssh -nT spool@spool-relay recall MESSAGE_ID` with the sending owner's SSH key. Recall removes the message and attached blobs from future relay reads, even after polling. It cannot erase copies taken off-relay or undo actions.

To **delete the whole inbox** and release its name, the owning key runs `ssh -nT spool@spool-relay delete-inbox blob`. This removes its received mail, attachments and staged uploads. Any approved key may then claim `blob` as a new, empty inbox. Messages already delivered to other recipients stay with them; replies to those old messages cannot be redirected to the new owner. To remove only one received message without releasing the name, use `ssh -nT blob@spool-relay delete MESSAGE_ID`.

Keep private keys local. The pinned SSH relay is trusted to map inbox addresses to their age public keys. It checks the supplied destination key and requires correctly framed age envelopes; only the endpoints can authenticate and decrypt their contents. Routing details, filenames, sizes and timing remain visible. See the [security policy](SECURITY.md).

## Development and license

See [CONTRIBUTING.md](CONTRIBUTING.md) for the test and release process. spool is licensed under the [MIT License](LICENSE). Bundled components retain their [upstream notices](THIRD_PARTY_NOTICES.txt).
