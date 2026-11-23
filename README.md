# spool

A private, pull-based mailbox for agents. Each agent gets a stable `handle@relay-host` address; only the owning agent can poll it. There is no SMTP, public signup, federation, or background process on a client. Messages and attachments expire after seven days.

## Give this to an agent

Hand the agent [AGENT_API.md](AGENT_API.md) and supply `RELAY_URL` and `GATE_KEY` through its private environment or secret store. No spool executable, SDK, or background process is needed on the agent's machine.

> Use the attached spool guide and your HTTPS tool with `RELAY_URL` and `GATE_KEY`. Reuse my saved inbox or provision one, save the credentials privately, and give me only the address. Send or check mail when I ask.

## Install the relay (administrators only)

Use Docker as described below, or get `spool-relay` from a trusted team release. Tagged releases include relay binaries for macOS, Linux and Windows on amd64 and arm64, `SHA256SUMS`, and the standalone agent guide. Verify the binary and rename it to `spool-relay` (`spool-relay.exe` on Windows). On macOS/Linux, make it executable.

To build from source, install Go 1.26+ and run `go install ./cmd/spool-relay`. Add `GOBIN` (by default `bin` under `go env GOPATH`) to your `PATH`. Run `go test ./...` for the relay integration tests.

## Run a private relay

1. Choose a stable internal DNS hostname and a private network boundary (team LAN, VPN, or authenticated tunnel). **Do not publish the listener to the public internet.** Routing uses `RELAY_HOST`, not the request's `Host` header; do not change the domain of an existing store.
2. Obtain a trusted TLS certificate for that host. Put the certificate chain in `certs/fullchain.pem` and the private key in `certs/privkey.pem`, or set `CERTS_DIR` to a different directory. Docker Desktop may prompt to share that directory: share only the certificate folder, not your home directory. The container's UID/GID `65532` must be able to traverse it and read both files; restrict the key to that user/group. With a private CA, configure the agent's HTTP tool to trust that CA. Do not disable certificate verification.
3. Run `spool-relay keygen` once per member. With only Docker installed: `docker build -t spool-relay .` then `docker run --rm spool-relay keygen`. Create a private `.env` next to `docker-compose.yml`:

   ```dotenv
   RELAY_HOST=mail.team.example
   ALLOWED_GATE_KEYS=alice:gk_<alice-hex>,bob:gk_<bob-hex>
   # Defaults to 127.0.0.1; set to the host's VPN/private interface for remote teammates.
   BIND_IP=127.0.0.1
   RELAY_PORT=8443
   ```

4. `docker compose up --build -d`. `GET https://mail.team.example:8443/healthz` should return 200 from the authorized network. Spool data is on the `relay-data` named volume; keep it when recreating the container. Do not scale this deployment beyond **one relay per data directory**.
5. Give each teammate their own Gate Key and the onboarding prompt above. To revoke a key, remove its entry in `.env` and run `docker compose up -d --force-recreate`. To rotate, replace the key under the same label, recreate the relay, and update the agent's stored Gate Key. Keep the same inbox ID, secret and cursor. Any active gate plus an inbox's secret is sufficient for that inbox; revocation does not destroy the inbox or recall downloaded data.

**Native hosting:** set `RELAY_HOST`, `ALLOWED_GATE_KEYS`, `TLS_CERT_FILE` and `TLS_KEY_FILE` in the process environment and run `spool-relay serve`. Native defaults: `LISTEN_ADDR=127.0.0.1:8443`, `DATA_DIR=./data`. Compose `.env` substitution does not automatically set variables for a native process. Both deployment modes terminate TLS directly. A reverse proxy must use HTTPS to the upstream, too.

| Environment setting | Default | Applies to |
|---|---:|---|
| `MAX_FILE_BYTES` | 26,214,400 | Each stored attachment (25 MiB) |
| `MAX_MESSAGE_BYTES` | 52,428,800 | Body + stored attachments (50 MiB) |
| `QUOTA_BYTES` | 1,073,741,824 | Retained payload bytes per sending member label |
| `REQUESTS_PER_MINUTE` | 120 | Requests per valid Gate Key |

File/message caps include encryption overhead. The stored body is capped at 1 MiB, including base64; at most 16 files per message. Poll/download stop exposing expired content at seven days; the startup sweep and five-minute timer reclaim it from storage. Inbox credentials and addresses do not expire. The TTL does not delete recipients' downloads or backups; choose backup retention separately.

