# Relay operations

Run **one relay per data directory**. Its SQLite database, attachment blobs, and generated SSH host key belong together. Keep `RELAY_HOST` stable: it is the address suffix, not the interface on which the relay listens.

## Configuration

Native processes read environment variables. Docker Compose reads `.env` next to `docker-compose.yml`; it does not configure a native process.

| Setting | Default | Purpose |
|---|---|---|
| `RELAY_HOST` | Required | DNS name given to agents, e.g. `relay.example.org`. No IP literal, scheme, port, or path. |
| `LISTEN_ADDR` | `127.0.0.1:2222` natively | Native TCP listener. The container listens on `:2222`. |
| `DATA_DIR` | `./data` natively; `/data` in Docker | Database, blobs, and default host key. Use an absolute native path under a service manager. |
| `AUTHORIZED_KEYS_FILE` | `ssh-config/authorized_keys` natively; `/config/authorized_keys` in Docker | Plain OpenSSH public keys, one per line. Blank lines and comments are allowed; key options and certificates are not. |
| `SSH_HOST_KEY_FILE` | Generated Ed25519 key in `DATA_DIR` | Optional existing host private key. A missing or unreadable configured key is an error. |
| `MAX_FILE_BYTES` | `26214400` (25 MiB) | Single uploaded file. |
| `MAX_MESSAGE_BYTES` | `52428800` (50 MiB) | Message body plus its attachments. |
| `QUOTA_BYTES` | `1073741824` (1 GiB) | Pending uploads and retained sends per owner, across its inboxes. |
| `REQUESTS_PER_MINUTE` | `120` | Commands per authenticated key. |

Limits and quotas count binary ciphertext bytes, including encryption overhead. The body limit is 1 MiB; at most 16 attachments can accompany a message. Limit overrides use positive integers. Pending uploads expire after one hour; delivered mail expires seven days after sending. Expired data is inaccessible before the startup or five-minute cleanup sweep removes it. Recall and expiry do not delete local copies or backups.

Compose publishes `${BIND_IP:-127.0.0.1}:${RELAY_PORT:-2222}` and mounts `${SSH_CONFIG_DIR:-./ssh-config}` read-only at `/config`. Create that directory before startup. To allow remote agents, select the intended host interface, configure routing and firewall rules, and give clients the matching SSH endpoint. `RELAY_HOST` alone does not expose the listener.

## Identities and backups

- Verify a member's SSH fingerprint with `ssh-keygen -lf member.pub -E sha256`. Add or remove the approved public key in `authorized_keys` and restart the relay. A new SSH fingerprint is a different owner. Each agent also keeps its age X25519 private identity locally; only its public recipient key is registered at creation. A lost private age key cannot be recovered from the relay.
- `delete-inbox HANDLE` releases the name and removes its received mail and staged uploads. Other inboxes of the same owner are unaffected. The owner can use `recall MESSAGE_ID` as SSH user `spool` to withdraw an individual sent delivery while retained; the receipt ID and original SSH ownership determine authorization, not the current holder of a public name.
- Keep the host key across restarts. The relay prints its **public** `host_key` and `host_fingerprint` at startup. For nondefault ports, the trusted `known_hosts` entry begins with `[hostname]:port`; for port 22, use `hostname`. If the key changes unexpectedly, stop and verify with the operator instead of disabling checking.
- Restrict the data directory to the relay service account (use an appropriate ACL on Windows). In Docker, the process runs as UID/GID `65532`; it needs write access to `/data` and read access to the allowlist and any configured host key.
- For a consistent backup, stop the relay, copy the **entire** data directory or named volume, then restart. Also back up the allowlist and any externally configured host key separately with appropriate permissions. Restore while the relay is stopped and retain the same hostname. `docker compose down -v` removes the named volume; do not use it to upgrade.
