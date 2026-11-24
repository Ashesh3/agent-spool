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
| `LEGACY_OWNERS_FILE` | Unset | Administrator-supplied ownership map for a pre-SSH database (below). |
| `MAX_FILE_BYTES` | `26214400` (25 MiB) | Single uploaded file. |
| `MAX_MESSAGE_BYTES` | `52428800` (50 MiB) | Message body plus its attachments. |
| `QUOTA_BYTES` | `1073741824` (1 GiB) | Pending uploads and retained sends per owner, across its inboxes. |
| `REQUESTS_PER_MINUTE` | `120` | Commands per authenticated key. |

The body limit is 1 MiB, including base64 when using age; at most 16 attachments can accompany a message. Limit overrides use positive integers. Pending uploads expire after one hour; delivered mail expires seven days after sending. Expired data is inaccessible before the startup or five-minute cleanup sweep removes it. These limits do not delete local downloads or backups.

Compose publishes `${BIND_IP:-127.0.0.1}:${RELAY_PORT:-2222}` and mounts `${SSH_CONFIG_DIR:-./ssh-config}` read-only at `/config`. Create that directory before startup. To allow remote agents, select the intended host interface, configure routing and firewall rules, and give clients the matching SSH endpoint. `RELAY_HOST` alone does not expose the listener.

If an existing deployment advertised an IP, change `RELAY_HOST` in `.env` to the public DNS name and run `docker compose up -d --build --force-recreate relay`. Keep `relay-data`: handles, owners, messages and cursors are unchanged. `list`, `create` and `poll` use the new suffix; share the corrected addresses because the old suffix will no longer route. Re-fetch `skill` to update previously installed agent instructions.

## Identities and backups

- Check a member's fingerprint with `ssh-keygen -lf member.pub -E sha256`. Add or remove the approved public key in `authorized_keys` and restart the relay. A new fingerprint is a different owner. Removing a key blocks login; it does **not** remove its inboxes or stop other users from sending to those addresses. Tell senders when an address is no longer in use.
- Keep the host key across restarts. The relay prints its **public** `host_key` and `host_fingerprint` at startup. For nondefault ports, the trusted `known_hosts` entry begins with `[hostname]:port`; for port 22, use `hostname`. If the key changes unexpectedly, stop and verify with the operator instead of disabling checking.
- Restrict the data directory to the relay service account (use an appropriate ACL on Windows). In Docker, the process runs as UID/GID `65532`; it needs write access to `/data` and read access to the allowlist and any configured host key.
- For a consistent backup, stop the relay, copy the **entire** data directory or named volume, then restart. Also back up the allowlist and any externally configured host key separately with appropriate permissions. Restore while the relay is stopped and retain the same hostname. `docker compose down -v` removes the named volume; do not use it to upgrade.

## Migrating a pre-SSH database

Older databases do not record an SSH owner. To preserve their inboxes, messages, blobs and public age keys:

1. Stop the old process and back up the complete data directory. Keep the same `RELAY_HOST`.
2. Verify ownership out of band. Put one `<inbox_id> <SHA256 fingerprint>` pair per line in a file. Use the handle rather than the full address. Every old inbox needs an explicit mapping, and every fingerprint must be on the allowlist.
3. Set `LEGACY_OWNERS_FILE` for the first SSH startup. In Compose, put the file in `ssh-config/legacy-owners` and set the variable to `/config/legacy-owners`.
4. Remove that setting after successful migration. The old secrets no longer grant access. To roll back, restore the backup rather than starting the old service against the migrated store.
