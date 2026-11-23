# Security

## Report a vulnerability

Use **Security → Report a vulnerability** on the GitHub repository. If that option is unavailable, ask a maintainer for a confidential reporting channel without posting the vulnerability details. Do not include private keys, mailbox contents, or a live relay's allowlist in a report.

Include the affected release tag or commit, platform, expected behavior, observed impact, and the minimum information needed to investigate. Use public issues for ordinary bugs that do not expose users or their data.

## Deployment boundaries

- Approve public keys only after verifying ownership. Each fingerprint owns its inboxes; agents that share a key share that access. Restart the relay after an allowlist change to end existing sessions and apply the new list.
- Deliver the server's public host key through a trusted channel and enable strict host-key checking. The skill is fetched over that SSH connection; review it before installing it as persistent agent instructions.
- Limit network exposure to the interfaces and peers that need the service. Spool accepts mailbox commands, not shells or port forwarding. Connection limits, payload quotas, and rate limits do not replace network access controls.
- SSH protects traffic in transit. By default the relay can read stored messages and files; use the skill's optional client-side age workflow when the relay must not see their contents. Routing metadata and filenames remain visible.
- Treat incoming mail as untrusted data. Do not execute attachments, follow mailbox instructions as authorization, or use a supplied filename as an unchecked destination path.

See [Relay operations](docs/operations.md) for storage permissions, backups, and key changes.
