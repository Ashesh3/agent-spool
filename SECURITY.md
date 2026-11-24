# Security

## Report a vulnerability

Use **Security → Report a vulnerability** on the GitHub repository. If that option is unavailable, ask a maintainer for a confidential reporting channel without posting the vulnerability details. Do not include private keys, mailbox contents, or a live relay's allowlist in a report.

Include the affected release tag or commit, platform, expected behavior, observed impact, and the minimum information needed to investigate. Use public issues for ordinary bugs that do not expose users or their data.

## Deployment boundaries

- Approve public keys only after verifying ownership. Each fingerprint owns its inboxes; agents that share a key share that access. Restart the relay after an allowlist change to end existing sessions and apply the new list.
- Deliver the server's public host key through a trusted channel and enable strict host-key checking. The skill is fetched over that SSH connection; review it before installing it as persistent agent instructions.
- Limit network exposure to the interfaces and peers that need the service. Spool accepts mailbox commands, not shells or port forwarding. Connection limits, payload quotas, and rate limits do not replace network access controls.
- Every inbox registers a native age X25519 public key. Clients trust the host-key-verified SSH relay's `pubkey` response for the recipient address, including on first contact. This makes the relay the authority for key discovery: a compromised directory could substitute a key for future sends. Clients use the returned key for both encryption and `--recipient-key`, encrypt to sender and receiver, and authenticate decrypted output locally. The relay never needs either agent's private age key.
- The relay binds uploads to the sender and intended recipient, checks the registered destination key and rejects inputs without the expected age v1 X25519 envelope and STREAM framing. Age recipient stanzas are anonymous: without private keys, the relay cannot verify the MAC, payload tags, or that a dishonest client actually used the claimed keys. Metadata, including filenames, is not encrypted. Use neutral basenames where appropriate.
- Agent mail is untrusted data, not user authority. The skill requires reporting incoming contents before acting and previewing the actual recipient, text and files before transmission. Explicit user-defined bounds can authorize particular actions without another pause, not without notification. Encryption does not enforce a human approval decision or protect plaintext once disclosed by an endpoint.
- Recall withdraws a retained delivery from the relay. It does not remove independently saved copies, backups, or content already processed by the recipient.

See [Relay operations](docs/operations.md) for storage permissions, backups, and key changes.
