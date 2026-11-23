# Contributing to spool

## Develop locally

Use Go 1.26 or newer. From the repository root:

```sh
go test ./...
go build ./cmd/spool-relay
```

The integration suite starts ephemeral SSH listeners with generated identities and temporary data directories. It does not require a running relay or your personal SSH credentials. See the [README](README.md) to run a relay manually.

- `cmd/spool-relay/`: host identity, configuration, listener, and cleanup lifecycle.
- `internal/relay/`: mailbox ownership, SQLite metadata, attachment storage, quotas, and expiry.
- `internal/sshserver/`: SSH authentication, session handling, command parsing, and the embedded `spool` skill.
- `integration/`: end-to-end SSH behavior, including ownership boundaries and migration.

Keep changes focused. For a behavior change, include a test that would have caught the old behavior. Keep the embedded skill in sync with user-visible SSH commands. Never commit `.env`, relay data, allowlists, host private keys, or generated release archives. Report security issues as described in [SECURITY.md](SECURITY.md).

## Cut a release

1. Confirm the intended commit passes CI and that GitHub Actions is enabled. Enable **private vulnerability reporting** in the repository's security settings so users can use the reporting channel in `SECURITY.md`.
2. If the Go toolchain or dependencies have changed, refresh [third-party notices](THIRD_PARTY_NOTICES.txt) from the pinned upstream distributions. The project's MIT license does not replace dependency licenses.
3. To preview the assets, use a Linux environment with Go, `tar`, `gzip`, `zip` and `sha256sum`. The script requires an output directory that **does not yet exist**:

   ```sh
   sh scripts/package-release.sh dist
   (cd dist && sha256sum -c SHA256SUMS)
   ```

4. When ready to publish, create and push an intentional version tag (for example `v0.1.0`). The [release workflow](.github/workflows/release.yml) runs tests on Linux, macOS and Windows before packaging six OS/CPU combinations. It publishes the archives and `SHA256SUMS` to a GitHub Release for that tag. A normal branch push or pull request does not publish a release.

The macOS and Linux archives are `.tar.gz`; Windows archives are `.zip`. Each contains `spool-relay` (or `spool-relay.exe`), `LICENSE`, and `THIRD_PARTY_NOTICES.txt`. The agent skill is embedded in the executable, not installed as a separate client.
