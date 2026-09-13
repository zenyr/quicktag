# Working on the agent CLI fork

Read `docs/agent-cli.md` for the command contract and feature coverage. The
`agent-cli` branch preserves the desktop application and adds `crates/cli`.

- Build the CLI specifically: `cargo build --locked --release -p quicktag-cli`.
- Run `cargo test --locked -p quicktag-cli -p quicktag-scanner` on Linux/Windows.
  The current `tiger-pkg` dependency cannot compile on macOS; use a Linux container
  for synthetic tests and the package host for actual Oodle decompression.
- Prefer `serve` over repeated process launches during investigations. Use a small
  `limit`, follow `next_offset`, and request individual tags/byte ranges as needed.
- Tag hashes use GUI display byte order; class IDs and string hashes are numeric
  hex. Preserve evidence (source/target/offset/basis) when extending query output.
- Share decoding/scanning behavior with existing library crates. List incomplete
  parity explicitly in `docs/agent-cli.md`; payload export does not imply decoded
  image/audio export.
- Keep game data, caches, exports and private host details out of the repository.
  Record test build identifiers and compact validation summaries, not bulk dumps.
- Push fork commits before updating a parent repository's submodule pointer.
