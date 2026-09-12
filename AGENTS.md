# RefineID Windows agent rules

- Source and project prose may use the ISO-8859-15 character repertoire,
  including meaningful specification symbols such as `§`; do not degrade them
  to ASCII. Store each source file in the encoding required by its toolchain
  (Rust `.rs` files must be valid UTF-8). Preserve a protocol fixture's exact
  specified byte encoding.
- No AI attribution in commits.
- Zero PIN and PIN-length logging across all environments: Never log, trace,
  display, or format PIN bytes, candidate PIN lengths (e.g. `got {len}`), or
  development PIN identifiers in log sinks, audit records, or error strings.
  Never commit test PINs or card secrets.
- Safe Rust owns protocol, parsing, and secret handling. Keep `unsafe` inside
  the Windows Card Module or PC/SC boundary.
- Every Windows ABI pointer access must validate nullability and length before
  dereferencing.
- Use named constants instead of naked protocol or status values.
- Verify claims from Microsoft, DVV, ICAO, eIDAS, or another primary source.
- Always run formatting (`cargo fmt`, `csharpier`), clippy (`-D warnings` on both host and Windows targets), and unit tests before committing (`.githooks/pre-commit` enforces this). Keep `Cargo.lock` Git dependencies synchronized with upstream (`.githooks/pre-push` enforces this). Never bypass verification with `--no-verify`. Hardware claims additionally require a real reader and card.
- Do not publish unsigned or test-signed binaries as production releases.
