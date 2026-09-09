# Contributing

ReFineID is security-sensitive identity middleware. Small, reviewable changes
with evidence are preferred.

Before submitting:

```powershell
cargo fmt --all -- --check
dotnet tool restore
dotnet csharpier check .
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p refineid-lib-core
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build.ps1 -Architecture x64,arm64
```

Formatting is owned by dedicated tools: rustfmt for Rust and CSharpier for C#,
XAML, and the project files. CSharpier is pinned in `.config/dotnet-tools.json`
and its style is fixed, so `dotnet csharpier format .` fixes any formatting the
check reports.

## Commit gate

`.github/workflows/ci.yml` is the authoritative push gate: it runs formatting,
lint, tests, and the requester build on a Windows runner, and `main` is
protected so nothing merges until it passes.

Enable the local pre-commit hook once per clone so a badly formatted change is
caught before it leaves the machine:

```sh
git config core.hooksPath .githooks
```

The pre-commit hook runs on every host to catch defects locally before
pushing: `cargo fmt`, `dotnet csharpier check`, `cargo clippy` (both native
host and `x86_64-pc-windows-msvc` for Windows-specific crates), and core
unit tests (`cargo test -p refineid-lib-core`). CI then validates the full
suite on Windows runners before merging.

Rules:

- Never log or commit a PIN, personal certificate, identity code, or private
  card trace.
- Keep protocol and parsing logic in safe Rust.
- New `unsafe` code belongs only at a documented Windows ABI boundary and must
  state its pointer, length, ownership, and lifetime invariants.
- Replace magic protocol values with named constants and cite the primary
  specification or Windows SDK contract.
- Fail closed on malformed input and unsupported operations.
- Hardware claims require sanitized card/reader evidence.
- Do not add AI attribution trailers to commits.
