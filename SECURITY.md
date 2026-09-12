# Security

RefineID for Windows is beta software handling identity-card credentials.

## Reporting

Report however suits you. A public issue is fine and often better, because
it gets more eyes on the problem sooner. GitHub private vulnerability
reporting is enabled if you would rather coordinate a fix first, and that is
the kinder route for anything already exploitable against an installed
driver, where a citizen's PIN or signature is at stake before a fix exists.

**Whichever route you pick, never include a PIN, PUK, CAN, candidate PIN length, private key, full
personal certificate, personal identity code, or an unredacted event log.**
This matters far more than where the report goes: those values identify a
real person, and nothing published on the internet can be unpublished.
Sanitized status words and APDU shapes carry all the information a fix
needs.

A useful report names the affected commit, the Windows architecture, the
card generation, the reader, and a minimal reproduction.

## Fixes

There are no maintained branches and no backports. Fixes land on `main` and
produce a new `YY.M.D.B` build, so the remedy for an affected version is
always to install a newer one.

## Release policy

Packages built from CI are development builds. A public end-user release
requires:

- successful formatting, lint, unit-test, and x64/ARM64 release builds;
- hardware acceptance on supported FINEID card generations;
- published SHA-256 checksums and provenance;
- a documented rollback and uninstall path.

Beta packages are unsigned and install with an unknown-publisher prompt.
Code signing is a separate, later step and is not a condition of beta
availability. A FINEID qualified signature cannot substitute for it:
Authenticode requires a code-signing certificate from a CA in the Microsoft
Trusted Root Program, which a citizen certificate is not.
