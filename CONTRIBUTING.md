# Contributing

Thanks for your interest in improving `enpass2bitwarden`!

## Reporting bugs

Open a [GitHub issue](../../issues/new) and include:

- Tool version (`enpass2bitwarden --version`) and OS
- How you obtained the vault (`.enpassbackup` file vs raw sync files)
- The exact command you ran
- The full output, including any `warn:` lines
- **Never paste decrypted vault contents** — redact titles/usernames if needed
  for context.

## Pull requests

1. Fork, create a branch from `master`
2. `go vet ./...` must pass (CI runs it)
3. Keep changes focused; one logical change per PR
4. Update `docs/` if you touch wire formats or add flags

## Development notes

- The SQLCipher dependency (`go-sqlcipher`) vendors its own C sources — no
  system library required, just any C compiler.
- Test against a **copy** of a vault, never your live one. If you need a test
  vault: create one in Enpass with 2–3 dummy items, one passkey, one attachment.
- Never commit vault files, dumps, or logs — `.gitignore` guards common names,
  but double-check `git status`.

## Security-sensitive changes

Anything touching decryption, key derivation, or the Bitwarden credential
format will be reviewed carefully before merge — expect questions.
