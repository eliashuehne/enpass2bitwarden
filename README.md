# enpass2bitwarden

Migrate an **Enpass v6** vault to **Bitwarden / Vaultwarden**, including the
things no official importer handles: **passkeys** and **file attachments**.

Works fully offline — your master password and vault data never leave the machine.

## Quick start (~1 minute)

> **Prerequisites:** [Bitwarden CLI](https://bitwarden.com/help/cli/) installed, an Enpass backup file (Enpass desktop app → **File → Backup**), and your Enpass master password.

**1. Install** (macOS/Linux via Homebrew; Windows: download the `.exe` from [Releases](../../releases)):

```bash
brew install eliashuehne/enpass2bitwarden/enpass2bitwarden
```

(Formula lives in the [homebrew-enpass2bitwarden](https://github.com/eliashuehne/homebrew-enpass2bitwarden) tap.)

**2. Unlock your vault:**

```bash
bw config server https://your-vaultwarden.example.com   # skip if using bitwarden.com
export BW_SESSION=$(bw unlock --raw)
```

**3. Migrate everything:**

```bash
enpass2bitwarden migrate ~/Documents/vault-498_items-auto.enpassbackup ./out
```

That's it — passwords, TOTP codes, attachments **and passkeys** are all
migrated automatically.

The only manual step left: test a passkey login on a low-stakes site before
relying on the important ones. (If any item couldn't be matched by name,
re-run with `enpass2bitwarden apply ./out` after renaming it in the web vault.)

---

## What it does

No official import path exists for Enpass passkeys or attachments. This tool
fills those gaps:

- **Passkeys** — Enpass stores them in an undocumented database table that its
  own JSON export omits. This tool decrypts them and converts them into
  Bitwarden's internal format, byte-for-byte.
- **Attachments** — stored across encrypted side-car files. This tool finds,
  decrypts, and extracts every one of them.
- Passwords, TOTP codes, credit cards, and folders are imported by Bitwarden
  itself (`bw import enpassjson`).

## Step-by-step (details)

Prefer to run the pieces individually, or migrating from raw vault files instead of a backup? See:

- **`decrypt`** — accepts either a `.enpassbackup` file or a raw `vault.enpassdb`.
  For raw vaults you also need the sibling `Enpass/` folder (attachment
  databases) and `vault.json`, copied from your sync location or device.
- **`passkeys ./out/dump.json > fido2.json`** — emits Bitwarden-format passkey
  credentials (see [docs/FORMATS.md](docs/FORMATS.md) for what's inside).
- **`attach ./out`** — uploads extracted attachments to their matching items via `bw`.

The JSON export for password import is created in Enpass via **File → Export → As JSON**.

## Logging

Every run prints progress to stdout. For an audit trail add:

```bash
enpass2bitwarden migrate --log-file=./out backup.enpassbackup ./out
```

All output (including per-item debug traces with `--verbose`) is mirrored to
`<path>/enpass2bitwarden.log` with UTC timestamps.

## Safety

- Your master password is used **in memory only** — never written to disk by this tool.
- Decrypted data lands in `./out` with `0700` permissions. **Delete the folder
  when you're satisfied** — it contains your secrets in plain form.
- Keep your Enpass vault untouched until you've verified everything migrated.
- Make a backup copy of `vault.enpassdb` before starting (one `cp` command).

## What if something goes wrong?

See [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md). It covers every failure
mode we've seen, with exact fixes.

## Known limitations

- Keyfile-protected vaults (`have_keyfile: 1`) are not supported yet.
- Intel Macs and Windows: no Homebrew formula — download from
  [Releases](../../releases) (Windows) or build from source (Intel Macs).
- Passkeys must be attached to their login items in the web vault after
  migration (Bitwarden has no import API for them) — the tool writes a ready-
  to-paste JSON file and prints instructions.

## Building from source

Requires Go 1.22+, a C compiler, and SQLCipher
(`libsqlcipher-dev` on Debian/Ubuntu, `brew install sqlcipher` on macOS):

```bash
git clone https://github.com/eliashuehne/enpass2bitwarden
cd enpass2bitwarden
CGO_ENABLED=1 go build -o enpass2bitwarden ./cmd
```

## License

MIT
