# Enpass / Bitwarden internal formats

Reverse-engineered notes from migrating a live Enpass v6 vault (517 items,
32 passkeys, 22 attachments) to Vaultwarden 1.37.2 in August 2026.

## Enpass vault.enpassdb

SQLCipher v4 database.

- Salt: first 16 bytes of the file.
- Key: `PBKDF2-HMAC-SHA512(master_password, salt, kdf_iter, 64)` where
  `kdf_iter` comes from the sibling `vault.json` (320000 on current versions).
- Open DSN: `path?_pragma_key=x'<hex(key)[:64]>'&_pragma_cipher_compatibility=4`

Pitfall: Python's `sqlcipher3` pip package cannot open these files with any
pragma ordering; use Go's `github.com/mutecomm/go-sqlcipher`.

### Tables of interest

- `item(uuid, title, key BLOB[44], ...)` — `key` = 32-byte AES key ‖ 12-byte
  nonce used to encrypt sensitive fields and passkey material.
- `itemfield(value TEXT, type TEXT, sensitive INT)` — non-password fields are
  plaintext; `type='password'` values are hex-encoded AES-256-GCM ciphertext,
  AAD = item uuid without dashes.
- `passkeys` — **undocumented**, invisible to hazcod/enpass-cli (it only reads
  `item`/`itemfield`). Columns include credential_id (base64url text),
  relying_party_id, user_handle, private_key BLOB.
- `attachment(uuid, name, data BLOB, password TEXT)` — small (<~1KB)
  attachments are stored **plaintext** in `data`; larger ones have empty
  `data` and a `password` column pointing at an external file.

### passkeys.private_key

AES-256-GCM encrypted with the parent item's key:
`plaintext = GCM_Open(item.key[32:44], private_key_blob, AAD=item_uuid_hex)`.
Decrypts to a PEM `EC PRIVATE KEY` (SEC1, P-256 / ES256).

## .enpassattach external attachment databases

Each is its own SQLCipher v4 database. The key is NOT derived from the master
password — it lives in the main vault's `attachment.password` column as a
SQLite blob-literal text string:

```
x'<96 hex chars>'        → 48 bytes: 32-byte AES key ‖ 12-byte nonce
```

Open with `_pragma_key=x'<first 64 hex chars of those 48 bytes>'`. The DB
contains an `attachment` table whose blob column is the plaintext file.

## Bitwarden fido2Credentials

Stored per-cipher at `login.fido2Credentials[]`. Getting these fields wrong
produces confusing failures only visible in the browser extension's
background-page console (`chrome://extensions` → Developer mode → service
worker):

| Field | Requirement | Symptom if wrong |
|---|---|---|
| `credentialId` | `"b64." + base64(raw_bytes)` or GUID string | Extension offers nothing; page AbortError/timeout |
| `keyAlgorithm` | `"ECDSA"` (WebCrypto name) | `importKey ... Algorithm: Unrecognized name` |
| `keyValue` | base64(PKCS#8 DER) | signature failures |
| `userHandle` | base64 exactly as registered | assertion rejected |
| `discoverable`, `counter` | strings, not bools/int | parse errors |

Sources: bitwarden/clients `libs/common/src/platform/services/fido2/credential-id-utils.ts`,
`sdk-internal crates/bitwarden-fido/src/crypto.rs`.
