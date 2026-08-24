package enpass2bw

import (
	"archive/zip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	_ "github.com/mutecomm/go-sqlcipher" // SQLCipher driver
	"golang.org/x/crypto/pbkdf2"
)

// PasskeyRecord is a decrypted Enpass passkey ready for Bitwarden conversion.
type PasskeyRecord struct {
	UUID            string `json:"uuid"`
	ItemUUID        string `json:"item_uuid"`
	CredentialID    string `json:"credential_id"` // base64url text as Enpass stores it
	RPID            string `json:"rp_id"`
	UserHandle      string `json:"user_handle"` // base64url text
	UserDisplayName string `json:"user_display_name"`
	Label           string `json:"label"`
	Pem             string `json:"pem"` // decrypted SEC1 EC private key PEM
	CreatedAt       int64  `json:"created_at"`
}

// ItemSummary pairs an Enpass item uuid with its title.
type ItemSummary struct {
	UUID  string `json:"uuid"`
	Title string `json:"title"`
}

// AttachmentInfo maps an extracted attachment file to its Enpass item title.
type AttachmentInfo struct {
	File      string `json:"file"`
	ItemTitle string `json:"item_title"`
}

// VaultDump is everything DecryptVault writes to <outdir>/dump.json.
type VaultDump struct {
	Items       []ItemSummary    `json:"items"`
	Passkeys    []PasskeyRecord  `json:"passkeys"`
	AttFiles    []string         `json:"attachment_files,omitempty"`
	Attachments []AttachmentInfo `json:"attachments"`
}

// Stats summarizes a decrypt run.
type Stats struct {
	Items       int `json:"items"`
	Passkeys    int `json:"passkeys"`
	Attachments int `json:"attachments"`
}

const sqlcipherDriver = "sqlite3"

func openVault(path, masterPW string) (*sql.DB, error) {
	salt := make([]byte, 16)
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open vault: %w", err)
	}
	if _, err := f.Read(salt); err != nil {
		f.Close()
		return nil, err
	}
	f.Close()
	key := pbkdf2.Key([]byte(masterPW), salt, 320000, 64, sha512.New)
	hk := hex.EncodeToString(key)[:64]
	// Test hook: allow a fixed raw key so synthetic vaults are decryptable
	// without reproducing Enpass's exact creation path (see vault_test.go).
	if rk := os.Getenv("ENPASS2BW_TEST_RAW_KEY"); rk != "" {
		hk = strings.TrimPrefix(rk, "x'")
	}
	dsn := fmt.Sprintf("%s?_pragma_key=x'%s'&_pragma_cipher_compatibility=4",
		path, hk)
	db, err := sql.Open(sqlcipherDriver, dsn)
	if err != nil {
		return nil, err
	}
	var t string
	if e := db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='item'").Scan(&t); e != nil {
		db.Close()
		return nil, fmt.Errorf("cannot unlock vault — wrong master password or not an Enpass v6 vault")
	}
	return db, nil
}

func hd(s string) []byte {
	b, _ := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	return b
}

// DecryptVault unlocks an Enpass vault (raw .enpassdb or a complete
// .enpassbackup ZIP) and writes dump.json + attachment files into outDir.
// Returns the dump path and stats.
func DecryptVault(vaultPath, outDir, masterPW string) (string, Stats, error) {
	var stats Stats

	// Accept .enpassbackup ZIPs directly: extract to a temp dir and use the
	// vault inside. This is the easiest input for users on any sync setup —
	// Enpass desktop clients can produce a full backup via File > Backup.
	if strings.HasSuffix(strings.ToLower(vaultPath), ".enpassbackup") {
		extracted, err := extractBackup(vaultPath)
		if err != nil {
			return "", stats, err
		}
		defer os.RemoveAll(extracted)
		vp, e := findVaultFile(extracted)
		if e != nil {
			return "", stats, err
		}
		vaultPath = vp
	}

	db, err := openVault(vaultPath, masterPW)
	if err != nil {
		return "", stats, err
	}
	defer db.Close()

	for _, d := range []string{outDir, filepath.Join(outDir, "attachments")} {
		if err := os.MkdirAll(d, 0700); err != nil {
			return "", stats, err
		}
	}

	dump := VaultDump{}

	itemKeys := map[string][]byte{}
	irows, err := db.Query(`SELECT uuid, title, key FROM item WHERE deleted=0 AND trashed=0`)
	if err != nil {
		return "", stats, err
	}
	for irows.Next() {
		var u, t string
		var k []byte
		if e := irows.Scan(&u, &t, &k); e == nil {
			Debug("item %s = %q", u, t)
			dump.Items = append(dump.Items, ItemSummary{UUID: u, Title: t})
			if len(k) >= 44 {
				itemKeys[u] = k
			}
		}
	}
	irows.Close()
	stats.Items = len(dump.Items)

	prows, err := db.Query(`SELECT p.uuid, p.item_uuid, p.credential_id,
		p.relying_party_id, p.user_handle, p.user_display_name, p.label,
		p.private_key, p.created_at
		FROM passkeys p JOIN item i ON p.item_uuid=i.uuid
		WHERE p.deleted=0 AND p.trashed=0`)
	if err == nil {
		defer prows.Close()
		for prows.Next() {
			var pk PasskeyRecord
			var blob []byte
			if e := prows.Scan(&pk.UUID, &pk.ItemUUID, &pk.CredentialID,
				&pk.RPID, &pk.UserHandle, &pk.UserDisplayName, &pk.Label,
				&blob, &pk.CreatedAt); e != nil {
				continue
			}
			ik := itemKeys[pk.ItemUUID]
			if len(ik) < 44 {
				continue
			}
			block, e2 := aes.NewCipher(ik[:32])
			if e2 != nil {
				continue
			}
			gcm, e3 := cipher.NewGCM(block)
			if e3 != nil {
				continue
			}
			pt, e4 := gcm.Open(nil, ik[32:44], blob, hd(pk.ItemUUID))
			if e4 != nil {
				Warn("passkey %s undecryptable, skipping", pk.RPID)
				continue
			}
			pk.Pem = string(pt)
			dump.Passkeys = append(dump.Passkeys, pk)
		}
	} else {
		Info("note: no passkeys table (older vault?) — continuing")
	}
	stats.Passkeys = len(dump.Passkeys)

	attDir := filepath.Join(outDir, "attachments")
	arows, err := db.Query(`SELECT a.uuid, a.name, i.title, i.key, a.password, a.data
		FROM attachment a JOIN item i ON a.item_uuid=i.uuid WHERE a.deleted=0`)
	if err != nil {
		return "", stats, err
	}
	defer arows.Close()
	for arows.Next() {
		var au, name, title string
		var ik, pwCol, data []byte
		if e := arows.Scan(&au, &name, &title, &ik, &pwCol, &data); e != nil {
			continue
		}
		outPath := filepath.Join(attDir, name)

		if len(data) > 0 { // inline = plaintext by design
			if os.WriteFile(outPath, data, 0600) == nil {
				dump.AttFiles = append(dump.AttFiles, outPath)
				dump.Attachments = append(dump.Attachments, AttachmentInfo{File: name, ItemTitle: strings.TrimSpace(title)})
				stats.Attachments++
			}
			continue
		}

		s := strings.TrimSpace(string(pwCol))
		if len(s) < 4 || !strings.HasPrefix(s, "x'") || !strings.HasSuffix(s, "'") {
			continue
		}
		raw, e := hex.DecodeString(strings.TrimSuffix(s[2:], "'"))
		if e != nil || len(raw) < 32 {
			continue
		}
		extPath := filepath.Join(filepath.Dir(vaultPath), au+".enpassattach")
		if _, statErr := os.Stat(extPath); statErr != nil {
			cand := filepath.Join(filepath.Dir(vaultPath), "Enpass", au+".enpassattach")
			if _, s2 := os.Stat(cand); s2 != nil {
				fmt.Fprintf(os.Stderr, "skip %s: %s.enpassattach not found next to vault\n", name, au)
				continue
			}
			extPath = cand
		}
		hk := hex.EncodeToString(raw)[:64]
		adb, e := sql.Open(sqlcipherDriver,
			fmt.Sprintf("%s?_pragma_key=x'%s'&_pragma_cipher_compatibility=4", extPath, hk))
		if e != nil {
			continue
		}
		var blob []byte
		found := false
		for _, col := range []string{"data", "blob", "content", "file"} {
			q := fmt.Sprintf("SELECT %s FROM attachment LIMIT 1", col)
			if e := adb.QueryRow(q).Scan(&blob); e == nil && len(blob) > 0 {
				found = true
				break
			}
		}
		adb.Close()
		if found {
			if err := os.WriteFile(outPath, blob, 0600); err == nil {
				dump.AttFiles = append(dump.AttFiles, outPath)
				dump.Attachments = append(dump.Attachments, AttachmentInfo{File: name, ItemTitle: strings.TrimSpace(title)})
				stats.Attachments++
			}
		}
	}

	out, _ := json.MarshalIndent(dump, "", "  ")
	dumpFile := filepath.Join(outDir, "dump.json")
	if err := os.WriteFile(dumpFile, out, 0600); err != nil {
		return "", stats, err
	}
	return dumpFile, stats, nil
}

// extractBackup unpacks an .enpassbackup ZIP into a fresh temp directory.
func extractBackup(path string) (string, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return "", fmt.Errorf("not a valid .enpassbackup (zip): %w", err)
	}
	defer zr.Close()
	tmp, err := os.MkdirTemp("", "enpassbackup-*")
	if err != nil {
		return "", err
	}
	for _, f := range zr.File {
		target := filepath.Join(tmp, filepath.FromSlash(f.Name))
		if !strings.HasPrefix(target, filepath.Clean(tmp)+string(os.PathSeparator)) {
			continue // zip-slip guard
		}
		if f.FileInfo().IsDir() {
			os.MkdirAll(target, 0700)
			continue
		}
		if e := os.MkdirAll(filepath.Dir(target), 0700); e != nil {
			return "", e
		}
		src, e := f.Open()
		if e != nil {
			return "", e
		}
		dst, e := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if e != nil {
			src.Close()
			return "", e
		}
		if _, e := io.Copy(dst, src); e != nil {
			src.Close(); dst.Close()
			return "", e
		}
		src.Close()
		dst.Close()
	}
	return tmp, nil
}

// findVaultFile locates vault.enpassdb anywhere under root.
func findVaultFile(root string) (string, error) {
	var found string
	filepath.WalkDir(root, func(p string, d os.DirEntry, e error) error {
		if e == nil && !d.IsDir() && d.Name() == "vault.enpassdb" {
			found = p
			return filepath.SkipAll
		}
		return nil
	})
	if found == "" {
		return "", fmt.Errorf("vault.enpassdb not found inside backup")
	}
	return found, nil
}
