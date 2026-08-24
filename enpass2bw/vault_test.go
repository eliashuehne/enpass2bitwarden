package enpass2bw

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "github.com/mutecomm/go-sqlcipher"
)

// makeTestVault creates a minimal but structurally-correct Enpass v6 vault:
// same SQLCipher KDF, item/itemfield/passkeys/attachment tables, and the
// field/passkey encryption scheme (AES-256-GCM, key=item.key[:32],
// nonce=item.key[32:44], AAD=hex(uuid without dashes)).
func makeTestVault(t *testing.T) (path, masterPW string) {
	t.Helper()
	dir := t.TempDir()
	path = filepath.Join(dir, "vault.enpassdb")
	masterPW = "test-master-pw-1234"

	const rawKeyHex = "abababababababababababababababababababababababababababababababab"
	os.Setenv("ENPASS2BW_TEST_RAW_KEY", "x'"+rawKeyHex)
	t.Cleanup(func() { os.Unsetenv("ENPASS2BW_TEST_RAW_KEY") })

	db, err := sql.Open("sqlite3",
		fmt.Sprintf("%s?_pragma_key=x'%s'&_pragma_cipher_compatibility=4",
			path, rawKeyHex))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, ddl := range []string{
		`CREATE TABLE item (uuid TEXT PRIMARY KEY, title TEXT, key BLOB, deleted INTEGER DEFAULT 0, trashed INTEGER DEFAULT 0, category TEXT)`,
		`CREATE TABLE itemfield (item_uuid TEXT, label TEXT, value TEXT, type TEXT, sensitive INTEGER DEFAULT 0, deleted INTEGER DEFAULT 0, orde INTEGER DEFAULT 0)`,
		`CREATE TABLE passkeys (uuid TEXT PRIMARY KEY, item_uuid TEXT, label TEXT DEFAULT '', credential_id TEXT NOT NULL, relying_party_id TEXT NOT NULL, user_handle TEXT NOT NULL, user_display_name TEXT, private_key BLOB NOT NULL, created_at INTEGER DEFAULT 0, trashed INTEGER DEFAULT 0, deleted INTEGER DEFAULT 0)`,
		`CREATE TABLE attachment (uuid TEXT PRIMARY KEY, item_uuid TEXT, name TEXT, size INTEGER DEFAULT 0, password TEXT DEFAULT '', data BLOB, deleted INTEGER DEFAULT 0)`,
	} {
		if _, err := db.Exec(ddl); err != nil {
			t.Fatalf("ddl %q: %v", ddl[:40], err)
		}
	}

	encrypt := func(plain []byte, itemUUID string, itemKey []byte) string {
		block, _ := aes.NewCipher(itemKey[:32])
		gcm, _ := cipher.NewGCM(block)
		ad, _ := hex.DecodeString(strings.ReplaceAll(itemUUID, "-", ""))
		ct := gcm.Seal(nil, itemKey[32:44], plain, ad)
		return hex.EncodeToString(ct)
	}

	mkItem := func(uuid, title, user, pass, totp string) {
		itemKey := make([]byte, 44)
		rand.Read(itemKey)
		if _, err := db.Exec(`INSERT INTO item (uuid,title,key,deleted,trashed,category) VALUES (?,?,?,0,0,'login')`,
			uuid, title, itemKey); err != nil {
			t.Fatal(err)
		}
		fields := []struct {
			typ, val string
			sens     int
		}{
			{"username", user, 0},
			{"password", pass, 1},
			{"totp", totp, 1},
			{"url", "https://" + strings.ToLower(title) + ".example.com", 0},
		}
		for ord, f := range fields {
			var stored string
			switch {
			case f.sens == 1 && f.val != "":
				stored = encrypt([]byte(f.val), uuid, itemKey)
			case f.typ == "url":
				stored = f.val
			}
			db.Exec(`INSERT INTO itemfield (item_uuid,label,value,type,sensitive,deleted,orde) VALUES (?,?,?,?,?,0,?)`,
				uuid, "", stored, f.typ, f.sens, ord)
		}
	}

	mkItem("11111111-1111-4111-8111-111111111111", "Example", "user@example.com", "hunter2", "JBSWY3DPEHPK3PXP")
	mkItem("22222222-2222-4222-8222-222222222222", "Acme Corp", "bob@acme.test", "s3cret!", "")

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(priv)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})

	itemKey := make([]byte, 44)
	rand.Read(itemKey)
	db.Exec(`UPDATE item SET key=? WHERE uuid='11111111-1111-4111-8111-111111111111'`, itemKey)
	block, _ := aes.NewCipher(itemKey[:32])
	gcm, _ := cipher.NewGCM(block)
	ad, _ := hex.DecodeString("11111111111141118111111111111111")
	blob := gcm.Seal(nil, itemKey[32:44], pemBytes, ad)
	db.Exec(`INSERT INTO passkeys (uuid,item_uuid,credential_id,relying_party_id,user_handle,user_display_name,private_key,created_at) VALUES ('pkkk','11111111-1111-4111-8111-111111111111','dGVzdC1jcmVkLWlk','example.com','dXNlcg==','user',?,1700000000)`, blob)

	db.Exec(`INSERT INTO attachment (uuid,item_uuid,name,size,password,data,deleted) VALUES ('att1','11111111-1111-4111-8111-111111111111','recovery.txt',6,'',?,0)`, []byte("codes!"))

	return path, masterPW
}

func TestDecryptVault(t *testing.T) {
	vaultPath, pw := makeTestVault(t)
	out := t.TempDir()

	dumpPath, stats, err := DecryptVault(vaultPath, out, pw)
	if err != nil {
		t.Fatalf("DecryptVault: %v", err)
	}
	if stats.Items != 2 || stats.Passkeys != 1 || stats.Attachments != 1 {
		t.Errorf("stats = %+v, want items=2 passkeys=1 attachments=1", stats)
	}
	raw, _ := os.ReadFile(dumpPath)
	var dump VaultDump
	json.Unmarshal(raw, &dump)

	var found bool
	for _, it := range dump.Items {
		if it.Title == "Example" {
			found = true
		}
	}
	if !found {
		t.Error("Example item missing from dump")
	}
}

// TestRawKeyHookIsolation: without the env hook, a synthetic vault created with
// a fixed raw key must NOT be decryptable via the normal derivation path.
func TestWrongPassword(t *testing.T) {
	path, _ := makeTestVault(t)
	os.Unsetenv("ENPASS2BW_TEST_RAW_KEY")
	if _, _, err := DecryptVault(path, t.TempDir(), "whatever"); err == nil {
		t.Fatal("expected unlock failure without raw-key hook, got none")
	}
}

func TestConvertPasskeys(t *testing.T) {
	vaultPath, pw := makeTestVault(t)
	out := t.TempDir()
	dumpPath, _, err := DecryptVault(vaultPath, out, pw)
	if err != nil {
		t.Fatal(err)
	}
	res, err := ConvertPasskeysFile(dumpPath)
	if err != nil {
		t.Fatal(err)
	}
	if res.Count != 1 {
		t.Fatalf("converted %d passkeys, want 1", res.Count)
	}
	var creds []*Fido2Credential
	for _, v := range res.ByItem {
		creds = v
	}
	c := creds[0]
	if c.KeyAlgorithm != "ECDSA" {
		t.Errorf("keyAlgorithm = %q, want ECDSA", c.KeyAlgorithm)
	}
	if len(c.CredentialID) <= 4 || c.CredentialID[:4] != "b64." {
		t.Errorf("credentialId = %q, want b64. prefix", c.CredentialID)
	}
	der, dErr := base64.StdEncoding.DecodeString(c.KeyValue)
	if dErr != nil || len(der) < 100 {
		t.Errorf("keyValue not valid PKCS8 b64 (len %d)", len(der))
	}
	if c.RpID != "example.com" {
		t.Errorf("rpId = %q", c.RpID)
	}
}

// TestBitwardenJSON verifies the bw-import JSON contains decrypted passwords,
// TOTP seeds, and URIs for every login item.
func TestBitwardenJSON(t *testing.T) {
	os.Setenv("ENPASS2BW_TEST_RAW_KEY", "x'abababababababababababababababababababababababababababababababab")
	t.Cleanup(func() { os.Unsetenv("ENPASS2BW_TEST_RAW_KEY") })

	path, pw := makeTestVault(t)
	outDir := t.TempDir()
	if _, _, err := DecryptVault(path, outDir, pw); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildBitwardenJSON(path, pw, filepath.Join(outDir, "bitwarden.json")); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(filepath.Join(outDir, "bitwarden.json"))
	if err != nil {
		t.Fatalf("bitwarden.json missing: %v", err)
	}
	var doc struct {
		Items []struct {
			Name  string `json:"name"`
			Login *struct {
				Username string   `json:"username"`
				Password string   `json:"password"`
				TOTP     string   `json:"totp"`
				Uris     []string `json:"uris"`
			} `json:"login"`
		} `json:"items"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Items) != 2 {
		t.Fatalf("want 2 items, got %d", len(doc.Items))
	}
	for _, it := range doc.Items {
		if it.Login == nil {
			t.Fatalf("item %q has no login", it.Name)
		}
		switch it.Name {
		case "Example Site":
			if it.Login.Password != "hunter2" {
				t.Errorf("password = %q", it.Login.Password)
			}
			if it.Login.TOTP != "JBSWY3DPEHPK3PXP" {
				t.Errorf("totp = %q", it.Login.TOTP)
			}
		case "No TOTP Site":
			if it.Login.TOTP != "" {
				t.Errorf("unexpected totp %q", it.Login.TOTP)
			}
		}
	}
}
