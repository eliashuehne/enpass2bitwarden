package enpass2bw

import (
	"crypto/aes"
	"encoding/hex"
	"crypto/cipher"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// BitwardenItem is one entry of the bitwardenjson import format.
type BitwardenItem struct {
	Type     int             `json:"type"`
	Name     string          `json:"name"`
	Notes    string          `json:"notes,omitempty"`
	Favorite bool            `json:"favorite"`
	Login    *BitwardenLogin `json:"login,omitempty"`
	Fields   []BwField       `json:"fields,omitempty"`
}

// BitwardenLogin holds credential data for type-1 items.
type BitwardenLogin struct {
	URIs     []string `json:"uris,omitempty"`
	Username string   `json:"username,omitempty"`
	Password string   `json:"password,omitempty"`
	TOTP     string   `json:"totp,omitempty"`
}

// BwField is a custom field (0=text, 1=hidden, 2=boolean).
type BwField struct {
	Type  int    `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

// bitwardenExport is the top-level bitwardenjson document.
type bitwardenExport struct {
	Folders []string        `json:"folders,omitempty"`
	Items   []BitwardenItem `json:"items"`
}

// fieldRow is a decrypted item field.
type fieldRow struct {
	Label string
	Value string
	Type  string
	URL   string
	TOTP  string
	Note  string
}

// BuildBitwardenJSON converts a decrypted dump into the bitwardenjson import
// format. It reads full item data from the vault via a second pass.
func BuildBitwardenJSON(vaultPath, masterPW, outPath string) (int, error) {
	extract := vaultPath
	if strings.HasSuffix(strings.ToLower(vaultPath), ".enpassbackup") {
		ex, err := extractBackup(vaultPath)
		if err != nil {
			return 0, err
		}
		defer os.RemoveAll(ex)
		vp, err := findVaultFile(ex)
		if err != nil {
			return 0, err
		}
		extract = vp
	}
	db, err := openVault(extract, masterPW)
	if err != nil {
		return 0, err
	}
	defer db.Close()

	itemKeys := map[string][]byte{}
	titles := map[string]string{}
	irows, err := db.Query(`SELECT uuid, title, key FROM item WHERE deleted=0 AND trashed=0`)
	if err != nil {
		return 0, err
	}
	for irows.Next() {
		var u, t string
		var k []byte
		if e := irows.Scan(&u, &t, &k); e == nil {
			titles[u] = t
			if len(k) >= 44 {
				itemKeys[u] = k
			}
		}
	}
	irows.Close()

	// gather fields per item
	type acc struct {
		item    BitwardenItem
		urls    []string
		user    string
		pass    string
		totp    string
		hasData bool
	}
	items := map[string]*acc{}
	frows, err := db.Query(`SELECT f.item_uuid, f.label, f.value, i.key, f.type FROM itemfield f
		JOIN item i ON f.item_uuid = i.uuid WHERE f.deleted=0 ORDER BY f.item_uuid, f.orde`)
	if err != nil {
		return 0, err
	}
	defer frows.Close()
	n := 0
	for frows.Next() {
		var iu, typ string
		var label string
		var val, key []byte
		if e := frows.Scan(&iu, &label, &val, &key, &typ); e != nil {
			continue
		}
		title := titles[iu]
		if title == "" {
			continue
		}
		a := items[iu]
		if a == nil {
			a = &acc{}
			a.item = BitwardenItem{Type: 1, Name: title}
			items[iu] = a
		}
		pt := ""
		sensitive := isSensitiveFieldType(typ)
		if typ == "totp" {
			pt = strings.TrimSpace(string(val)) // TOTP seeds are stored as plain base32
		} else if sensitive && len(val) > 0 && len(key) >= 44 {
			raw, derr := hex.DecodeString(string(val))
			if derr != nil {
				continue
			}
			p, ok := decryptGCM(raw, key, iu)
			if !ok {
				continue
			}
			pt = p
		} else if !sensitive {
			pt = string(val)
		} else {
			continue // encrypted but no usable key
		}
		switch typ {
		case "username":
			a.user = pt
		case "password":
			a.pass = pt
		case "url":
			a.urls = append(a.urls, pt)
		case "totp":
			a.totp = pt
		case "section":
			// ignore separators
		default:
			if label == "" || pt == "" {
				continue
			}
			ft := 0 // text
			if sensitive && typ != "email" && typ != "text" {
				ft = 1 // hidden
			}
			a.item.Fields = append(a.item.Fields, BwField{Type: ft, Name: label, Value: pt})
		}
		a.hasData = true
		n++
	}

	exp := bitwardenExport{}
	for iu, a := range items {
		if !a.hasData {
			continue
		}
		if a.user != "" || a.pass != "" || a.totp != "" || len(a.urls) > 0 {
			a.item.Login = &BitwardenLogin{
				URIs:     dedupe(a.urls),
				Username: a.user,
				Password: a.pass,
				TOTP:     normalizeTOTP(a.totp),
			}
		}
		exp.Items = append(exp.Items, a.item)
		_ = iu
	}
	if len(exp.Items) == 0 {
		return 0, fmt.Errorf("no items extracted")
	}
	data, err := json.MarshalIndent(exp, "", " ")
	if err != nil {
		return 0, err
	}
	if err := os.WriteFile(outPath, data, 0600); err != nil {
		return 0, err
	}
	return len(exp.Items), nil
}

func isSensitiveFieldType(t string) bool {
	switch t {
	case "password", "totp":
		return true
	}
	return false
}

// decryptGCM decrypts an itemfield value: AES-256-GCM with the item key
// (key=first 32 bytes, nonce=next 12) and AAD = hex(uuid without dashes).
func decryptGCM(blob, itemKey []byte, uuid string) (string, bool) {
	if len(itemKey) < 44 || len(blob) < 16 {
		return "", false
	}
	block, err := aes.NewCipher(itemKey[:32])
	if err != nil {
		return "", false
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", false
	}
	pt, err := gcm.Open(nil, itemKey[32:44], blob, hd(uuid))
	if err != nil {
		return "", false
	}
	return string(pt), true
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func normalizeTOTP(s string) string { return strings.TrimSpace(s) }

// RunBWImport shells out to `bw import bitwardenjson <path>` using BW_SESSION.
func RunBWImport(jsonPath string) error {
	cmd := exec.Command("bw", "import", "bitwardenjson", jsonPath)
	cmd.Env = os.Environ()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
