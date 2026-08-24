package enpass2bw

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"time"
)

// Fido2Credential mirrors Bitwarden's cipher.login.fido2Credentials[] entry.
type Fido2Credential struct {
	CredentialID string `json:"credentialId"` // "b64." + base64(raw bytes)
	KeyType      string `json:"keyType"`      // "public-key"
	KeyAlgorithm string `json:"keyAlgorithm"` // MUST be "ECDSA" (WebCrypto), not "ES256" (COSE)
	KeyCurve     string `json:"keyCurve"`     // "P-256"
	KeyValue     string `json:"keyValue"`     // base64(PKCS8 DER)
	RpID         string `json:"rpId"`
	UserHandle   string `json:"userHandle"`
	UserName     string `json:"userName,omitempty"`
	Counter      string `json:"counter"`
	Discoverable string `json:"discoverable"`
	CreationDate string `json:"creationDate"` // ISO8601 Z
}

// b64FromB64URL converts Enpass's base64url text to standard base64.
func b64FromB64URL(s string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		raw, err = base64.URLEncoding.DecodeString(s)
		if err != nil {
			return "", err
		}
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// pemToPKCS8B64 converts a SEC1/PKCS8 EC private key PEM into base64 PKCS8 DER.
func pemToPKCS8B64(pemStr string) (string, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return "", fmt.Errorf("no PEM block found")
	}
	switch block.Type {
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return "", err
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return "", err
		}
		return base64.StdEncoding.EncodeToString(der), nil
	case "PRIVATE KEY":
		if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			return "", err
		}
		return base64.StdEncoding.EncodeToString(block.Bytes), nil
	default:
		return "", fmt.Errorf("unexpected PEM type %q", block.Type)
	}
}

// BuildFido2Credential converts one decrypted Enpass passkey into the
// Bitwarden fido2Credentials entry.
func BuildFido2Credential(pk PasskeyRecord) (*Fido2Credential, error) {
	kv, err := pemToPKCS8B64(pk.Pem)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", pk.RPID, err)
	}
	cid, err := b64FromB64URL(pk.CredentialID)
	if err != nil {
		return nil, fmt.Errorf("%s: credentialId: %w", pk.RPID, err)
	}
	uh, err := b64FromB64URL(pk.UserHandle)
	if err != nil {
		uh = base64.StdEncoding.EncodeToString([]byte(pk.UserHandle))
	}
	return &Fido2Credential{
		CredentialID: "b64." + cid,
		KeyType:      "public-key",
		KeyAlgorithm: "ECDSA",
		KeyCurve:     "P-256",
		KeyValue:     kv,
		RpID:         pk.RPID,
		UserHandle:   uh,
		UserName:     pk.UserDisplayName,
		Counter:      "0",
		Discoverable: "true",
		CreationDate: time.Unix(pk.CreatedAt, 0).UTC().Format("2006-01-02T15:04:05.000Z"),
	}, nil
}

// ConvertedPasskeys is the output of ConvertPasskeys: per-item-uuid credentials
// plus the count for reporting.
type ConvertedPasskeys struct {
	ByItem map[string][]*Fido2Credential `json:"byItem"`
	Count  int                           `json:"-"`
	Skipped int                          `json:"skipped"`
}

// ConvertPasskeys converts every passkey in a dump. Never fails on individual
// bad records — those are counted in Skipped and reported on stderr.
func ConvertPasskeys(dump *VaultDump) (*ConvertedPasskeys, error) {
	res := &ConvertedPasskeys{ByItem: map[string][]*Fido2Credential{}}
	for _, pk := range dump.Passkeys {
		cred, err := BuildFido2Credential(pk)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skip: %v\n", err)
			res.Skipped++
			continue
		}
		res.ByItem[pk.ItemUUID] = append(res.ByItem[pk.ItemUUID], cred)
		res.Count++
	}
	return res, nil
}

// ConvertPasskeysFile loads a dump.json from disk and converts it.
func ConvertPasskeysFile(dumpPath string) (*ConvertedPasskeys, error) {
	raw, err := os.ReadFile(dumpPath)
	if err != nil {
		return nil, err
	}
	var dump VaultDump
	if err := json.Unmarshal(raw, &dump); err != nil {
		return nil, fmt.Errorf("invalid dump file: %w", err)
	}
	return ConvertPasskeys(&dump)
}
