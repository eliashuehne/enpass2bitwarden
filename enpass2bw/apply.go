package enpass2bw

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// PasskeyApplyResult reports the outcome for one passkey.
type PasskeyApplyResult struct {
	RP     string `json:"rp"`
	Item   string `json:"item"`
	Status string `json:"status"` // updated | already-present | no-cipher | error
	Error  string `json:"error,omitempty"`
}

func bwEnv(session string) []string {
	env := append(os.Environ(), "BW_NOINTERACTION=true")
	if session != "" {
		env = append(env, "BW_SESSION="+session)
	}
	return env
}

func bwRun(env []string, args ...string) (string, string, error) {
	cmd := exec.Command("bw", args...)
	cmd.Env = env
	var out, errb strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	return out.String(), errb.String(), err
}

// ApplyPasskeys attaches converted fido2Credentials to their matching Bitwarden
// ciphers via the bw CLI. Cipher matching uses the Enpass item title recorded in
// dump.json (same ground truth as the attachment uploader).
// session is the BW_SESSION key; empty inherits from the environment.
func ApplyPasskeys(dumpPath, session string) ([]PasskeyApplyResult, int, error) {
	data, err := os.ReadFile(dumpPath)
	if err != nil {
		return nil, 0, err
	}
	var dump VaultDump
	if err := json.Unmarshal(data, &dump); err != nil {
		return nil, 0, fmt.Errorf("invalid dump: %w", err)
	}
	creds, err := ConvertPasskeys(&dump)
	if err != nil {
		return nil, 0, err
	}
	uuidTitle := map[string]string{}
	for _, it := range dump.Items {
		uuidTitle[it.UUID] = it.Title
	}

	env := bwEnv(session)

	itemsJSON, errS, err := bwRun(env, "list", "items")
	if err != nil {
		return nil, 0, fmt.Errorf("bw list items failed: %s", strings.TrimSpace(errS))
	}
	var items []map[string]any
	if err := json.Unmarshal([]byte(itemsJSON), &items); err != nil {
		return nil, 0, err
	}

	byTitle := map[string]map[string]any{}
	for _, it := range items {
		if name, ok := it["name"].(string); ok {
			byTitle[strings.ToLower(name)] = it
		}
	}

	findCipher := func(rp string) (map[string]any, bool) {
		if c, ok := byTitle[strings.ToLower(rp)]; ok {
			return c, true
		}
		parts := strings.Split(rp, ".")
		for _, p := range parts {
			if c, ok := byTitle[p]; ok {
				return c, true
			}
			if len(p) > 0 {
				up := strings.ToUpper(p[:1]) + p[1:]
				if c, ok := byTitle[up]; ok {
					return c, true
				}
			}
		}
		return nil, false
	}

	results := make([]PasskeyApplyResult, 0, len(creds.ByItem))
	okCount := 0

	for itemUUID, arr := range creds.ByItem {
		rp := uuidTitle[itemUUID]
		if rp == "" {
			rp = itemUUID
		}
		for _, cred := range arr {
			res := PasskeyApplyResult{RP: rp}

			cipher, found := findCipher(rp)
			if !found {
				res.Status = "no-cipher"
				res.Item = rp
				results = append(results, res)
				continue
			}
			name, _ := cipher["name"].(string)
			id, _ := cipher["id"].(string)
			res.Item = name

			login, _ := cipher["login"].(map[string]any)
			existing, _ := login["fido2Credentials"].([]any)
			already := false
			for _, e := range existing {
				em, ok := e.(map[string]any)
				if ok && em["credentialId"] == cred.CredentialID {
					already = true
					break
				}
			}
			if already {
				res.Status = "already-present"
				results = append(results, res)
				continue
			}

			login["fido2Credentials"] = append(existing, cred)
			cipher["login"] = login

			payload, mErr := json.Marshal(cipher)
			if mErr != nil {
				res.Status = "error"
				res.Error = mErr.Error()
				results = append(results, res)
				continue
			}
			cmd := exec.Command("bw", "encode")
			cmd.Env = env
			cmd.Stdin = strings.NewReader(string(payload))
			encoded, encErr := cmd.Output()
			if encErr != nil {
				res.Status = "error"
				res.Error = encErr.Error()
				results = append(results, res)
				continue
			}

			_, editErrS, editErr := bwRun(env, "edit", "item", id, string(encoded))
			if editErr != nil && !strings.Contains(editErrS, "out of date") {
				res.Status = "error"
				res.Error = strings.TrimSpace(editErrS)
				results = append(results, res)
				continue
			}
			if editErr != nil { // stale client: sync + retry once
				bwRun(env, "sync")
				listOut, _, listErr := bwRun(env, "list", "items")
				if listErr == nil {
					var fresh []map[string]any
					if json.Unmarshal([]byte(listOut), &fresh) == nil {
						for _, it := range fresh {
							if it["id"] == id {
								cipher = it
							}
						}
					}
					lg, _ := cipher["login"].(map[string]any)
					ex2, _ := lg["fido2Credentials"].([]any)
					dup := false
					for _, e := range ex2 {
						em, _ := e.(map[string]any)
						if em["credentialId"] == cred.CredentialID {
							dup = true
							break
						}
					}
					if !dup {
						lg["fido2Credentials"] = append(ex2, cred)
						cipher["login"] = lg
						pl2, _ := json.Marshal(cipher)
						c2 := exec.Command("bw", "encode")
						c2.Env = env
						c2.Stdin = strings.NewReader(string(pl2))
						enc2, ee := c2.Output()
						if ee == nil {
							_, es2, e2 := bwRun(env, "edit", "item", id, string(enc2))
							if e2 == nil {
								res.Status = "updated"
								okCount++
								results = append(results, res)
								break
							}
							res.Error = strings.TrimSpace(es2)
						}
					} else {
						res.Status = "already-present"
						results = append(results, res)
						break
					}
				}
				res.Status = "error"
				results = append(results, res)
				continue
			}
			res.Status = "updated"
			okCount++
			results = append(results, res)
		}
	}
	return results, okCount, nil
}
