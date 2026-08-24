package enpass2bw

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// AttachResult reports the outcome for one attachment file.
type AttachResult struct {
	File    string `json:"file"`
	Cipher  string `json:"cipher"`
	Status  string `json:"status"` // OK | NO-CIPHER | FAIL
	Detail  string `json:"detail,omitempty"`
}

const attachUsage = `attachments must be mapped to their Enpass item titles.
Run "decrypt" first: dump.json contains items[] and attachment_files[].`

// UploadAttachments walks attDir, matches each file to a cipher by comparing
// the file name against the item titles in dump.json (fuzzy: lowercase,
// trimmed), and uploads it with `bw create attachment --itemid ... --file ...`.
func UploadAttachments(dumpPath string, session string) (ok, fail, skipped int, err error) {
	raw, e := os.ReadFile(dumpPath)
	if e != nil {
		return 0, 0, 0, e
	}
	var dump VaultDump
	if e := json.Unmarshal(raw, &dump); e != nil {
		return 0, 0, 0, fmt.Errorf("invalid dump: %w", e)
	}

	env := environWithSession(session)
	bwBin, e := exec.LookPath("bw")
	if e != nil {
		return 0, 0, 0, fmt.Errorf("bw CLI not found in PATH")
	}

	// index ciphers by normalized title
	out, e := runBW(env, bwBin, "list", "items")
	if e != nil {
		return 0, 0, 0, fmt.Errorf("bw list items: %w", e)
	}
	var ciphers []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if e := json.Unmarshal([]byte(out), &ciphers); e != nil {
		return 0, 0, 0, fmt.Errorf("bw list items output: %w", e)
	}
	norm := func(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
	byTitle := map[string]string{}
	for _, c := range ciphers {
		byTitle[norm(c.Name)] = c.ID
	}

	attDir := filepath.Join(filepath.Dir(dumpPath), "attachments")
	for _, ai := range dump.Attachments {
		base := ai.File
		path := filepath.Join(attDir, base)
		if _, e := os.Stat(path); e != nil {
			fmt.Printf("FAIL  %-45s file missing: %v\n", base, e)
			fail++
			continue
		}
		title := ai.ItemTitle
		cid, known := byTitle[norm(title)]
		if !known {
			fmt.Printf("SKIP  %-45s no cipher named %q\n", base, title)
			skipped++
			continue
		}
		r := exec.Command(bwBin, "create", "attachment", "--itemid", cid, "--file", path)
		r.Env = env
		if e := r.Run(); e != nil {
			fmt.Printf("FAIL  %-45s -> %s: %v\n", base, title, e)
			fail++
			continue
		}
		fmt.Printf("OK    %-45s -> %s\n", base, title)
		ok++
	}
	return ok, fail, skipped, nil
}

func strings_TrimExt(s string) string {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '.' {
			if i > 0 {
				return s[:i]
			}
			break
		}
	}
	return s
}

func environWithSession(session string) []string {
	env := os.Environ()
	filtered := env[:0]
	for _, kv := range env {
		if strings.HasPrefix(kv, "BW_SESSION=") {
			continue
		}
		filtered = append(filtered, kv)
	}
	return append(filtered, "BW_SESSION="+session, "BW_NOINTERACTION=true")
}

func runBW(env []string, args ...string) (string, error) {
	c := exec.Command(args[0], args[1:]...)
	c.Env = env
	b, e := c.Output()
	if e != nil {
		return "", e
	}
	return strings.TrimSpace(string(b)), nil
}
