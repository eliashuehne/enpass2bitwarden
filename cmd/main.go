package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/eliashuehne/enpass2bitwarden/enpass2bw"
)

var version = "dev"

var (
	logPath     string
	logFlagNext bool
)

const usage = `enpass2bitwarden — migrate an Enpass v6 vault to Bitwarden/Vaultwarden

Quick start (2 commands):
  enpass2bitwarden migrate ~/vault-backup.enpassbackup ./out
  enpass2bitwarden import ~/vault-backup.enpassbackup

Commands:
  decrypt   Decrypt vault or .enpassbackup: items, passkeys, attachments -> out dir
  passkeys  Emit Bitwarden-ready fido2Credentials JSON from a dump
  apply     Attach converted passkeys to matching ciphers via bw (needs BW_SESSION)
  attach    Upload extracted attachments to matching ciphers via bw
  migrate   Full migration from a vault file OR a .enpassbackup file (recommended)
  check     Verify prerequisites and vault/backup file
  help      Show this help

Flags:
  --version          Print version
  --verbose, -v      Extra detail (per-item traces)
  --log-file <path>  Mirror all output to a timestamped log file

Environment:
  ENPASS_MASTER_PW   Master password (prompted if unset)
  BW_SESSION         Bitwarden CLI session key (required for attach/migrate)

Docs: https://github.com/eliashuehne/enpass2bitwarden#readme`

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		fmt.Print(usage)
		os.Exit(0)
	}

	// global flags
	var rest []string
	for _, a := range args {
		if a == "--verbose" || a == "-v" {
			enpass2bw.Verbose = true
			continue
		}
		if strings.HasPrefix(a, "--log-file=") {
			logPath = strings.TrimPrefix(a, "--log-file=")
			continue
		}
		if a == "--log-file" {
			logFlagNext = true
			continue
		}
		if logFlagNext {
			logPath = a
			logFlagNext = false
			continue
		}
		rest = append(rest, a)
	}
	args = rest
	for _, a := range args {
		if a == "--version" || a == "version" {
			fmt.Println("enpass2bitwarden", version)
			return
		}
	}

	cmd := args[0]
	args = args[1:]

	if logPath != "" {
		if err := enpass2bw.LogOpen(logPath); err != nil {
			fmt.Fprintln(os.Stderr, "warn: cannot open log file:", err)
		} else {
			defer enpass2bw.LogClose()
			enpass2bw.Info("logging to %s", logPath)
		}
	}

	var err error
	switch cmd {
	case "decrypt":
		err = runDecrypt(args)
	case "passkeys":
		err = runPasskeys(args)
	case "attach":
		err = runAttach(args)
	case "passkeys-apply", "apply":
		err = runPasskeysApply(args)
	case "migrate":
		err = runMigrate(args)
	case "import":
		err = runImport(args)
	case "check":
		err = runCheck(args)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		fmt.Print(usage)
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		fmt.Fprintln(os.Stderr, "\nSee docs/TROUBLESHOOTING.md for common failures.")
		os.Exit(1)
	}
}

func runDecrypt(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: enpass2bitwarden decrypt <vault.enpassdb> <outdir>")
	}
	pw, err := readMasterPassword()
	if err != nil {
		return err
	}
	fmt.Println("Decrypting vault (items, passkeys, attachments)...")
	dumpPath, stats, err := enpass2bw.DecryptVault(args[0], args[1], pw)
	if err != nil {
		return err
	}
	fmt.Printf("\n✔ %d items | %d passkeys | %d attachments extracted\n", stats.Items, stats.Passkeys, stats.Attachments)
	fmt.Printf("✔ dump written to %s\n", dumpPath)
	fmt.Printf("✔ attachment files in %s/attachments/\n", args[1])
	fmt.Println("\nNext steps:")
	fmt.Println("  1. bw import enpassjson <your-enpass-export.json>   # passwords/TOTP/cards")
	fmt.Printf("  2. enpass2bitwarden passkeys %s > passkeys.json\n", dumpPath)
	fmt.Printf("  3. enpass2bitwarden attach %s\n", args[1])
	return nil
}

func runPasskeys(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: enpass2bitwarden passkeys <outdir>/dump.json")
	}
	data, err := os.ReadFile(args[0])
	if err != nil {
		return err
	}
	var dump enpass2bw.VaultDump
	if err := json.Unmarshal(data, &dump); err != nil {
		return fmt.Errorf("invalid dump file: %w", err)
	}
	res, err := enpass2bw.ConvertPasskeys(&dump)
	if err != nil {
		return err
	}
	enc, _ := json.MarshalIndent(res.ByItem, "", "  ")
	fmt.Println(string(enc))
	fmt.Fprintf(os.Stderr, "✔ %d passkey credentials converted (%d skipped)\n", res.Count, res.Skipped)
	fmt.Fprintln(os.Stderr, "Apply each to its login item via the web vault, or script with:")
	fmt.Fprintln(os.Stderr, "  bw encode < cred.json | bw edit item <itemId>")
	return nil
}

func runAttach(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: enpass2bitwarden attach <outdir-or-dump.json>")
	}
	session := os.Getenv("BW_SESSION")
	if session == "" {
		return fmt.Errorf("BW_SESSION not set — run: export BW_SESSION=$(bw unlock --raw)")
	}
	dumpPath := args[0]
	if fi, e := os.Stat(dumpPath); e == nil && fi.IsDir() {
		dumpPath = filepath.Join(dumpPath, "dump.json")
	}
	fmt.Println("Uploading attachments to matching ciphers via bw...")
	ok, fail, skipped, err := enpass2bw.UploadAttachments(dumpPath, session)
	if err != nil {
		return err
	}
	fmt.Printf("\n✔ uploaded: %d | skipped (no matching cipher): %d | failed: %d\n", ok, skipped, fail)
	if fail > 0 {
		return fmt.Errorf("%d attachment uploads failed — see output above", fail)
	}
	return nil
}

func runMigrate(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: enpass2bitwarden migrate <vault.enpassdb | backup.enpassbackup> <outdir>")
	}
	pw, err := readMasterPassword()
	if err != nil {
		return err
	}
	session := os.Getenv("BW_SESSION")

	fmt.Println("[1/5] Decrypting vault...")
	dumpPath, stats, err := enpass2bw.DecryptVault(args[0], args[1], pw)
	if err != nil {
		return err
	}
	fmt.Printf("    ✔ %d items | %d passkeys | %d attachments\n", stats.Items, stats.Passkeys, stats.Attachments)

	fmt.Println("[2/5] Converting passkeys to Bitwarden format...")
	dumpData, err := os.ReadFile(dumpPath)
	if err != nil {
		return err
	}
	var dump enpass2bw.VaultDump
	if err := json.Unmarshal(dumpData, &dump); err != nil {
		return fmt.Errorf("invalid dump: %w", err)
	}
	res, err := enpass2bw.ConvertPasskeys(&dump)
	if err != nil {
		return err
	}
	enc, _ := json.MarshalIndent(res.ByItem, "", "  ")
	pkFile := strings.TrimSuffix(dumpPath, ".json") + "-fido2.json"
	if err := os.WriteFile(pkFile, enc, 0600); err != nil {
		return err
	}
	fmt.Printf("    ✔ wrote %s\n", pkFile)

	// step 3: passwords/TOTP via bw import
	bwj := filepath.Join(args[1], "bitwarden.json")
	n, e := enpass2bw.BuildBitwardenJSON(args[0], pw, bwj)
	if e != nil {
		return e
	}
	fmt.Printf("    ✔ %d items → %s\n", n, filepath.Base(bwj))
	if session == "" {
		fmt.Println("[3/5] Skipping password import (BW_SESSION not set).")
	} else {
		fmt.Println("[3/5] Importing passwords/TOTP into Bitwarden...")
		if err := enpass2bw.RunBWImport(bwj); err != nil {
			return err
		}
	}

	if session == "" {
		fmt.Println("[4/4] Skipping attachment upload (BW_SESSION not set).")
	} else {
		fmt.Println("[4/5] Uploading attachments...")
		ok, fail, skipped, err := enpass2bw.UploadAttachments(dumpPath, session)
		if err != nil {
			return err
		}
		fmt.Printf("    ✔ uploaded: %d | skipped: %d | failed: %d\n", ok, skipped, fail)

		fmt.Println("[5/5] Attaching passkeys to their logins...")
		pkRes, pkOK, err := enpass2bw.ApplyPasskeys(dumpPath, session)
		if err != nil {
			return err
		}
		for _, r := range pkRes {
			switch r.Status {
			case "updated":
				fmt.Printf("    OK    %-40s -> %s\n", r.RP, r.Item)
			case "already-present":
				fmt.Printf("    SKIP  %-40s already attached\n", r.RP)
			case "no-cipher":
				fmt.Printf("    SKIP  %-40s no matching cipher (%q)\n", r.RP, r.Item)
			default:
				fmt.Printf("    FAIL  %-40s %s\n", r.RP, r.Error)
			}
		}
		fmt.Printf("    ✔ attached: %d | total: %d\n", pkOK, len(pkRes))
	}

	fmt.Println(`

All done. Remaining steps:
  1. Test one passkey login on a low-stakes site before relying on critical ones.
  2. Delete the output directory when satisfied — it contains decrypted secrets.`)
	return nil
}

func filepath_Base(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

func runPasskeysApply(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: enpass2bitwarden apply <outdir-or-dump.json>")
	}
	session := os.Getenv("BW_SESSION")
	if session == "" && os.Getenv("BW_PASSWORD") == "" {
		return fmt.Errorf("BW_SESSION not set — run: export BW_SESSION=$(bw unlock --raw)")
	}
	target := args[0]
	dumpPath := target
	if fi, err := os.Stat(target); err == nil && fi.IsDir() {
		dumpPath = filepath.Join(target, "dump.json")
	}
	results, ok, err := enpass2bw.ApplyPasskeys(dumpPath, session)
	if err != nil {
		return err
	}
	for _, r := range results {
		switch r.Status {
		case "updated":
			fmt.Printf("OK    %-40s -> %s\n", r.RP, r.Item)
		case "already-present":
			fmt.Printf("SKIP  %-40s already attached to %s\n", r.RP, r.Item)
		case "no-cipher":
			fmt.Printf("SKIP  %-40s no cipher named %q found\n", r.RP, r.Item)
		default:
			fmt.Printf("FAIL  %-40s %s %s\n", r.RP, r.Status, r.Error)
		}
	}
	fmt.Printf("\n✔ attached: %d | total: %d\n", ok, len(results))
	failed := 0
	for _, r := range results {
		if r.Status == "no-cipher" || r.Status == "error" {
			failed++
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d passkey(s) could not be attached — see output above", failed)
	}
	return nil
}

func runCheck(args []string) error {
	failures := 0
	check := func(name string, fn func() error) {
		e := fn()
		status := "✔"
		if e != nil {
			status = "✘"
			failures++
		}
		fmt.Printf("%s %s", status, name)
		if e != nil {
			fmt.Printf(" — %v", e)
		}
		fmt.Println()
	}
	check("bw CLI installed", func() error {
		_, e := os.Stat("/usr/local/bin/bw")
		if e != nil {
			_, e = lookPath("bw")
		}
		return e
	})
	check("BW_SESSION set", func() error {
		if os.Getenv("BW_SESSION") == "" {
			return fmt.Errorf("not set; run: export BW_SESSION=$(bw unlock --raw)")
		}
		return nil
	})
	check("vault path provided & readable", func() error {
		if len(args) < 1 {
			return fmt.Errorf("pass the vault path: enpass2bitwarden check <vault.enpassdb>")
		}
		f, e := os.Open(args[0])
		if e != nil {
			return e
		}
		f.Close()
		return nil
	})
	if failures > 0 {
		return fmt.Errorf("%d checks failed", failures)
	}
	fmt.Println("All good.")
	return nil
}

func readMasterPassword() (string, error) {
	if p := os.Getenv("ENPASS_MASTER_PW"); p != "" {
		return p, nil
	}
	fmt.Fprint(os.Stderr, "Enpass master password: ")
	r := bufio.NewReader(os.Stdin)
	s, _ := r.ReadString('\n')
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("empty master password")
	}
	return s, nil
}

// lookPath is a tiny helper so we don't import os/exec just for one check.
func lookPath(name string) (string, error) {
	for _, dir := range strings.Split(os.Getenv("PATH"), ":") {
		p := dir + "/" + name
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("bw not found in PATH — install from https://bitwarden.com/help/cli/")
}

func runImport(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: enpass2bitwarden import <vault.enpassbackup|vault.enpassdb>")
	}
	vault := args[0]
	pw, err := readMasterPassword()
	if err != nil {
		return err
	}
	tmp, e := os.MkdirTemp("", "e2b-import-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(tmp)
	jsonPath := filepath.Join(tmp, "bitwarden.json")
	fmt.Println("[1/2] Generating Bitwarden import file...")
	n, e := enpass2bw.BuildBitwardenJSON(vault, pw, jsonPath)
	if e != nil {
		return e
	}
	fmt.Printf("    ✔ %d items\n", n)
	fmt.Println("[2/2] Running bw import (this cannot be undone — make sure your vault is backed up)...")
	return enpass2bw.RunBWImport(jsonPath)
}
