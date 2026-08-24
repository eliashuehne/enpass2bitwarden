// Package enpass2bw — logging helpers.
//
// Progress messages go to stdout; warnings and debug traces go to stderr.
// With --log-file set, everything (stdout + stderr) is mirrored to the file
// with timestamps, giving users an audit trail of the migration.
package enpass2bw

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

var (
	logFile io.Writer // nil unless LogOpen was called
	Verbose bool
)

// LogOpen opens <dir>/enpass2bitwarden.log for mirroring all output.
func LogOpen(dir string) error {
	if dir == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, "enpass2bitwarden.log"),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	logFile = f
	return nil
}

// LogClose flushes and closes the log file.
func LogClose() {
	if f, ok := logFile.(*os.File); ok && f != nil {
		f.Sync()
		f.Close()
	}
	logFile = nil
}

func stamp() string { return time.Now().UTC().Format("2006-01-02T15:04:05Z") }

// Info prints a progress line to stdout (and mirrors it to the log file).
func Info(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	fmt.Println(msg)
	mirror(msg + "\n")
}

// Warn prints a warning to stderr (and mirrors it).
func Warn(format string, a ...any) {
	msg := "warn: " + fmt.Sprintf(format, a...)
	fmt.Fprintln(os.Stderr, msg)
	mirror(msg + "\n")
}

// Debug prints extra detail only with --verbose.
func Debug(format string, a ...any) {
	if !Verbose {
		return
	}
	msg := "debug: " + fmt.Sprintf(format, a...)
	fmt.Fprintln(os.Stderr, msg)
	mirror(msg + "\n")
}

func mirror(s string) {
	if logFile != nil {
		fmt.Fprintf(logFile, "%s %s", stamp(), s)
	}
}
