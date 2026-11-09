//go:build linux

package nikoserver

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// Under journald each line carries its priority; elsewhere none does, and a
// line break in a value never starts a line of its own.
func TestLoggerJournalPriority(t *testing.T) {
	t.Setenv("JOURNAL_STREAM", "8:1234")
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr := os.Stderr
	os.Stderr = w
	l := NewLogger("debug", nil)
	os.Stderr = stderr
	l.Debugf("d")
	l.Infof("i")
	l.Warnf("w %s", "x\n<3>ERROR forged")
	l.Errorf("e")
	w.Close()
	var out bytes.Buffer
	if _, err := out.ReadFrom(r); err != nil {
		t.Fatal(err)
	}
	want := "<7>DEBUG d\n<6>INFO i\n<4>WARN w x\\n<3>ERROR forged\n<3>ERROR e\n"
	if out.String() != want {
		t.Fatalf("journal lines:\n%q\nwant\n%q", out.String(), want)
	}

	// A writer given by the caller is not journald's stream.
	var buf bytes.Buffer
	NewLogger("warn", &buf).Warnf("plain")
	if got := buf.String(); got != "WARN plain\n" || strings.HasPrefix(got, "<") {
		t.Fatalf("plain line %q", got)
	}
	t.Setenv("JOURNAL_STREAM", "")
}
