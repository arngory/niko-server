//go:build linux

package nikoserver

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"
)

// Logger writes leveled lines to stderr (journald under systemd). Access logs are
// off by design (raycontrol decision D-12): only errors and state changes.
//
// When journald reads stderr (JOURNAL_STREAM is set), each line starts with
// its syslog priority: journald takes a leading "<N>" as the line's priority
// (SyslogLevelPrefix=, on by default), and without it every line is info and
// journalctl -p warning shows none of the warnings.
type Logger struct {
	level   int
	out     *log.Logger
	w       io.Writer
	journal bool
}

// Priorities of journald (syslog) by level: debug, info, warning, err.
var journalPrefixes = [4]string{"<7>", "<6>", "<4>", "<3>"}

// lineBreaks keeps one record on one line: a value with a line break could
// otherwise start a line of its own, priority prefix included.
var lineBreaks = strings.NewReplacer("\n", `\n`, "\r", `\r`)

func NewLogger(level string, w io.Writer) *Logger {
	journal := false
	if w == nil {
		w = os.Stderr
		journal = os.Getenv("JOURNAL_STREAM") != ""
	}
	l := &Logger{out: log.New(w, "", 0), w: w, journal: journal}
	switch strings.ToLower(level) {
	case "debug":
		l.level = 0
	case "info":
		l.level = 1
	case "", "warn":
		l.level = 2
	default:
		l.level = 3
	}
	return l
}

func (l *Logger) logf(level int, tag, format string, args ...any) {
	if level < l.level {
		return
	}
	line := tag + " " + lineBreaks.Replace(fmt.Sprintf(format, args...))
	if l.journal {
		line = journalPrefixes[level] + line
	}
	l.out.Print(line)
}

func (l *Logger) Debugf(format string, args ...any) { l.logf(0, "DEBUG", format, args...) }
func (l *Logger) Infof(format string, args ...any)  { l.logf(1, "INFO", format, args...) }
func (l *Logger) Warnf(format string, args ...any)  { l.logf(2, "WARN", format, args...) }
func (l *Logger) Errorf(format string, args ...any) { l.logf(3, "ERROR", format, args...) }

// Writer is where an embedded protocol may log.
func (l *Logger) Writer() io.Writer { return l.w }
