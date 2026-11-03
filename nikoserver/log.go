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
type Logger struct {
	level int
	out   *log.Logger
	w     io.Writer
}

func NewLogger(level string, w io.Writer) *Logger {
	if w == nil {
		w = os.Stderr
	}
	l := &Logger{out: log.New(w, "", 0), w: w}
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
	if level >= l.level {
		l.out.Print(tag + " " + fmt.Sprintf(format, args...))
	}
}

func (l *Logger) Debugf(format string, args ...any) { l.logf(0, "DEBUG", format, args...) }
func (l *Logger) Infof(format string, args ...any)  { l.logf(1, "INFO", format, args...) }
func (l *Logger) Warnf(format string, args ...any)  { l.logf(2, "WARN", format, args...) }
func (l *Logger) Errorf(format string, args ...any) { l.logf(3, "ERROR", format, args...) }

// Writer is where an embedded protocol may log.
func (l *Logger) Writer() io.Writer { return l.w }
