package logger

import (
	"fmt"
	"log"
	"os"
)

type LogLevel int

const (
	DebugLevel LogLevel = iota
	InfoLevel
	WarningLevel
	ErrorLevel
)

type Logger struct {
	debug   *log.Logger
	info    *log.Logger
	warning *log.Logger
	error   *log.Logger
}

var l *Logger

func NewLogger() {
	l = &Logger{
		debug:   log.New(os.Stdout, "DEBUG: ", log.Ldate|log.Ltime|log.Lshortfile),
		info:    log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile),
		warning: log.New(os.Stdout, "WARNING: ", log.Ldate|log.Ltime|log.Lshortfile),
		error:   log.New(os.Stdout, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile),
	}
}

func Debug(format string, v ...interface{}) {
	l.debug.Output(2, fmt.Sprintf(format, v...))
}

func Info(format string, v ...interface{}) {
	l.info.Output(2, fmt.Sprintf(format, v...))
}

func Warning(format string, v ...interface{}) {
	l.warning.Output(2, fmt.Sprintf(format, v...))
}

func Error(format string, v ...interface{}) {
	l.error.Output(2, fmt.Sprintf(format, v...))
}

func Fatal(format string, v ...interface{}) {
	l.error.Fatalf(format, v)
}
