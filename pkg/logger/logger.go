package logger

import (
	"fmt"
	"os"
	"time"
)

func getTimeString() string {
	return time.Now().Format("15:04:05")
}

func Debug(format string, a ...interface{}) {
	if CurrentLevel <= LevelDebug {
		msg := fmt.Sprintf(format, a...)
		fmt.Printf("%s%s %s[·]%s %s\n", ColorGray, getTimeString(), ColorCyan, ColorReset, msg)
	}
}

func Info(format string, a ...interface{}) {
	if CurrentLevel <= LevelInfo {
		msg := fmt.Sprintf(format, a...)
		fmt.Printf("%s%s %s[+]%s %s\n", ColorGray, getTimeString(), ColorGreen, ColorReset, msg)
	}
}

func Warn(format string, a ...interface{}) {
	if CurrentLevel <= LevelWarn {
		msg := fmt.Sprintf(format, a...)
		fmt.Printf("%s%s %s[-]%s %s%s\n", ColorGray, getTimeString(), ColorYellow, ColorReset, ColorYellow, msg)
	}
}

func Error(format string, a ...interface{}) {
	if CurrentLevel <= LevelError {
		msg := fmt.Sprintf(format, a...)
		fmt.Fprintf(os.Stderr, "%s%s %s[!] %s%s\n", ColorGray, getTimeString(), ColorRed, msg, ColorReset)
	}
}

func Fatal(format string, a ...interface{}) {
	if CurrentLevel <= LevelFatal {
		msg := fmt.Sprintf(format, a...)
		fmt.Fprintf(os.Stderr, "%s%s%s %s[FATAL] %s%s\n", ColorBold, ColorGray, getTimeString(), ColorRed, msg, ColorReset)
		os.Exit(1)
	}
}

func Success(format string, a ...interface{}) {
	if CurrentLevel <= LevelInfo {
		msg := fmt.Sprintf(format, a...)
		fmt.Printf("%s%s %s[★] %s%s%s\n", ColorGray, getTimeString(), ColorBold, ColorGreen, msg, ColorReset)
	}
}
