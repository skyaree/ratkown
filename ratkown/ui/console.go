//go:build !windows

package ui

import (
	"os"
	"strconv"
)

func InitConsole() {}

func tuiIsTTY() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func tuiTermSize() (int, int) {
	w, h := 120, 40
	if v, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && v > 40 {
		w = v
	}
	if v, err := strconv.Atoi(os.Getenv("LINES")); err == nil && v > 16 {
		h = v
	}
	return w, h
}

func tuiConsoleUTF8() bool {
	return true
}
