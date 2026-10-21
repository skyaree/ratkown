//go:build windows

package ui

import (
	"syscall"
	"unsafe"
)

var (
	kernel32                    = syscall.NewLazyDLL("kernel32.dll")
	procGetConsoleMode          = kernel32.NewProc("GetConsoleMode")
	procSetConsoleMode          = kernel32.NewProc("SetConsoleMode")
	procGetStdHandle            = kernel32.NewProc("GetStdHandle")
	procGetConsoleScreenBufInfo = kernel32.NewProc("GetConsoleScreenBufferInfo")
	procGetConsoleOutputCP      = kernel32.NewProc("GetConsoleOutputCP")
)

const (
	stdOutputHandle                 = uint32(0xFFFFFFF5)
	stdErrorHandle                  = uint32(0xFFFFFFF4)
	enableVirtualTerminalProcessing = uint32(0x0004)
)

type coordStruct struct {
	X, Y int16
}

type smallRectStruct struct {
	Left, Top, Right, Bottom int16
}

type consoleScreenBufferInfo struct {
	Size              coordStruct
	CursorPosition    coordStruct
	Attributes        uint16
	Window            smallRectStruct
	MaximumWindowSize coordStruct
}

func InitConsole() {
	for _, stdHandleID := range []uint32{stdOutputHandle, stdErrorHandle} {
		handle, _, _ := procGetStdHandle.Call(uintptr(stdHandleID))
		if handle == 0 || handle == uintptr(syscall.InvalidHandle) {
			continue
		}
		var mode uint32
		r, _, _ := procGetConsoleMode.Call(handle, uintptr(unsafe.Pointer(&mode)))
		if r != 0 {
			procSetConsoleMode.Call(handle, uintptr(mode|enableVirtualTerminalProcessing))
		}
	}
}

func tuiIsTTY() bool {
	handle, _, _ := procGetStdHandle.Call(uintptr(stdOutputHandle))
	if handle == 0 || handle == uintptr(syscall.InvalidHandle) {
		return false
	}
	var mode uint32
	r, _, _ := procGetConsoleMode.Call(handle, uintptr(unsafe.Pointer(&mode)))
	return r != 0
}

func tuiTermSize() (int, int) {
	handle, _, _ := procGetStdHandle.Call(uintptr(stdOutputHandle))
	var csbi consoleScreenBufferInfo
	r, _, _ := procGetConsoleScreenBufInfo.Call(handle, uintptr(unsafe.Pointer(&csbi)))
	if r == 0 {
		return 120, 40
	}
	w := int(csbi.Window.Right-csbi.Window.Left) + 1
	h := int(csbi.Window.Bottom-csbi.Window.Top) + 1
	if w < 40 {
		w = 40
	}
	if h < 16 {
		h = 16
	}
	return w, h
}

func tuiConsoleUTF8() bool {
	cp, _, _ := procGetConsoleOutputCP.Call()
	return cp == 65001
}
