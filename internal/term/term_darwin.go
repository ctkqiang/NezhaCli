//go:build darwin

// macOS 平台终端原始模式实现：TIOCGETA/TIOCSETA 与 BSD termios 结构。
package term

import (
	"fmt"
	"syscall"
	"unsafe"
)

// darwinTermios 镜像 macOS struct termios 布局，tcflag_t 为 64 位。
type darwinTermios struct {
	Iflag  uint64
	Oflag  uint64
	Cflag  uint64
	Lflag  uint64
	Cc     [20]uint8
	Ispeed uint64
	Ospeed uint64
}

/*
makeRaw 读取当前终端属性，关闭回显与行缓冲，
保持 ISIG 开启让 Ctrl+C 仍能产生 SIGINT 取消运行中的模块。

参数:
  - fd (uintptr): 终端文件描述符。

返回:
  - func(): 恢复函数。
  - error: ioctl 失败时返回错误。
*/
func makeRaw(fd uintptr) (func(), error) {
	var state darwinTermios
	if err := getTermios(fd, &state); err != nil {
		return nil, fmt.Errorf("读取终端属性失败: %w", err)
	}

	raw := state
	raw.Iflag &^= syscall.IGNBRK | syscall.BRKINT | syscall.PARMRK | syscall.ISTRIP | syscall.INLCR | syscall.IGNCR | syscall.ICRNL | syscall.IXON
	raw.Oflag &^= syscall.OPOST
	raw.Lflag &^= syscall.ECHO | syscall.ECHONL | syscall.ICANON | syscall.IEXTEN
	raw.Cc[syscall.VMIN] = 1
	raw.Cc[syscall.VTIME] = 0

	if err := setTermios(fd, &raw); err != nil {
		return nil, fmt.Errorf("设置终端属性失败: %w", err)
	}

	return func() {
		_ = setTermios(fd, &state)
	}, nil
}

/*
getTermios 通过 ioctl TIOCGETA 读取终端属性。

参数:
  - fd (uintptr): 终端文件描述符。
  - settings (*darwinTermios): 属性输出目标。

返回:
  - error: ioctl 失败时返回错误。
*/
func getTermios(fd uintptr, settings *darwinTermios) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TIOCGETA, uintptr(unsafe.Pointer(settings)))
	if errno != 0 {
		return errno
	}
	return nil
}

/*
setTermios 通过 ioctl TIOCSETA 写入终端属性。

参数:
  - fd (uintptr): 终端文件描述符。
  - settings (*darwinTermios): 待写入属性。

返回:
  - error: ioctl 失败时返回错误。
*/
func setTermios(fd uintptr, settings *darwinTermios) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TIOCSETA, uintptr(unsafe.Pointer(settings)))
	if errno != 0 {
		return errno
	}
	return nil
}
