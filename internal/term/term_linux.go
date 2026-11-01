//go:build linux

// Linux 平台终端原始模式实现：TCGETS/TCSETS 与内核 termios 结构。
package term

import (
	"fmt"
	"syscall"
	"unsafe"
)

// linuxTermios 镜像 Linux 内核 struct termios 布局。
// Cc 使用 32 字节宽松数组，避免跨架构 NCCS 差异导致越界。
type linuxTermios struct {
	Iflag  uint32
	Oflag  uint32
	Cflag  uint32
	Lflag  uint32
	Line   uint8
	Cc     [32]uint8
	Ispeed uint32
	Ospeed uint32
}

/*
makeRaw 读取当前终端属性，关闭回显、行缓冲与扩展输入处理，
保持 ISIG 开启让 Ctrl+C 仍能产生 SIGINT 取消运行中的模块。

参数:
  - fd (uintptr): 终端文件描述符。

返回:
  - func(): 恢复函数。
  - error: ioctl 失败时返回错误。
*/
func makeRaw(fd uintptr) (func(), error) {
	var state linuxTermios
	if err := getTermios(fd, &state); err != nil {
		return nil, fmt.Errorf("读取终端属性失败: %w", err)
	}

	raw := state
	raw.Iflag &^= syscall.IGNBRK | syscall.BRKINT | syscall.PARMRK | syscall.ISTRIP | syscall.INLCR | syscall.IGNCR | syscall.ICRNL | syscall.IXON
	raw.Oflag &^= syscall.OPOST
	raw.Lflag &^= syscall.ECHO | syscall.ECHONL | syscall.ICANON | syscall.IEXTEN
	raw.Cflag &^= syscall.CSIZE | syscall.PARENB
	raw.Cflag |= syscall.CS8
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
getTermios 通过 ioctl TCGETS 读取终端属性。

参数:
  - fd (uintptr): 终端文件描述符。
  - settings (*linuxTermios): 属性输出目标。

返回:
  - error: ioctl 失败时返回错误。
*/
func getTermios(fd uintptr, settings *linuxTermios) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TCGETS, uintptr(unsafe.Pointer(settings)))
	if errno != 0 {
		return errno
	}
	return nil
}

/*
setTermios 通过 ioctl TCSETS 写入终端属性。

参数:
  - fd (uintptr): 终端文件描述符。
  - settings (*linuxTermios): 待写入属性。

返回:
  - error: ioctl 失败时返回错误。
*/
func setTermios(fd uintptr, settings *linuxTermios) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TCSETS, uintptr(unsafe.Pointer(settings)))
	if errno != 0 {
		return errno
	}
	return nil
}
