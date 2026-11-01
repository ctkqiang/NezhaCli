//go:build linux

package esp

import (
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"
)

const (
	// 串口 ioctl 请求号，取自 Linux asm-generic/ioctls.h。
	ioctlTCGETS   = 0x5401
	ioctlTCSETS   = 0x5402
	ioctlTCFLSH   = 0x540B
	ioctlTIOCMBIS = 0x5416
	ioctlTIOCMBIC = 0x5417

	// TCFLSH 的队列选择：清空输入队列。
	tcIFLUSH = 0

	// 调制解调器控制位。
	tiocmDTR = 0x002
	tiocmRTS = 0x004

	// termios 控制标志：115200 8N1、使能接收、忽略调制解调器控制线。
	baud115200 = 0x1002
	flagCS8    = 0x30
	flagCREAD  = 0x80
	flagCLOCAL = 0x800

	// termios 控制字符下标。
	controlVMIN  = 6
	controlVTIME = 5

	// Linux asm-generic termios 的 NCCS 长度，arm64 与 amd64 均适用。
	nccs = 19
)

// linuxTermios 对应内核 uapi 的 struct termios。
type linuxTermios struct {
	Iflag  uint32
	Oflag  uint32
	Cflag  uint32
	Lflag  uint32
	Line   uint8
	Cc     [nccs]uint8
	Ispeed uint32
	Ospeed uint32
}

// linuxSerialPort 使用 os.File 封装串口；文件以非阻塞方式注册到 Go 轮询器。
type linuxSerialPort struct {
	file *os.File
}

/*
openSerialPort 打开 Linux 串口并配置为 115200 8N1 原始模式。
不使用任何第三方串口库，只依赖标准库、termios 与 ioctl。

参数:
  - path (string): 串口设备路径，例如 /dev/ttyUSB0。

返回:
  - serialPort: 已配置的串口句柄。
  - error: 设备不存在、被占用或 termios 配置失败时返回错误。
*/
func openSerialPort(path string) (serialPort, error) {
	file, err := os.OpenFile(path, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, err
	}

	fd := file.Fd()
	settings, err := getTermios(fd)
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("读取串口参数失败: %w", err)
	}

	settings.Iflag = 0
	settings.Oflag = 0
	settings.Lflag = 0
	settings.Cflag = baud115200 | flagCS8 | flagCREAD | flagCLOCAL
	settings.Cc[controlVMIN] = 0
	settings.Cc[controlVTIME] = 0

	if err := setTermios(fd, &settings); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("配置串口为 115200 8N1 失败: %w", err)
	}

	return &linuxSerialPort{file: file}, nil
}

/*
getTermios 读取串口当前 termios 配置。

参数:
  - fd (uintptr): 文件描述符。

返回:
  - linuxTermios: 当前配置。
  - error: ioctl 失败时返回错误。
*/
func getTermios(fd uintptr) (linuxTermios, error) {
	var settings linuxTermios
	err := ioctlPointer(fd, ioctlTCGETS, unsafe.Pointer(&settings))
	return settings, err
}

/*
setTermios 写回串口 termios 配置。

参数:
  - fd (uintptr): 文件描述符。
  - settings (*linuxTermios): 新配置。

返回:
  - error: ioctl 失败时返回错误。
*/
func setTermios(fd uintptr, settings *linuxTermios) error {
	return ioctlPointer(fd, ioctlTCSETS, unsafe.Pointer(settings))
}

/*
ioctlPointer 执行携带指针参数的 ioctl。

参数:
  - fd (uintptr): 文件描述符。
  - request (uintptr): ioctl 请求号。
  - argument (unsafe.Pointer): 参数指针。

返回:
  - error: 系统调用返回错误时返回错误。
*/
func ioctlPointer(fd uintptr, request uintptr, argument unsafe.Pointer) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, request, uintptr(argument))
	if errno != 0 {
		return errno
	}
	return nil
}

/*
ioctlValue 执行携带整数值的 ioctl。

参数:
  - fd (uintptr): 文件描述符。
  - request (uintptr): ioctl 请求号。
  - value (uintptr): 参数值。

返回:
  - error: 系统调用返回错误时返回错误。
*/
func ioctlValue(fd uintptr, request uintptr, value uintptr) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, request, value)
	if errno != 0 {
		return errno
	}
	return nil
}

/*
Read 从串口读取字节，受 SetReadDeadline 约束。

参数:
  - buffer ([]byte): 接收缓冲区。

返回:
  - int: 读取字节数。
  - error: 读取失败或超时时返回错误。
*/
func (p *linuxSerialPort) Read(buffer []byte) (int, error) {
	return p.file.Read(buffer)
}

/*
Write 向串口写入字节。

参数:
  - buffer ([]byte): 待写入数据。

返回:
  - int: 写入字节数。
  - error: 写入失败时返回错误。
*/
func (p *linuxSerialPort) Write(buffer []byte) (int, error) {
	return p.file.Write(buffer)
}

/*
Close 关闭串口。

参数:
  - 无。

返回:
  - error: 关闭失败时返回错误。
*/
func (p *linuxSerialPort) Close() error {
	return p.file.Close()
}

/*
SetReadDeadline 设置串口读取截止时间。

参数:
  - deadline (time.Time): 绝对截止时间；零值表示取消限制。

返回:
  - error: 底层文件不支持截止时间时返回错误。
*/
func (p *linuxSerialPort) SetReadDeadline(deadline time.Time) error {
	return p.file.SetReadDeadline(deadline)
}

/*
SetDTR 控制 DTR 线电平。

参数:
  - value (bool): true 表示置位。

返回:
  - error: ioctl 失败时返回错误。
*/
func (p *linuxSerialPort) SetDTR(value bool) error {
	return setModemLine(p.file.Fd(), tiocmDTR, value)
}

/*
SetRTS 控制 RTS 线电平。

参数:
  - value (bool): true 表示置位。

返回:
  - error: ioctl 失败时返回错误。
*/
func (p *linuxSerialPort) SetRTS(value bool) error {
	return setModemLine(p.file.Fd(), tiocmRTS, value)
}

/*
setModemLine 通过 TIOCMBIS/TIOCMBIC 置位或清除调制解调器控制线。

参数:
  - fd (uintptr): 文件描述符。
  - bit (int32): TIOCM_DTR 或 TIOCM_RTS。
  - value (bool): true 表示置位。

返回:
  - error: ioctl 失败时返回错误。
*/
func setModemLine(fd uintptr, bit int32, value bool) error {
	request := uintptr(ioctlTIOCMBIS)
	if !value {
		request = ioctlTIOCMBIC
	}
	return ioctlPointer(fd, request, unsafe.Pointer(&bit))
}

/*
FlushInput 清空串口输入队列，丢弃上一次会话与启动噪声。

参数:
  - 无。

返回:
  - error: ioctl 失败时返回错误。
*/
func (p *linuxSerialPort) FlushInput() error {
	return ioctlValue(p.file.Fd(), ioctlTCFLSH, tcIFLUSH)
}
