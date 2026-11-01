package esp

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// serialPatterns 汇总常见 USB 串口设备路径；Termux 下优先匹配 ttyUSB 与 ttyACM。
var serialPatterns = []string{
	"/dev/ttyUSB*",
	"/dev/ttyACM*",
	"/dev/ttyCH343USB*",
	"/dev/ttyXRUSB*",
	"/dev/ttyHS*",
	"/dev/cu.usbserial*",
	"/dev/cu.SLAB_USBtoUART*",
	"/dev/cu.wchusbserial*",
	"/dev/tty.usbserial*",
}

// serialPort 抽象串口的最小能力，便于 Linux 实现与测试替身互换。
type serialPort interface {
	Read(buffer []byte) (int, error)
	Write(buffer []byte) (int, error)
	Close() error
	SetReadDeadline(deadline time.Time) error
	SetDTR(value bool) error
	SetRTS(value bool) error
	FlushInput() error
}

/*
Ports 枚举当前系统上的候选 USB 串口设备。
只返回字符设备，避免把普通文件误判为串口。

参数:
  - 无。

返回:
  - []string: 去重并按字典序排列的设备路径。
  - error: 枚举过程发生不可恢复错误时返回错误。
*/
func Ports() ([]string, error) {
	seen := make(map[string]struct{}, 8)
	result := make([]string, 0, 8)

	for _, pattern := range serialPatterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		for _, match := range matches {
			info, err := os.Stat(match)
			if err != nil || info.Mode()&os.ModeCharDevice == 0 {
				continue
			}
			if _, exists := seen[match]; exists {
				continue
			}
			seen[match] = struct{}{}
			result = append(result, match)
		}
	}

	sort.Strings(result)
	return result, nil
}

/*
DefaultPort 自动选择唯一的 USB 串口设备。
发现多个设备时返回可操作的中文错误，要求操作员显式指定端口。

参数:
  - 无。

返回:
  - string: 串口设备路径。
  - error: 未发现设备或存在多个候选时返回错误。
*/
func DefaultPort() (string, error) {
	ports, err := Ports()
	if err != nil {
		return "", err
	}

	switch len(ports) {
	case 0:
		return "", errors.New("未发现 USB 串口设备；请确认 ESP 开发板已插入（驱动：CH340/CP2102），或使用 set PORT /dev/ttyUSB0 指定")
	case 1:
		return ports[0], nil
	default:
		return "", fmt.Errorf("发现多个 USB 串口设备 %s；请使用 set PORT <设备> 指定", strings.Join(ports, "、"))
	}
}
