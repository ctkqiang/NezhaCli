//go:build !linux

package esp

import "fmt"

/*
openSerialPort 在非 Linux 平台返回明确的不可用错误。
目标运行环境为 Termux/Linux ARM64；macOS 与 Windows 不在本轮承诺范围内。

参数:
  - path (string): 串口设备路径。

返回:
  - serialPort: 始终为 nil。
  - error: 始终返回平台不支持错误。
*/
func openSerialPort(path string) (serialPort, error) {
	return nil, fmt.Errorf("当前平台不提供原生串口驱动，无法打开 %s；请使用 Linux/Termux 构建", path)
}
