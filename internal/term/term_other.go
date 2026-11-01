//go:build !linux && !darwin

// 非 Linux/macOS 平台不提供终端原始模式，行编辑器自动退化为行读取模式。
package term

import "fmt"

/*
makeRaw 在不支持的平台上返回明确错误。

参数:
  - fd (uintptr): 终端文件描述符。

返回:
  - func(): 始终为 nil。
  - error: 始终返回平台不支持错误。
*/
func makeRaw(fd uintptr) (func(), error) {
	return nil, fmt.Errorf("当前平台不提供终端原始模式，历史与光标编辑不可用")
}
