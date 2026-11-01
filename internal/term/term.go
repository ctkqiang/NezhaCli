// term 包提供终端原始模式的纯 Go 实现，供行编辑器与交互式控制台使用。
// 只依赖各平台 syscall，不引入第三方库；不支持平台明确报错。
package term

/*
MakeRaw 把文件描述符对应的终端切换为原始模式，并返回恢复函数。
恢复函数必须用 defer 调用，进程退出前还原终端，避免残留脏状态。

参数:
  - fd (uintptr): 终端文件描述符，例如 os.Stdin.Fd()。

返回:
  - func(): 恢复原始设置的函数。
  - error: 非终端或不支持平台时返回错误。
*/
func MakeRaw(fd uintptr) (func(), error) {
	return makeRaw(fd)
}
