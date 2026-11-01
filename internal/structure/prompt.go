package structure

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
)

/*
readLine 输出提示符并读取一行输入。
输入流关闭时返回 io.EOF，调用方据此结束控制台。

参数:
  - reader (*bufio.Reader): 标准输入缓冲器。
  - out (io.Writer): 提示符输出目标。
  - prompt (string): 提示符文本。

返回:
  - string: 去除首尾空白后的输入。
  - error: 读取失败或输入流关闭时返回错误。
*/
func readLine(reader *bufio.Reader, out io.Writer, prompt string) (string, error) {
	fmt.Fprint(out, prompt)
	line, err := reader.ReadString('\n')
	if err != nil && len(line) == 0 {
		return "", err
	}
	if errors.Is(err, io.EOF) {
		return strings.TrimSpace(line), io.EOF
	}
	return strings.TrimSpace(line), nil
}

/*
parseCommand 把命令行拆分为参数切片，支持双引号包裹含空格的值。
例如：set TARGET "10.0.0.0/24" 会得到三个参数。

参数:
  - line (string): 原始命令行。

返回:
  - []string: 拆分后的参数；未闭合引号按到行尾处理。
*/
func parseCommand(line string) []string {
	var (
		arguments []string
		current   strings.Builder
		quoted    bool
		hasToken  bool
	)

	for _, char := range line {
		switch {
		case char == '"':
			quoted = !quoted
			hasToken = true
		case (char == ' ' || char == '\t') && !quoted:
			if hasToken {
				arguments = append(arguments, current.String())
				current.Reset()
				hasToken = false
			}
		default:
			current.WriteRune(char)
			hasToken = true
		}
	}
	if hasToken {
		arguments = append(arguments, current.String())
	}
	return arguments
}

/*
promptText 生成当前控制台提示符。
选中模块后提示符会显示模块名，避免操作员在多模块之间误执行。

参数:
  - color (bool): 是否启用颜色。
  - module (string): 当前模块名；为空表示未选中模块。

返回:
  - string: 提示符文本。
*/
func (c *Console) promptText() string {
	prefix := paint(c.color, palette.Bold+palette.Green, "nezha")
	if c.selected != nil {
		return prefix + paint(c.color, palette.Gray, " (") +
			paint(c.color, palette.Yellow, c.selected.Meta.Name) +
			paint(c.color, palette.Gray, ") > ")
	}
	return prefix + paint(c.color, palette.Gray, " > ")
}

/*
readCommand 读取一条命令；输入流关闭时返回 io.EOF。

参数:
  - 无。

返回:
  - string: 命令行。
  - error: 输入流关闭或读取失败时返回错误。
*/
func (c *Console) readCommand() (string, error) {
	return readLine(c.reader, c.out, c.promptText())
}
