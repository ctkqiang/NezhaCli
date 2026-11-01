package structure

import (
	"fmt"
	"os"
	"strings"
)

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
		moduleColor := palette.Yellow
		if strings.TrimSpace(c.selected.Meta.Impact) != "" {
			moduleColor = palette.Bold + palette.Red
		}
		return prefix + paint(c.color, palette.Gray, " (") +
			paint(c.color, moduleColor, c.selected.Meta.Name) +
			paint(c.color, palette.Gray, ") > ")
	}
	return prefix + paint(c.color, palette.Gray, " > ")
}

/*
promptHelp 输出启动后的快速上手提示，引导操作员三步完成一次任务。

参数:
  - 无。

返回:
  - 无。
*/
func (c *Console) promptHelp() {
	fmt.Fprintf(c.out, "%s%s\n",
		paint(c.color, palette.Bold+palette.White, "三步上手："),
		paint(c.color, palette.Gray, "所有能力都已内置，无需安装任何外部工具"),
	)
	fmt.Fprintf(c.out, "  %s %s\n",
		paint(c.color, palette.Cyan, "show modules"),
		paint(c.color, palette.Gray, "查看全部内置能力（按类别分组）"),
	)
	fmt.Fprintf(c.out, "  %s %s\n",
		paint(c.color, palette.Cyan, "use <序号|名称>"),
		paint(c.color, palette.Gray, "选中模块"),
	)
	fmt.Fprintf(c.out, "  %s %s\n",
		paint(c.color, palette.Cyan, "set <参数> <值>"),
		paint(c.color, palette.Gray, "配置参数（红色必填项必须设置）"),
	)
	fmt.Fprintf(c.out, "  %s %s\n",
		paint(c.color, palette.Green, "run"),
		paint(c.color, palette.Gray, "执行；红色影响模块需输入 yes 确认授权"),
	)
}

/*
readCommand 读取一条命令；输入流关闭时返回 io.EOF。
交互模式且标准输入为终端时走原始模式行编辑器，支持历史与光标编辑；
其余输入源退化为整行读取。

参数:
  - 无。

返回:
  - string: 命令行。
  - error: 输入流关闭或读取失败时返回错误。
*/
func (c *Console) readCommand() (string, error) {
	if c.raw {
		return c.editor.ReadLine(os.Stdin, c.out, c.promptText())
	}
	return c.editor.ReadLine(c.reader, c.out, c.promptText())
}
