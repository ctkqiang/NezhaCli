// modulekit 包提供内置模块共用的元数据构造函数与终端排版辅助。
package modulekit

import (
	"fmt"
	"io"

	"github.com/ctkqiang/nezha_cli/internal/model"
	"github.com/ctkqiang/nezha_cli/internal/text"
)

const (
	// CategoryRecon 是网络侦察类模块。
	CategoryRecon = "侦察"

	// CategoryWeb 是 Web 安全评估类模块。
	CategoryWeb = "Web"

	// CategoryWireless 是无线安全类模块。
	CategoryWireless = "无线"

	// CategorySystem 是系统与环境类模块。
	CategorySystem = "系统"

	// CategoryBluetooth 是蓝牙类模块。
	CategoryBluetooth = "蓝牙"

	// Author 是模块默认作者信息。
	Author = "钟智强 ctkqiang"

	// DefaultTableWidth 是模块表格的单列默认最大宽度。
	DefaultTableWidth = 44
)

/*
Option 构造一个模块参数声明。

参数:
  - name (string): 参数名，控制台按大写匹配。
  - description (string): 参数说明。
  - required (bool): 是否必填。
  - defaultValue (string): 默认值。

返回:
  - model.Option: 可直接放入模块元数据的参数声明。
*/
func Option(name string, description string, required bool, defaultValue string) model.Option {
	return model.Option{
		Name:        name,
		Description: description,
		Required:    required,
		Default:     defaultValue,
	}
}

/*
Section 向输出目标写入段落标题。

参数:
  - out (io.Writer): 输出目标。
  - title (string): 段落标题。

返回:
  - 无。
*/
func Section(out io.Writer, title string) {
	fmt.Fprint(out, text.Section(title))
}

/*
Table 向输出目标写入等宽表格。

参数:
  - out (io.Writer): 输出目标。
  - headers ([]string): 表头。
  - rows ([][]string): 数据行。
  - maxWidth (int): 单列最大显示宽度；小于等于 0 时使用默认值。

返回:
  - 无。
*/
func Table(out io.Writer, headers []string, rows [][]string, maxWidth int) {
	if maxWidth <= 0 {
		maxWidth = DefaultTableWidth
	}
	fmt.Fprint(out, text.Table(headers, rows, maxWidth))
}

/*
KeyValues 向输出目标写入两列键值表。

参数:
  - out (io.Writer): 输出目标。
  - pairs ([][2]string): 键值对。
  - maxWidth (int): 值列最大显示宽度。

返回:
  - 无。
*/
func KeyValues(out io.Writer, pairs [][2]string, maxWidth int) {
	fmt.Fprint(out, text.KeyValues(pairs, maxWidth))
}

/*
Yes 判断参数是否为肯定值。

参数:
  - options (model.Options): 参数表。
  - key (string): 参数名。

返回:
  - bool: 参数为 true/yes/1 时返回 true。
*/
func Yes(options model.Options, key string) bool {
	return options.Bool(key, false)
}

/*
Etc 在值过长时追加省略号，用于命令行摘要。

参数:
  - value (string): 原始值。
  - width (int): 最大显示宽度。

返回:
  - string: 截断后的值。
*/
func Etc(value string, width int) string {
	return text.Truncate(value, width)
}
