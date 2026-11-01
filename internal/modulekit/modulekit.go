// modulekit 包提供内置模块共用的元数据构造函数与终端排版辅助。
package modulekit

import (
	"fmt"
	"io"
	"strings"

	"github.com/ctkqiang/nezha_cli/internal/model"
	"github.com/ctkqiang/nezha_cli/internal/text"
	"github.com/ctkqiang/nezha_cli/pkg/logger"
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

// categoryColors 是类别到终端颜色的映射，供控制台与模块统一着色。
var categoryColors = map[string]string{
	CategoryRecon:     "\033[36m",
	CategoryWeb:       "\033[35m",
	CategoryWireless:  "\033[33m",
	CategorySystem:    "\033[32m",
	CategoryBluetooth: "\033[34m",
}

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
CategoryColor 返回类别对应的终端颜色码。
未收录的类别返回白色；颜色关闭时由调用方决定是否忽略。

参数:
  - category (string): 类别名。

返回:
  - string: ANSI 颜色码。
*/
func CategoryColor(category string) string {
	if color, ok := categoryColors[category]; ok {
		return color
	}
	return "\033[37m"
}

/*
Section 向输出目标写入带标尺的段落标题。
标题着色后接灰色横线，横线长度随终端宽度自适应。

参数:
  - out (io.Writer): 输出目标。
  - title (string): 段落标题。

返回:
  - 无。
*/
func Section(out io.Writer, title string) {
	ruleWidth := text.TermWidth() - text.Width(title) - 8
	if ruleWidth < 4 {
		ruleWidth = 4
	}
	rule := strings.Repeat("─", ruleWidth)

	if !logger.ColorEnabled {
		fmt.Fprintf(out, "\n──┤ %s ├%s\n", title, rule)
		return
	}
	fmt.Fprintf(out, "\n\033[90m──┤ \033[0m\033[1;36m%s\033[0m \033[90m├%s\033[0m\n", title, rule)
}

/*
tableStyle 返回当前颜色开关下的表格样式。

参数:
  - 无。

返回:
  - text.TableStyle: 边框灰色、表头粗体青色的样式；颜色关闭时为空样式。
*/
func tableStyle() text.TableStyle {
	if !logger.ColorEnabled {
		return text.TableStyle{}
	}
	return text.TableStyle{
		Border: "\033[90m",
		Header: "\033[1;36m",
		Reset:  "\033[0m",
	}
}

/*
Table 向输出目标写入带样式的等宽表格。
边框为灰色，表头为粗体青色；颜色关闭时自动退化为纯文本。

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
	fmt.Fprint(out, text.TableStyled(headers, rows, maxWidth, tableStyle()))
}

/*
KeyValues 向输出目标写入两列键值表，样式与 Table 一致。

参数:
  - out (io.Writer): 输出目标。
  - pairs ([][2]string): 键值对。
  - maxWidth (int): 值列最大显示宽度。

返回:
  - 无。
*/
func KeyValues(out io.Writer, pairs [][2]string, maxWidth int) {
	rows := make([][]string, 0, len(pairs))
	for _, pair := range pairs {
		rows = append(rows, []string{pair[0], pair[1]})
	}
	fmt.Fprint(out, text.TableStyled([]string{"字段", "值"}, rows, maxWidth, tableStyle()))
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
