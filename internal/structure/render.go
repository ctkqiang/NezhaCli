package structure

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/ctkqiang/nezha_cli/internal/core"
	"github.com/ctkqiang/nezha_cli/internal/text"
	"github.com/ctkqiang/nezha_cli/pkg/config"
	"github.com/ctkqiang/nezha_cli/pkg/logger"
)

// palette 汇总控制台使用的 ANSI 颜色，避免各处硬编码。
var palette = struct {
	Reset   string
	Bold    string
	Dim     string
	Red     string
	Green   string
	Yellow  string
	Cyan    string
	Magenta string
	Blue    string
	White   string
	Gray    string
}{
	Reset:   logger.ColorReset,
	Bold:    logger.ColorBold,
	Dim:     "\033[2m",
	Red:     logger.ColorRed,
	Green:   logger.ColorGreen,
	Yellow:  logger.ColorYellow,
	Cyan:    logger.ColorCyan,
	Magenta: "\033[35m",
	Blue:    "\033[34m",
	White:   logger.ColorWhite,
	Gray:    logger.ColorGray,
}

/*
printBanner 输出控制台启动横幅。
横幅沿用雷达扫描弧与中文大字标，下方按 metasploit 风格列出内置能力清单，
让操作员一眼看清本终端内置了哪些能力，而不是再去安装任何外部工具。

参数:
  - out (io.Writer): 输出目标。
  - color (bool): 是否启用 ANSI 颜色。
  - registry (*core.Registry): 模块注册表，用于统计类别能力。

返回:
  - 无。
*/
func printBanner(out io.Writer, color bool, registry *core.Registry) {
	art := []string{
		`            ▂▃▅▇█▇▅▃▂`,
		`      ▂▃▅▇█▀         ▀█▇▅▃▂`,
		`▂▃▅▇█▀                   ▀█▇▅▃▂`,
		`   ███████████████████████████`,
	}

	fmt.Fprintln(out)
	for index, line := range art {
		if index == 3 {
			fmt.Fprintln(out, paint(color, palette.Bold+palette.Green, line))
			continue
		}
		fmt.Fprintln(out, paint(color, palette.Red, line))
	}

	title := "哪 吒 网 络 安 全 终 端"
	width := text.TermWidth()
	if width > 78 {
		width = 78
	}
	pad := (width - text.Width(title)) / 2
	if pad < 0 {
		pad = 0
	}
	fmt.Fprintf(out, "%s%s\n",
		strings.Repeat(" ", pad),
		paint(color, palette.Bold+palette.Green, title),
	)
	fmt.Fprintf(out, "%s%s%s%s\n",
		strings.Repeat(" ", pad),
		paint(color, palette.Gray, "战 术 控 制 台"),
		paint(color, palette.Gray, "  ·  "),
		paint(color, palette.Gray, "v"+config.AppVersion),
	)

	fmt.Fprintln(out)
	line := " " + strings.Repeat("=", width-2) + " "
	fmt.Fprintf(out, "%s\n", paint(color, palette.Cyan, line))
	fmt.Fprintf(out, "=%s[ %s %s ]%s\n",
		paint(color, palette.Cyan, ""),
		paint(color, palette.Bold+palette.White, config.AppName),
		paint(color, palette.Gray, "v"+config.AppVersion),
		paint(color, palette.Cyan, ""),
	)

	capacity := buildCapacityLine(color, registry)
	fmt.Fprintf(out, "+ -- --=[ %s\n", capacity)
	fmt.Fprintf(out, "+ -- --=[ %s\n",
		paint(color, palette.White, fmt.Sprintf("内置 %d 个模块 · 零外部依赖 · 无需再安装任何工具", len(registry.List()))),
	)
	fmt.Fprintf(out, "%s\n", paint(color, palette.Cyan, line))

	fmt.Fprintln(out)
	center(out, color, width, config.AppTagline, palette.Red)
	center(out, color, width, "战术控制台 · Termux 环境 · 安卓 ARM64 · 非 Root", palette.Gray)
	fmt.Fprintln(out)
	center(out, color, width, "输入 help 查看命令 · show modules 查看全部内置能力", palette.Dim)
	fmt.Fprintln(out)
}

/*
center 把文本按终端宽度居中输出。

参数:
  - out (io.Writer): 输出目标。
  - color (bool): 是否启用颜色。
  - width (int): 终端宽度。
  - value (string): 待居中文本。
  - code (string): 颜色码。

返回:
  - 无。
*/
func center(out io.Writer, color bool, width int, value string, code string) {
	pad := (width - text.Width(value)) / 2
	if pad < 0 {
		pad = 0
	}
	fmt.Fprintf(out, "%s%s\n", strings.Repeat(" ", pad), paint(color, code, value))
}

/*
buildCapacityLine 生成类别能力清单行，各类别按自己的颜色着色。
用于启动横幅与 show categories，让内置能力一目了然。

参数:
  - color (bool): 是否启用颜色。
  - registry (*core.Registry): 模块注册表。

返回:
  - string: 已着色的能力清单文本。
*/
func buildCapacityLine(color bool, registry *core.Registry) string {
	counts := make(map[string]int, 8)
	for _, entry := range registry.List() {
		counts[entry.Meta.Category]++
	}

	names := make([]string, 0, len(counts))
	for name := range counts {
		names = append(names, name)
	}
	sort.Slice(names, func(left int, right int) bool {
		return counts[names[left]] > counts[names[right]]
	})

	parts := make([]string, 0, len(names))
	for _, name := range names {
		item := fmt.Sprintf("%s %d 个", name, counts[name])
		parts = append(parts, paint(color, categoryCode(name), item))
	}
	return strings.Join(parts, " · ")
}

/*
categoryCode 返回类别对应的 ANSI 颜色码。

参数:
  - category (string): 类别名。

返回:
  - string: ANSI 颜色码。
*/
func categoryCode(category string) string {
	switch category {
	case "侦察":
		return palette.Cyan
	case "Web":
		return palette.Magenta
	case "无线":
		return palette.Yellow
	case "系统":
		return palette.Green
	case "蓝牙":
		return palette.Blue
	default:
		return palette.Gray
	}
}

/*
printDashboard 渲染启动仪表盘面板，展示环境、规模与授权边界。
面板只读取内存中的注册表与状态，不触发任何网络或系统探测。

参数:
  - out (io.Writer): 输出目标。
  - color (bool): 是否启用 ANSI 颜色。
  - modules (int): 已注册模块数量。
  - categories (int): 模块类别数量。
  - operator (string): 当前操作员标识。

返回:
  - 无。
*/
func printDashboard(out io.Writer, color bool, modules int, categories int, operator string) {
	width := text.TermWidth() - 2
	if width > 62 {
		width = 62
	}
	if width < 40 {
		width = 40
	}

	title := " 操作台 "
	fmt.Fprintf(out, "%s┌%s%s┐%s\n",
		colorCode(color, palette.Gray),
		paint(color, palette.Bold+palette.White, title),
		paint(color, palette.Gray, strings.Repeat("─", width-text.Width(title))),
		colorCode(color, palette.Reset),
	)

	rows := [][2]string{
		{"操作员", operator},
		{"模块", fmt.Sprintf("%d 个 · %d 个类别", modules, categories)},
		{"运行环境", "Termux · 安卓 ARM64 · 非 Root"},
		{"授权状态", "仅限已获得书面授权的目标"},
		{"当前时间", time.Now().Format("2006-01-02 15:04:05")},
	}
	for _, row := range rows {
		key := " " + row[0] + " "
		valueWidth := width - text.Width(key) - 2
		fmt.Fprintf(out, "%s│%s%s%s%s│%s\n",
			colorCode(color, palette.Gray),
			paint(color, palette.Bold+palette.Cyan, key),
			colorCode(color, palette.Gray),
			paint(color, palette.White, padRight(row[1], valueWidth)),
			colorCode(color, palette.Gray),
			colorCode(color, palette.Reset),
		)
	}
	fmt.Fprintf(out, "%s└%s┘%s\n",
		colorCode(color, palette.Gray),
		strings.Repeat("─", width),
		colorCode(color, palette.Reset),
	)
	fmt.Fprintln(out)
}

/*
renderTable 渲染带样式着色的等宽表格，中文按两个终端列计算宽度。
边框灰色、表头粗体青色；颜色关闭时退化为纯文本表格。

参数:
  - color (bool): 是否启用颜色。
  - headers ([]string): 表头。
  - rows ([][]string): 数据行。
  - maxWidth (int): 单列最大显示宽度。

返回:
  - string: 可直接写入终端的表格文本。
*/
func renderTable(color bool, headers []string, rows [][]string, maxWidth int) string {
	style := text.TableStyle{}
	if color {
		style = text.TableStyle{
			Border: palette.Gray,
			Header: palette.Bold + palette.Cyan,
			Reset:  palette.Reset,
		}
	}
	return text.TableStyled(headers, rows, maxWidth, style)
}

/*
displayWidth 计算字符串在终端中的显示宽度。

参数:
  - value (string): 待计算字符串。

返回:
  - int: 终端列数。
*/
func displayWidth(value string) int {
	return text.Width(value)
}

/*
padRight 使用空格把字符串补齐到指定显示宽度。

参数:
  - value (string): 原始字符串。
  - width (int): 目标显示宽度。

返回:
  - string: 补齐后的字符串。
*/
func padRight(value string, width int) string {
	return text.PadRight(value, width)
}

/*
colorCode 在启用颜色时返回对应 ANSI 码，否则返回空字符串。

参数:
  - enabled (bool): 是否启用颜色。
  - code (string): ANSI 颜色码。

返回:
  - string: 可用颜色码或空字符串。
*/
func colorCode(enabled bool, code string) string {
	if !enabled {
		return ""
	}
	return code
}

/*
paint 为文本着色；关闭颜色时原样返回。

参数:
  - enabled (bool): 是否启用颜色。
  - code (string): ANSI 颜色码。
  - text (string): 待着色文本。

返回:
  - string: 着色后的文本。
*/
func paint(enabled bool, code string, text string) string {
	if !enabled {
		return text
	}
	return code + text + palette.Reset
}

/*
printSection 输出带标尺的段落标题，标尺长度随终端宽度自适应。

参数:
  - out (io.Writer): 输出目标。
  - color (bool): 是否启用颜色。
  - title (string): 段落标题。

返回:
  - 无。
*/
func printSection(out io.Writer, color bool, title string) {
	ruleWidth := text.TermWidth() - text.Width(title) - 8
	if ruleWidth < 4 {
		ruleWidth = 4
	}
	fmt.Fprintf(out, "\n%s──┤ %s ├%s%s%s\n",
		colorCode(color, palette.Gray),
		paint(color, palette.Bold+palette.Cyan, title),
		colorCode(color, palette.Gray),
		strings.Repeat("─", ruleWidth),
		colorCode(color, palette.Reset),
	)
}

/*
paintImpact 把影响级别文本着色为高亮徽标。
无影响级别时显示灰色占位符；存在影响级别时以红色加粗警告。

参数:
  - color (bool): 是否启用颜色。
  - impact (string): 影响级别文本。

返回:
  - string: 着色后的徽标文本。
*/
func paintImpact(color bool, impact string) string {
	if strings.TrimSpace(impact) == "" {
		return paint(color, palette.Gray, "—")
	}
	return paint(color, palette.Bold+palette.Red, impact)
}
