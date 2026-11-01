package structure

import (
	"fmt"
	"io"
	"strings"
	"time"

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
	White:   logger.ColorWhite,
	Gray:    logger.ColorGray,
}

/*
printBanner 输出哪吒战术框架的启动横幅。
横幅采用雷达同心弧与字标组合的原创图形，不依赖外部字体或图片。

参数:
  - out (io.Writer): 输出目标。
  - color (bool): 是否启用 ANSI 颜色。

返回:
  - 无。
*/
func printBanner(out io.Writer, color bool) {
	art := []string{
		`                  ▂▃▅▇█▇▅▃▂`,
		`            ▂▃▅▇█▀         ▀█▇▅▃▂`,
		`      ▂▃▅▇█▀                   ▀█▇▅▃▂`,
		`  ██████   N E Z H A   C L I   ██████`,
		`      ▀▀▀▅▃▂                   ▂▃▅▀▀▀`,
		`            ▀▀▀▅▃▂         ▂▃▅▀▀▀`,
		`                  ▀▀▀▅▃▂ ▂▃▅▀▀▀`,
	}

	fmt.Fprintln(out)
	for index, line := range art {
		switch index {
		case 3:
			fmt.Fprintln(out, paint(color, palette.Bold+palette.Green, line))
		default:
			fmt.Fprintln(out, paint(color, palette.Red, line))
		}
	}
	fmt.Fprintln(out)

	fmt.Fprintf(out, "  %s%s%s\n",
		paint(color, palette.Bold+palette.White, config.AppName),
		paint(color, palette.Gray, "  ·  "),
		paint(color, palette.Gray, "v"+config.AppVersion),
	)
	fmt.Fprintf(out, "  %s\n", paint(color, palette.Red, config.AppTagline))
	fmt.Fprintf(out, "  %s\n\n", paint(color, palette.Gray, "战术控制台 · Termux/ARM64 · 原生核心零外部运行时"))
}

/*
printDashboard 渲染启动仪表盘，展示模块规模、环境与授权边界。
仪表盘只读取内存中的注册表，不触发任何网络或系统探测。

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
	width := 62
	line := strings.Repeat("─", width)

	title := " 操作台 "
	fmt.Fprintf(out, "%s┌%s%s┐%s\n",
		colorCode(color, palette.Gray),
		title,
		strings.Repeat("─", width-displayWidth(title)),
		colorCode(color, palette.Reset),
	)

	rows := [][2]string{
		{"操作员", operator},
		{"模块", fmt.Sprintf("%d 个 · %d 个类别", modules, categories)},
		{"运行环境", "Termux / Android ARM64 / 非 Root"},
		{"授权状态", "仅限已获得书面授权的目标"},
		{"当前时间", time.Now().Format("2006-01-02 15:04:05")},
	}
	for _, row := range rows {
		key := fmt.Sprintf(" %-8s", row[0])
		valueWidth := width - displayWidth(key) - 2
		fmt.Fprintf(out, "%s│%s%s%s│%s\n",
			colorCode(color, palette.Gray),
			colorCode(color, palette.Cyan)+key+colorCode(color, palette.Reset),
			colorCode(color, palette.White)+padRight(row[1], valueWidth)+colorCode(color, palette.Reset),
			colorCode(color, palette.Gray),
			colorCode(color, palette.Reset),
		)
	}
	fmt.Fprintf(out, "%s└%s┘%s\n", colorCode(color, palette.Gray), line, colorCode(color, palette.Reset))
	fmt.Fprintln(out)
}

/*
renderTable 渲染带边框的等宽表格，中文按两个终端列计算宽度。
该函数是 text 包表格能力的控制台别名。

参数:
  - headers ([]string): 表头。
  - rows ([][]string): 数据行。
  - maxWidth (int): 单列最大显示宽度。

返回:
  - string: 可直接写入终端的表格文本。
*/
func renderTable(headers []string, rows [][]string, maxWidth int) string {
	return text.Table(headers, rows, maxWidth)
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
printSection 输出带序号风格的段落标题。

参数:
  - out (io.Writer): 输出目标。
  - color (bool): 是否启用颜色。
  - title (string): 段落标题。

返回:
  - 无。
*/
func printSection(out io.Writer, color bool, title string) {
	fmt.Fprintf(out, "\n%s▌ %s%s\n",
		colorCode(color, palette.Bold+palette.Cyan),
		title,
		colorCode(color, palette.Reset),
	)
}
