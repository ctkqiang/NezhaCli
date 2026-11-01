// text 包提供终端文本排版工具：中英混排宽度计算、表格与段落标题。
package text

import (
	"fmt"
	"strings"
	"unicode"
)

const (
	// ansiEscape 是终端转义序列起始符，计算显示宽度时整体跳过。
	ansiEscape = '\x1b'

	// cjkWidth 是中日韩全角字符占用的终端列数。
	cjkWidth = 2

	// tablePadding 是表格单元格左右各留的空格数。
	tablePadding = 1

	// defaultMaxWidth 是单列默认最大显示宽度，避免窄屏换行破坏对齐。
	defaultMaxWidth = 48
)

/*
Width 计算字符串在终端中的显示宽度，跳过 ANSI 转义序列。
CJK 全角字符按两列计算，组合符号按零列计算。

参数:
  - value (string): 待计算字符串。

返回:
  - int: 终端列数。
*/
func Width(value string) int {
	width := 0
	inEscape := false
	for _, char := range value {
		if inEscape {
			if char == 'm' {
				inEscape = false
			}
			continue
		}
		if char == ansiEscape {
			inEscape = true
			continue
		}
		width += runeWidth(char)
	}
	return width
}

/*
PadRight 使用空格把字符串补齐到指定显示宽度。
已经超宽时原样返回，不截断。

参数:
  - value (string): 原始字符串。
  - width (int): 目标显示宽度。

返回:
  - string: 补齐后的字符串。
*/
func PadRight(value string, width int) string {
	padding := width - Width(value)
	if padding <= 0 {
		return value
	}
	return value + strings.Repeat(" ", padding)
}

/*
Truncate 按显示宽度截断字符串，并在末尾保留省略号。

参数:
  - value (string): 原始字符串。
  - width (int): 允许的最大显示宽度。

返回:
  - string: 截断后的字符串。
*/
func Truncate(value string, width int) string {
	value = strings.ReplaceAll(value, "\n", " ")
	if width <= 0 {
		return ""
	}
	if Width(value) <= width {
		return value
	}

	limit := width - 1
	var builder strings.Builder
	current := 0
	for _, char := range value {
		charWidth := runeWidth(char)
		if current+charWidth > limit {
			break
		}
		builder.WriteRune(char)
		current += charWidth
	}
	builder.WriteString("…")
	return builder.String()
}

/*
Table 渲染带边框的等宽表格，中文按两个终端列计算宽度。
超长单元格会被截断并追加省略号。

参数:
  - headers ([]string): 表头。
  - rows ([][]string): 数据行。
  - maxWidth (int): 单列最大显示宽度；小于等于 0 时使用 48。

返回:
  - string: 可直接写入终端的表格文本。
*/
func Table(headers []string, rows [][]string, maxWidth int) string {
	if maxWidth <= 0 {
		maxWidth = defaultMaxWidth
	}

	widths := make([]int, len(headers))
	for index, header := range headers {
		widths[index] = Width(header)
	}
	for _, row := range rows {
		for index := range headers {
			if index >= len(row) {
				continue
			}
			width := Width(row[index])
			if width > maxWidth {
				width = maxWidth
			}
			if width > widths[index] {
				widths[index] = width
			}
		}
	}

	var builder strings.Builder
	builder.WriteString(borderLine(widths, "┌", "┬", "┐"))
	builder.WriteString(tableRow(headers, widths))
	builder.WriteString(borderLine(widths, "├", "┼", "┤"))
	for _, row := range rows {
		builder.WriteString(tableRow(row, widths))
	}
	builder.WriteString(borderLine(widths, "└", "┴", "┘"))
	return builder.String()
}

/*
Section 生成带竖条标记的段落标题，前后各留一个空行。

参数:
  - title (string): 段落标题。

返回:
  - string: 可直接写入终端的标题文本。
*/
func Section(title string) string {
	return "\n▌ " + title + "\n"
}

/*
KeyValues 把键值对渲染为两列表格。

参数:
  - pairs ([][2]string): 键值对集合。
  - maxWidth (int): 值列最大显示宽度。

返回:
  - string: 两列表格文本。
*/
func KeyValues(pairs [][2]string, maxWidth int) string {
	rows := make([][]string, 0, len(pairs))
	for _, pair := range pairs {
		rows = append(rows, []string{pair[0], pair[1]})
	}
	return Table([]string{"字段", "值"}, rows, maxWidth)
}

/*
Printf 输出一行格式化文本，供模块统一排版。

参数:
  - builder (*strings.Builder): 输出缓冲。
  - format (string): 格式化模板。
  - arguments (...any): 模板参数。

返回:
  - 无。
*/
func Printf(builder *strings.Builder, format string, arguments ...any) {
	fmt.Fprintf(builder, format, arguments...)
}

/*
borderLine 生成表格的水平边框。

参数:
  - widths ([]int): 每列显示宽度。
  - left (string): 左边角字符。
  - middle (string): 交叉字符。
  - right (string): 右边角字符。

返回:
  - string: 一行边框文本。
*/
func borderLine(widths []int, left string, middle string, right string) string {
	segments := make([]string, len(widths))
	for index, width := range widths {
		segments[index] = strings.Repeat("─", width+tablePadding*2)
	}
	return left + strings.Join(segments, middle) + right + "\n"
}

/*
tableRow 生成一行表格内容，并按列宽补齐或截断。

参数:
  - cells ([]string): 单元格内容。
  - widths ([]int): 每列显示宽度。

返回:
  - string: 一行表格文本。
*/
func tableRow(cells []string, widths []int) string {
	var builder strings.Builder
	builder.WriteString("│")
	for index, width := range widths {
		value := ""
		if index < len(cells) {
			value = cells[index]
		}
		value = Truncate(value, width)
		builder.WriteString(" ")
		builder.WriteString(value)
		builder.WriteString(strings.Repeat(" ", width-Width(value)))
		builder.WriteString(" │")
	}
	builder.WriteString("\n")
	return builder.String()
}

/*
runeWidth 返回单个字符的终端列数。

参数:
  - char (rune): 待判断字符。

返回:
  - int: 字符占用的终端列数。
*/
func runeWidth(char rune) int {
	if char == 0 {
		return 0
	}
	if unicode.Is(unicode.Mn, char) || unicode.Is(unicode.Me, char) {
		return 0
	}
	if isWideRune(char) {
		return cjkWidth
	}
	return 1
}

/*
isWideRune 判断字符是否属于东亚全角或 emoji 宽度区间。

参数:
  - char (rune): 待判断字符。

返回:
  - bool: 属于宽字符时返回 true。
*/
func isWideRune(char rune) bool {
	switch {
	case char >= 0x1100 && char <= 0x115F,
		char >= 0x2E80 && char <= 0x303E,
		char >= 0x3041 && char <= 0x33FF,
		char >= 0x3400 && char <= 0x4DBF,
		char >= 0x4E00 && char <= 0x9FFF,
		char >= 0xA000 && char <= 0xA4CF,
		char >= 0xAC00 && char <= 0xD7A3,
		char >= 0xF900 && char <= 0xFAFF,
		char >= 0xFE30 && char <= 0xFE6F,
		char >= 0xFF00 && char <= 0xFF60,
		char >= 0xFFE0 && char <= 0xFFE6,
		char >= 0x1F300 && char <= 0x1FAFF,
		char >= 0x20000 && char <= 0x3FFFD:
		return true
	default:
		return false
	}
}
