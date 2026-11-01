// readline 包提供零依赖的行编辑器：历史浏览、光标编辑与终端原始模式循环。
// 原始模式由调用方通过 internal/term 开启后传入 *os.File，否则退化为行读取。
package readline

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/ctkqiang/nezha_cli/internal/text"
)

const (
	// escapeTimeout 是 ESC 序列后续字节的读取等待上限。
	escapeTimeout = 80 * time.Millisecond

	// historyCap 是历史条数上限，防止长时间会话内存膨胀。
	historyCap = 500
)

// ErrInterrupted 表示编辑行期间收到 Ctrl+C 且当前行为空。
var ErrInterrupted = errors.New("操作被 Ctrl+C 中断")

// Editor 维护行缓冲、光标位置与命令历史，状态可独立单元测试。
type Editor struct {
	history []string
	index   int
	draft   string
	line    []rune
	cursor  int
}

/*
New 创建空编辑器。

参数:
  - 无。

返回:
  - *Editor: 编辑器实例。
*/
func New() *Editor {
	return &Editor{index: 0}
}

/*
Line 返回当前行内容。

参数:
  - 无。

返回:
  - string: 行缓冲内容。
*/
func (e *Editor) Line() string {
	return string(e.line)
}

/*
Insert 在光标处插入字符。

参数:
  - char (rune): 待插入字符。

返回:
  - 无。
*/
func (e *Editor) Insert(char rune) {
	e.line = append(e.line, 0)
	copy(e.line[e.cursor+1:], e.line[e.cursor:])
	e.line[e.cursor] = char
	e.cursor++
}

/*
Backspace 删除光标左侧一个字符，中文按整字删除。

参数:
  - 无。

返回:
  - 无。
*/
func (e *Editor) Backspace() {
	if e.cursor == 0 {
		return
	}
	copy(e.line[e.cursor-1:], e.line[e.cursor:])
	e.line = e.line[:len(e.line)-1]
	e.cursor--
}

/*
DeleteForward 删除光标处字符。

参数:
  - 无。

返回:
  - 无。
*/
func (e *Editor) DeleteForward() {
	if e.cursor >= len(e.line) {
		return
	}
	copy(e.line[e.cursor:], e.line[e.cursor+1:])
	e.line = e.line[:len(e.line)-1]
}

/*
MoveLeft 光标左移一个字符。

参数:
  - 无。

返回:
  - 无。
*/
func (e *Editor) MoveLeft() {
	if e.cursor > 0 {
		e.cursor--
	}
}

/*
MoveRight 光标右移一个字符。

参数:
  - 无。

返回:
  - 无。
*/
func (e *Editor) MoveRight() {
	if e.cursor < len(e.line) {
		e.cursor++
	}
}

/*
MoveHome 光标移到行首。

参数:
  - 无。

返回:
  - 无。
*/
func (e *Editor) MoveHome() {
	e.cursor = 0
}

/*
MoveEnd 光标移到行尾。

参数:
  - 无。

返回:
  - 无。
*/
func (e *Editor) MoveEnd() {
	e.cursor = len(e.line)
}

/*
KillToEnd 删除光标到行尾的内容。

参数:
  - 无。

返回:
  - 无。
*/
func (e *Editor) KillToEnd() {
	e.line = e.line[:e.cursor]
}

/*
KillWordBack 删除光标左侧一个词。

参数:
  - 无。

返回:
  - 无。
*/
func (e *Editor) KillWordBack() {
	for e.cursor > 0 && e.line[e.cursor-1] == ' ' {
		e.Backspace()
	}
	for e.cursor > 0 && e.line[e.cursor-1] != ' ' {
		e.Backspace()
	}
}

/*
Clear 清空当前行。

参数:
  - 无。

返回:
  - 无。
*/
func (e *Editor) Clear() {
	e.line = nil
	e.cursor = 0
}

/*
SetLine 整体替换行内容，光标移到行尾。

参数:
  - value (string): 新行内容。

返回:
  - 无。
*/
func (e *Editor) SetLine(value string) {
	e.line = []rune(value)
	e.cursor = len(e.line)
}

/*
HistoryUp 浏览上一条历史，首次离开新行时保存草稿。

参数:
  - 无。

返回:
  - 无。
*/
func (e *Editor) HistoryUp() {
	if len(e.history) == 0 {
		return
	}
	if e.index == len(e.history) {
		e.draft = string(e.line)
	}
	if e.index > 0 {
		e.index--
	}
	e.SetLine(e.history[e.index])
}

/*
HistoryDown 浏览下一条历史，回到末尾时恢复草稿。

参数:
  - 无。

返回:
  - 无。
*/
func (e *Editor) HistoryDown() {
	if e.index >= len(e.history) {
		return
	}
	e.index++
	if e.index == len(e.history) {
		e.SetLine(e.draft)
		e.draft = ""
		return
	}
	e.SetLine(e.history[e.index])
}

/*
History 返回历史命令副本，供测试与状态导出使用。

参数:
  - 无。

返回:
  - []string: 历史命令副本。
*/
func (e *Editor) History() []string {
	return append([]string(nil), e.history...)
}

/*
AppendHistory 追加一条历史，空行与连续重复跳过。

参数:
  - line (string): 待追加命令。

返回:
  - 无。
*/
func (e *Editor) AppendHistory(line string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	if len(e.history) > 0 && e.history[len(e.history)-1] == line {
		return
	}
	e.history = append(e.history, line)
	if len(e.history) > historyCap {
		e.history = e.history[len(e.history)-historyCap:]
	}
	e.index = len(e.history)
	e.draft = ""
}

/*
ReadLine 读取一行输入。
reader 为 *os.File 时按原始模式逐键处理；其余输入源退化为整行读取，
并剔除行内的 ANSI 转义序列，避免方向键残留污染命令。

参数:
  - reader (io.Reader): 输入源。
  - writer (io.Writer): 渲染目标。
  - prompt (string): 提示符文本，允许包含 ANSI 颜色。

返回:
  - string: 输入行。
  - error: 输入结束或中断时返回错误。
*/
func (e *Editor) ReadLine(reader io.Reader, writer io.Writer, prompt string) (string, error) {
	file, isFile := reader.(*os.File)
	if !isFile {
		return e.readLineFallback(reader, writer, prompt)
	}

	e.line = nil
	e.cursor = 0
	e.index = len(e.history)
	e.draft = ""
	e.render(writer, prompt)

	var key [1]byte
	for {
		count, err := file.Read(key[:])
		if err != nil {
			if errors.Is(err, syscall.EINTR) || errors.Is(err, syscall.EAGAIN) {
				// 信号打断读取（例如空闲时的 Ctrl+C）：保持编辑状态并重绘
				e.render(writer, prompt)
				continue
			}
			fmt.Fprintln(writer)
			return "", err
		}
		if count == 0 {
			continue
		}

		switch char := key[0]; {
		case char == '\r' || char == '\n':
			line := string(e.line)
			fmt.Fprintln(writer)
			return line, nil
		case char == 0x03:
			if len(e.line) == 0 {
				fmt.Fprintln(writer)
				return "", ErrInterrupted
			}
			e.Clear()
			e.render(writer, prompt)
		case char == 0x04:
			if len(e.line) == 0 {
				fmt.Fprintln(writer)
				return "", io.EOF
			}
			e.DeleteForward()
			e.render(writer, prompt)
		case char == 0x7f || char == 0x08:
			e.Backspace()
			e.render(writer, prompt)
		case char == 0x01:
			e.MoveHome()
			e.render(writer, prompt)
		case char == 0x05:
			e.MoveEnd()
			e.render(writer, prompt)
		case char == 0x0b:
			e.KillToEnd()
			e.render(writer, prompt)
		case char == 0x15:
			e.Clear()
			e.render(writer, prompt)
		case char == 0x17:
			e.KillWordBack()
			e.render(writer, prompt)
		case char == 0x1b:
			if e.handleEscape(file) {
				e.render(writer, prompt)
			}
		default:
			if e.consumeUTF8(file, char) {
				e.render(writer, prompt)
			}
		}
	}
}

/*
handleEscape 解析 ESC 序列：方向键、行首行尾与删除键。

参数:
  - file (*os.File): 终端文件，用于限时读取后续字节。

返回:
  - bool: 序列改变了编辑状态时返回 true。
*/
func (e *Editor) handleEscape(file *os.File) bool {
	second, ok := readByteTimeout(file, escapeTimeout)
	if !ok || second != '[' {
		return false
	}

	third, ok := readByteTimeout(file, escapeTimeout)
	if !ok {
		return false
	}

	switch third {
	case 'A':
		e.HistoryUp()
	case 'B':
		e.HistoryDown()
	case 'C':
		e.MoveRight()
	case 'D':
		e.MoveLeft()
	case 'H':
		e.MoveHome()
	case 'F':
		e.MoveEnd()
	case '3':
		tail, ok := readByteTimeout(file, escapeTimeout)
		if !ok || tail != '~' {
			return false
		}
		e.DeleteForward()
	default:
		return false
	}
	return true
}

/*
consumeUTF8 按首字节读取完整 UTF-8 字符并插入。

参数:
  - file (*os.File): 终端文件。
  - first (byte): 首字节。

返回:
  - bool: 成功插入返回 true。
*/
func (e *Editor) consumeUTF8(file *os.File, first byte) bool {
	if first < 0x20 {
		return false
	}
	length := utf8.RuneLen(rune(first))
	if length < 1 {
		return false
	}

	buffer := make([]byte, length)
	buffer[0] = first
	for index := 1; index < length; index++ {
		next, ok := readByteTimeout(file, escapeTimeout)
		if !ok {
			return false
		}
		buffer[index] = next
	}
	char, size := utf8.DecodeRune(buffer)
	if size != length || char == utf8.RuneError {
		return false
	}
	e.Insert(char)
	return true
}

/*
readByteTimeout 在限时内读取一个字节，超时返回失败。

参数:
  - file (*os.File): 终端文件。
  - timeout (time.Duration): 等待上限。

返回:
  - byte: 读取到的字节。
  - bool: 读取成功返回 true。
*/
func readByteTimeout(file *os.File, timeout time.Duration) (byte, bool) {
	_ = file.SetReadDeadline(time.Now().Add(timeout))
	defer file.SetReadDeadline(time.Time{})

	var buffer [1]byte
	count, err := file.Read(buffer[:])
	if err != nil || count == 0 {
		return 0, false
	}
	return buffer[0], true
}

/*
render 重绘提示符与当前行，并把光标放回正确列。
CJK 字符按两列计算，ANSI 颜色不计宽度。

参数:
  - writer (io.Writer): 渲染目标。
  - prompt (string): 提示符文本。

返回:
  - 无。
*/
func (e *Editor) render(writer io.Writer, prompt string) {
	line := string(e.line)
	prefix := string(e.line[:e.cursor])

	var builder strings.Builder
	builder.WriteString("\r\x1b[K")
	builder.WriteString(prompt)
	builder.WriteString(line)

	back := text.Width(prompt) + text.Width(line) - text.Width(prompt) - text.Width(prefix)
	if back > 0 {
		fmt.Fprintf(&builder, "\x1b[%dD", back)
	}
	fmt.Fprint(writer, builder.String())
}

/*
readLineFallback 非终端输入源的整行读取，剔除方向键残留序列。

参数:
  - reader (io.Reader): 输入源。
  - writer (io.Writer): 提示符输出目标。
  - prompt (string): 提示符文本。

返回:
  - string: 输入行。
  - error: 输入结束或读取失败时返回错误。
*/
func (e *Editor) readLineFallback(reader io.Reader, writer io.Writer, prompt string) (string, error) {
	fmt.Fprint(writer, prompt)
	buffer := bufio.NewReader(reader)
	line, err := buffer.ReadString('\n')
	line = strings.TrimRight(line, "\r\n")
	if err != nil && line == "" {
		return "", err
	}
	return stripEscapeSequences(line), nil
}

/*
stripEscapeSequences 剔除行内 ANSI 转义序列。

参数:
  - line (string): 原始行。

返回:
  - string: 剔除后的行。
*/
func stripEscapeSequences(line string) string {
	for {
		index := strings.IndexByte(line, 0x1b)
		if index < 0 {
			return line
		}
		end := index + 1
		if end < len(line) && line[end] == '[' {
			for end < len(line) {
				char := line[end]
				end++
				if (char >= 'A' && char <= 'Z') || (char >= 'a' && char <= 'z') || char == '~' {
					break
				}
			}
		}
		line = line[:index] + line[end:]
	}
}
