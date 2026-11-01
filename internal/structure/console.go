// structure 包实现 msfconsole 风格的交互式战术控制台。
package structure

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ctkqiang/nezha_cli/internal/core"
	"github.com/ctkqiang/nezha_cli/internal/engine"
	"github.com/ctkqiang/nezha_cli/internal/model"
	"github.com/ctkqiang/nezha_cli/internal/readline"
	"github.com/ctkqiang/nezha_cli/internal/term"
	"github.com/ctkqiang/nezha_cli/pkg/config"
	"github.com/ctkqiang/nezha_cli/pkg/logger"
)

// Session 记录一次模块执行，供 sessions 命令回溯。
type Session struct {
	Index    int
	Module   string
	Started  time.Time
	Duration time.Duration
	OK       bool
	Error    string
}

// Console 保存控制台的交互状态、模块选择与运行上下文。
type Console struct {
	registry *core.Registry

	reader *bufio.Reader
	out    io.Writer

	color       bool
	interactive bool

	selected *core.Entry
	options  model.Options
	globals  model.Options

	history  []string
	sessions []Session
	operator string

	lastErr error

	editor *readline.Editor
	raw    bool

	inputCustom bool
	rawRestore  func()

	signalOnce sync.Once
	signalCh   chan os.Signal

	runMu     sync.Mutex
	runCancel context.CancelFunc
	running   bool
}

/*
New 创建一个绑定标准输入输出的控制台。
模块选择、参数与会话记录都在实例内部维护，互不共享。

参数:
  - registry (*core.Registry): 已加载完成的模块注册表。

返回:
  - *Console: 控制台实例。
*/
func New(registry *core.Registry) *Console {
	operator := strings.TrimSpace(os.Getenv("USER"))
	if operator == "" {
		operator = strings.TrimSpace(os.Getenv("LOGNAME"))
	}
	if operator == "" {
		operator = "operator"
	}

	return &Console{
		registry: registry,
		reader:   bufio.NewReader(os.Stdin),
		out:      os.Stdout,
		color:    true,
		options:  make(model.Options),
		globals:  make(model.Options),
		history:  make([]string, 0, 64),
		sessions: make([]Session, 0, 16),
		operator: operator,
		editor:   readline.New(),
	}
}

/*
SetColor 控制是否启用 ANSI 颜色。
管道与非交互环境应关闭颜色，避免污染可解析输出。

参数:
  - enabled (bool): true 启用颜色。

返回:
  - 无。
*/
func (c *Console) SetColor(enabled bool) {
	c.color = enabled
}

/*
SetOutput 替换控制台的数据输出目标，便于测试捕获。

参数:
  - out (io.Writer): 新的输出目标。

返回:
  - 无。
*/
func (c *Console) SetOutput(out io.Writer) {
	c.out = out
}

/*
SetInput 替换控制台的输入来源，用于测试与脚本化确认。
默认输入为标准输入。

参数:
  - input (io.Reader): 新的输入来源。

返回:
  - 无。
*/
func (c *Console) SetInput(input io.Reader) {
	c.reader = bufio.NewReader(input)
	c.inputCustom = true
}

/*
Start 启动交互式控制台主循环。
启动时渲染横幅与仪表盘，随后逐行读取命令，直到 exit 或输入流关闭。

参数:
  - 无。

返回:
  - error: 输入流读取失败时返回错误；正常退出返回 nil。
*/
func (c *Console) Start() error {
	c.interactive = true
	c.installSignalHandler()

	c.enableRawMode()
	defer c.disableRawMode()

	printBanner(c.out, c.color, c.registry)
	printDashboard(c.out, c.color, len(c.registry.List()), len(c.registry.Categories()), c.operator)
	c.promptHelp()
	fmt.Fprintln(c.out)
	if c.selected != nil {
		c.printModuleCard(c.selected)
	}

	for {
		line, err := c.readCommand()
		if err != nil {
			if errors.Is(err, readline.ErrInterrupted) {
				c.printInterruptHint()
				continue
			}
			logger.Debug("输入流结束: %v", err)
			fmt.Fprintln(c.out)
			return nil
		}
		if !c.Execute(line) {
			return nil
		}
	}
}

/*
enableRawMode 在标准输入为终端时启用原始模式，支持方向键历史与光标编辑。
启用失败或非终端输入源时静默退化，不影响脚本与管道模式。

参数:
  - 无。

返回:
  - 无。
*/
func (c *Console) enableRawMode() {
	if c.inputCustom {
		// 输入源已被注入（测试或脚本化确认），不碰真实终端
		return
	}
	info, err := os.Stdin.Stat()
	if err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return
	}
	restore, err := term.MakeRaw(os.Stdin.Fd())
	if err != nil {
		logger.Debug("终端原始模式不可用: %v", err)
		return
	}
	c.raw = true
	c.rawRestore = restore
}

/*
disableRawMode 恢复终端原始设置，进程退出前必须调用。

参数:
  - 无。

返回:
  - 无。
*/
func (c *Console) disableRawMode() {
	if c.rawRestore != nil {
		c.rawRestore()
		c.rawRestore = nil
	}
	c.raw = false
}

/*
printInterruptHint 输出空闲状态下的 Ctrl+C 提示。

参数:
  - 无。

返回:
  - 无。
*/
func (c *Console) printInterruptHint() {
	fmt.Fprintf(c.out, "%s输入 exit 退出控制台；运行中的模块可用 Ctrl+C 中止。%s\n",
		colorCode(c.color, palette.Gray),
		colorCode(c.color, palette.Reset),
	)
}

/*
ExecuteOnce 执行一条命令后返回，用于 -c 脚本模式。
该模式不渲染横幅，也不会安装信号处理器。

参数:
  - command (string): 待执行命令。

返回:
  - bool: 命令要求退出时返回 false。
*/
func (c *Console) ExecuteOnce(command string) bool {
	c.interactive = false
	return c.Execute(command)
}

/*
RunScript 执行分号或换行分隔的命令脚本，用于 -c 自动化模式。
引号内的分号与换行不会被拆分；脚本以 @ 开头时从文件读取命令。

参数:
  - script (string): 命令脚本或 @脚本文件路径。

返回:
  - bool: 脚本中未出现 exit 时返回 true。
*/
func (c *Console) RunScript(script string) bool {
	c.interactive = false

	script = strings.TrimSpace(script)
	if strings.HasPrefix(script, "@") {
		path := strings.TrimSpace(strings.TrimPrefix(script, "@"))
		content, err := os.ReadFile(path)
		if err != nil {
			logger.Error("读取脚本文件 %s 失败: %v", path, err)
			c.lastErr = err
			return true
		}
		script = string(content)
	}

	for _, line := range splitScript(script) {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if !c.Execute(line) {
			return false
		}
	}
	return true
}

/*
splitScript 按引号外的分号与换行拆分脚本。

参数:
  - script (string): 原始脚本。

返回:
  - []string: 拆分后的命令行。
*/
func splitScript(script string) []string {
	lines := make([]string, 0, 8)
	var builder strings.Builder
	quoted := false

	for _, char := range script {
		switch {
		case char == '"':
			quoted = !quoted
			builder.WriteRune(char)
		case (char == ';' || char == '\n') && !quoted:
			lines = append(lines, strings.TrimSpace(builder.String()))
			builder.Reset()
		default:
			builder.WriteRune(char)
		}
	}
	if strings.TrimSpace(builder.String()) != "" {
		lines = append(lines, strings.TrimSpace(builder.String()))
	}
	return lines
}

/*
Execute 解析并分发一条控制台命令。

参数:
  - line (string): 原始命令行。

返回:
  - bool: 控制台应继续运行时返回 true。
*/
func (c *Console) Execute(line string) bool {
	line = strings.TrimSpace(line)
	if line == "" {
		return true
	}

	c.history = append(c.history, line)
	c.editor.AppendHistory(line)
	arguments := parseCommand(line)
	command := strings.ToLower(arguments[0])

	switch command {
	case "help", "?", "h":
		c.cmdHelp(arguments[1:])
	case "show":
		c.cmdShow(arguments[1:])
	case "search":
		c.cmdSearch(strings.Join(arguments[1:], " "))
	case "use":
		c.cmdUse(arguments[1:])
	case "back":
		c.cmdBack()
	case "info":
		c.cmdInfo()
	case "set":
		c.cmdSet(arguments[1:], false)
	case "setg":
		c.cmdSet(arguments[1:], true)
	case "unset":
		c.cmdUnset(arguments[1:], false)
	case "unsetg":
		c.cmdUnset(arguments[1:], true)
	case "run", "exploit":
		c.cmdRun()
	case "sessions":
		c.cmdSessions()
	case "report":
		c.cmdReport(arguments[1:])
	case "history":
		c.cmdHistory(arguments[1:])
	case "echo":
		c.cmdEcho(arguments[1:])
	case "sleep":
		c.cmdSleep(arguments[1:])
	case "source":
		c.cmdSource(arguments[1:])
	case "repeat":
		c.cmdRepeat(arguments[1:])
	case "watch":
		c.cmdWatch(arguments[1:])
	case "save":
		c.cmdSave(arguments[1:])
	case "load":
		c.cmdLoad(arguments[1:])
	case "banner":
		printBanner(c.out, c.color, c.registry)
	case "dashboard":
		printDashboard(c.out, c.color, len(c.registry.List()), len(c.registry.Categories()), c.operator)
	case "clear", "cls":
		fmt.Fprint(c.out, "\033[2J\033[H")
	case "version":
		fmt.Fprintf(c.out, "%s v%s · %s\n", config.AppName, config.AppVersion, config.Developer)
	case "exit", "quit", "q":
		return false
	case "env":
		c.cmdEnv()
	default:
		c.warn("未知命令: %s；输入 help 查看命令列表", arguments[0])
	}
	return true
}

/*
cmdRun 执行当前选中模块。
无线注入等主动模块在执行前要求明确确认授权；Ctrl+C 只中止当前模块。

参数:
  - 无。

返回:
  - 无。
*/
func (c *Console) cmdRun() {
	if c.selected == nil {
		c.warn("尚未选择模块，先执行 search 与 use")
		return
	}

	if c.selected.Meta.Impact != "" && !c.confirmImpact() {
		c.warn("操作已取消")
		return
	}

	printSection(c.out, c.color, "执行 · "+c.selected.Meta.Name)
	fmt.Fprintf(c.out, "%s%s%s\n",
		colorCode(c.color, palette.Gray),
		c.selected.Meta.Summary,
		colorCode(c.color, palette.Reset),
	)

	ctx, cancel := context.WithCancel(context.Background())
	c.runMu.Lock()
	c.running = true
	c.runCancel = cancel
	c.runMu.Unlock()

	result, err := engine.Run(ctx, c.selected, c.options, c.out)
	c.lastErr = err

	c.runMu.Lock()
	c.running = false
	c.runCancel = nil
	c.runMu.Unlock()
	cancel()

	session := Session{
		Index:    len(c.sessions) + 1,
		Module:   c.selected.Meta.Name,
		Started:  result.Started,
		Duration: result.Duration,
		OK:       err == nil,
	}
	if err != nil {
		session.Error = err.Error()
	}
	c.sessions = append(c.sessions, session)

	if err != nil && !errors.Is(err, context.Canceled) {
		c.warn("模块执行失败，输入 sessions 查看记录")
	}
}

/*
confirmImpact 对主动模块执行授权确认。
必须输入 yes 才会继续，空回车与其它输入都视为拒绝。

参数:
  - 无。

返回:
  - bool: 操作员确认授权时返回 true。
*/
func (c *Console) confirmImpact() bool {
	fmt.Fprintf(c.out, "%s[授权确认]%s 模块 %s 的影响级别为「%s」。\n",
		colorCode(c.color, palette.Bold+palette.Red),
		colorCode(c.color, palette.Reset),
		c.selected.Meta.Name,
		c.selected.Meta.Impact,
	)

	answer, err := c.editor.ReadLine(c.inputSource(), c.out, "仅可对已获得书面授权的目标执行。输入 yes 继续：")
	if !c.interactive {
		// 脚本模式下输入不会由终端回显，补一个换行避免后续日志粘在提示符后面。
		fmt.Fprintln(c.out)
	}
	if err != nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(answer), "yes")
}

/*
inputSource 返回当前输入源：原始模式用标准输入，否则用注入的读取器。

参数:
  - 无。

返回:
  - io.Reader: 输入源。
*/
func (c *Console) inputSource() io.Reader {
	if c.raw {
		return os.Stdin
	}
	return c.reader
}

/*
installSignalHandler 安装一次 SIGINT 处理器。
模块运行期间 Ctrl+C 取消当前模块；空闲时只提示退出方式，不杀进程。

参数:
  - 无。

返回:
  - 无。
*/
func (c *Console) installSignalHandler() {
	c.signalOnce.Do(func() {
		c.signalCh = make(chan os.Signal, 1)
		signal.Notify(c.signalCh, os.Interrupt)

		go func() {
			for range c.signalCh {
				c.runMu.Lock()
				running := c.running
				cancel := c.runCancel
				c.runMu.Unlock()

				if running && cancel != nil {
					cancel()
					continue
				}
				fmt.Fprintln(c.out)
				c.printInterruptHint()
			}
		}()
	})
}

/*
cmdEnv 展示全局参数与当前模块参数。

参数:
  - 无。

返回:
  - 无。
*/
func (c *Console) cmdEnv() {
	printSection(c.out, c.color, "全局参数")
	if len(c.globals) == 0 {
		fmt.Fprintf(c.out, "%s未设置全局参数%s\n", colorCode(c.color, palette.Gray), colorCode(c.color, palette.Reset))
	} else {
		rows := make([][]string, 0, len(c.globals))
		for key, value := range c.globals {
			rows = append(rows, []string{key, value})
		}
		fmt.Fprint(c.out, renderTable(c.color, []string{"参数", "值"}, rows, 48))
	}

	if c.selected == nil {
		return
	}
	printSection(c.out, c.color, "当前模块参数")
	fmt.Fprint(c.out, renderTable(c.color,
		[]string{"参数", "当前值"},
		c.optionRows(),
		56,
	))
}

/*
optionRows 把当前模块参数整理为表格行。
敏感参数只显示占位符，避免操作员在录屏或共享终端时泄露凭证。

参数:
  - 无。

返回:
  - [][]string: 参数名与当前值。
*/
func (c *Console) optionRows() [][]string {
	rows := make([][]string, 0, len(c.selected.Meta.Options))
	for _, option := range c.selected.Meta.Options {
		value := c.options.Get(option.Name)
		if value == "" {
			value = option.Default
		}
		if isSensitiveOption(option.Name) && value != "" {
			value = "********"
		}
		rows = append(rows, []string{option.Name, dash(value)})
	}
	return rows
}

/*
isSensitiveOption 判断参数名是否携带凭证类信息。

参数:
  - name (string): 参数名。

返回:
  - bool: 属于敏感参数时返回 true。
*/
func isSensitiveOption(name string) bool {
	upper := strings.ToUpper(name)
	for _, fragment := range []string{"PASS", "TOKEN", "SECRET", "KEY", "COOKIE"} {
		if strings.Contains(upper, fragment) {
			return true
		}
	}
	return false
}

/*
dash 在值为空时返回占位符，避免表格出现空白单元格。

参数:
  - value (string): 原始值。

返回:
  - string: 原值或 “-”。
*/
func dash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}

/*
warn 输出控制台级别的黄色警告。

参数:
  - format (string): 格式化模板。
  - arguments (...any): 模板参数。

返回:
  - 无。
*/
func (c *Console) warn(format string, arguments ...any) {
	fmt.Fprintf(c.out, "%s[!] %s%s\n",
		colorCode(c.color, palette.Yellow),
		fmt.Sprintf(format, arguments...),
		colorCode(c.color, palette.Reset),
	)
}

/*
info 输出控制台级别的灰色提示。

参数:
  - format (string): 格式化模板。
  - arguments (...any): 模板参数。

返回:
  - 无。
*/
func (c *Console) info(format string, arguments ...any) {
	fmt.Fprintf(c.out, "%s[·] %s%s\n",
		colorCode(c.color, palette.Gray),
		fmt.Sprintf(format, arguments...),
		colorCode(c.color, palette.Reset),
	)
}

/*
success 输出控制台级别的绿色状态。

参数:
  - format (string): 格式化模板。
  - arguments (...any): 模板参数。

返回:
  - 无。
*/
func (c *Console) success(format string, arguments ...any) {
	fmt.Fprintf(c.out, "%s[+] %s%s\n",
		colorCode(c.color, palette.Green),
		fmt.Sprintf(format, arguments...),
		colorCode(c.color, palette.Reset),
	)
}

/*
parsePositiveInt 解析正整数参数，失败时返回错误。

参数:
  - value (string): 原始输入。
  - name (string): 参数名称，用于错误信息。

返回:
  - int: 解析结果。
  - error: 非正整数时返回错误。
*/
func parsePositiveInt(value string, name string) (int, error) {
	parsed, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("%s 必须是正整数", name)
	}
	return parsed, nil
}
