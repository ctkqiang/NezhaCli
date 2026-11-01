// ops.go 承载战场脚本化控制命令：echo、sleep、source、repeat、watch、save 与 load。
// 这些命令让控制台可以作为无交互脚本引擎运行，且全部具备取消与错误恢复边界。
package structure

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ctkqiang/nezha_cli/internal/model"
	"github.com/ctkqiang/nezha_cli/pkg/logger"
)

/*
LastError 返回脚本模式下最近一次模块执行的错误。
命令行入口据此决定退出码：有错误退出 1，保证自动化流水线可感知失败。

参数:
  - 无。

返回:
  - error: 最近一次执行错误；从未出错返回 nil。
*/
func (c *Console) LastError() error {
	return c.lastErr
}

/*
cmdEcho 输出参数原文，用于脚本打印进度与标记。

参数:
  - arguments ([]string): 待输出内容。

返回:
  - 无。
*/
func (c *Console) cmdEcho(arguments []string) {
	fmt.Fprintln(c.out, strings.Join(arguments, " "))
}

/*
cmdSleep 按 Go 时长语法休眠，例如 500ms、2s、1m。
休眠期间可被 Ctrl+C 取消；负数视为非法。

参数:
  - arguments ([]string): 第一个参数为时长。

返回:
  - 无。
*/
func (c *Console) cmdSleep(arguments []string) {
	if len(arguments) == 0 {
		c.warn("用法: sleep <时长>，例如 sleep 2s")
		return
	}
	duration, err := time.ParseDuration(arguments[0])
	if err != nil {
		c.warn("时长格式非法: %v", err)
		return
	}
	if duration < 0 {
		c.warn("时长不能为负数")
		return
	}

	ctx, cancel := c.scopedCancel()
	defer cancel()

	select {
	case <-time.After(duration):
	case <-ctx.Done():
		c.info("休眠已取消")
	}
}

/*
cmdSource 逐行执行脚本文件中的命令，错误不中断后续行。

参数:
  - arguments ([]string): 脚本文件路径。

返回:
  - 无。
*/
func (c *Console) cmdSource(arguments []string) {
	if len(arguments) == 0 {
		c.warn("用法: source <脚本文件>")
		return
	}
	content, err := os.ReadFile(arguments[0])
	if err != nil {
		c.warn("读取脚本失败: %v", err)
		c.lastErr = err
		return
	}

	for _, line := range splitScript(string(content)) {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fmt.Fprintf(c.out, "%s· %s%s\n",
			colorCode(c.color, palette.Gray), line, colorCode(c.color, palette.Reset))
		if !c.Execute(line) {
			return
		}
	}
	logger.Info("脚本 %s 执行完毕", arguments[0])
}

/*
cmdRepeat 把一条命令重复执行 N 次，每次间隔指定时长。
适用于周期探测；Ctrl+C 立即中断剩余循环。

参数:
  - arguments ([]string): 次数、间隔与待执行命令。

返回:
  - 无。
*/
func (c *Console) cmdRepeat(arguments []string) {
	if len(arguments) < 3 {
		c.warn("用法: repeat <次数> <间隔> <命令...>，例如 repeat 5 1s run")
		return
	}
	count, err := strconv.Atoi(arguments[0])
	if err != nil || count < 1 {
		c.warn("次数必须是正整数")
		return
	}
	interval, err := time.ParseDuration(arguments[1])
	if err != nil || interval < 0 {
		c.warn("间隔格式非法: %v", err)
		return
	}

	command := strings.Join(arguments[2:], " ")
	ctx, cancel := c.scopedCancel()
	defer cancel()

	for index := 0; index < count; index++ {
		select {
		case <-ctx.Done():
			c.info("repeat 已取消，完成 %d/%d 次", index, count)
			return
		default:
		}

		fmt.Fprintf(c.out, "%s── 第 %d/%d 次 ──%s\n",
			colorCode(c.color, palette.Gray), index+1, count, colorCode(c.color, palette.Reset))
		if !c.Execute(command) {
			return
		}

		if index < count-1 {
			select {
			case <-time.After(interval):
			case <-ctx.Done():
				c.info("repeat 已取消")
				return
			}
		}
	}
}

/*
cmdWatch 以固定间隔无限执行一条命令，直到 Ctrl+C 或命令请求退出。
适用于存活监控与状态轮询。

参数:
  - arguments ([]string): 间隔与待执行命令。

返回:
  - 无。
*/
func (c *Console) cmdWatch(arguments []string) {
	if len(arguments) < 2 {
		c.warn("用法: watch <间隔> <命令...>，例如 watch 5s run")
		return
	}
	interval, err := time.ParseDuration(arguments[0])
	if err != nil || interval <= 0 {
		c.warn("间隔格式非法: %v", err)
		return
	}

	command := strings.Join(arguments[1:], " ")
	ctx, cancel := c.scopedCancel()
	defer cancel()

	round := 0
	for {
		round++
		fmt.Fprintf(c.out, "%s── 第 %d 轮 ──%s\n",
			colorCode(c.color, palette.Gray), round, colorCode(c.color, palette.Reset))
		if !c.Execute(command) {
			return
		}

		select {
		case <-time.After(interval):
		case <-ctx.Done():
			c.info("watch 已取消，共执行 %d 轮", round)
			return
		}
	}
}

/*
cmdSave 把全局参数、当前模块参数与命令历史导出为 JSON 状态文件。
文件权限 0600，防止敏感参数被同机其他用户读取。

参数:
  - arguments ([]string): 输出文件路径。

返回:
  - 无。
*/
func (c *Console) cmdSave(arguments []string) {
	if len(arguments) == 0 {
		c.warn("用法: save <状态文件>")
		return
	}

	state := consoleState{
		Globals: map[string]string(c.globals),
		Options: map[string]string(c.options),
		History: c.history,
	}
	if c.selected != nil {
		state.Module = c.selected.Meta.Name
	}

	content, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		c.warn("序列化状态失败: %v", err)
		return
	}
	if err := os.WriteFile(arguments[0], content, 0o600); err != nil {
		c.warn("写入状态文件失败: %v", err)
		return
	}
	logger.Success("状态已保存: %s", arguments[0])
}

/*
cmdLoad 从 JSON 状态文件恢复全局参数、模块参数与命令历史。
文件中的模块名存在时会自动选中该模块。

参数:
  - arguments ([]string): 状态文件路径。

返回:
  - 无。
*/
func (c *Console) cmdLoad(arguments []string) {
	if len(arguments) == 0 {
		c.warn("用法: load <状态文件>")
		return
	}

	content, err := os.ReadFile(arguments[0])
	if err != nil {
		c.warn("读取状态文件失败: %v", err)
		return
	}

	var state consoleState
	if err := json.Unmarshal(content, &state); err != nil {
		c.warn("状态文件格式非法: %v", err)
		return
	}

	if state.Globals != nil {
		c.globals = model.Options(state.Globals)
	}
	if state.Options != nil {
		c.options = model.Options(state.Options)
	}
	if state.History != nil {
		c.history = state.History
	}
	if state.Module != "" {
		if _, ok := c.registry.Get(state.Module); ok {
			_ = c.SelectModule(state.Module)
		} else {
			c.warn("状态中的模块 %s 不在注册表中，已跳过", state.Module)
		}
	}
	logger.Success("状态已恢复: %s", arguments[0])
}

/*
scopedCancel 注册一段可被 Ctrl+C 取消的等待上下文。
与模块运行共用同一信号处理器：SIGINT 优先取消当前等待。

参数:
  - 无。

返回:
  - context.Context: 取消上下文。
  - context.CancelFunc: 释放函数。
*/
func (c *Console) scopedCancel() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	c.runMu.Lock()
	c.running = true
	c.runCancel = cancel
	c.runMu.Unlock()

	go func() {
		<-ctx.Done()
		c.runMu.Lock()
		if c.runCancel != nil {
			c.running = false
			c.runCancel = nil
		}
		c.runMu.Unlock()
	}()
	return ctx, cancel
}

// consoleState 是可序列化的控制台状态快照。
type consoleState struct {
	Module  string            `json:"module,omitempty"`
	Globals map[string]string `json:"globals,omitempty"`
	Options map[string]string `json:"options,omitempty"`
	History []string          `json:"history,omitempty"`
}
