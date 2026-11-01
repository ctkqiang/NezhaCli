package structure

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ctkqiang/nezha_cli/internal/core"
	"github.com/ctkqiang/nezha_cli/internal/model"
	"github.com/ctkqiang/nezha_cli/pkg/config"
	"github.com/ctkqiang/nezha_cli/pkg/logger"
)

/*
cmdHelp 输出命令帮助；带参数时输出单个命令的用法。

参数:
  - arguments ([]string): help 之后的参数。

返回:
  - 无。
*/
func (c *Console) cmdHelp(arguments []string) {
	if len(arguments) > 0 {
		c.printCommandHelp(arguments[0])
		return
	}

	printSection(c.out, c.color, "命令")
	fmt.Fprint(c.out, renderTable(
		[]string{"命令", "用途"},
		[][]string{
			{"help [命令]", "查看总览或单条命令用法"},
			{"search <关键词>", "按名称、类别或描述检索模块"},
			{"show modules", "列出全部模块"},
			{"show options", "查看当前模块参数"},
			{"use <序号|名称>", "选中模块"},
			{"info", "查看当前模块详情"},
			{"set <参数> <值>", "设置当前模块参数"},
			{"setg <参数> <值>", "设置全局参数，切换模块后仍生效"},
			{"unset <参数>", "清除当前模块参数"},
			{"run", "执行当前模块；别名 exploit"},
			{"sessions", "查看本次会话的执行记录"},
			{"report [文件]", "导出本次会话为 Markdown 报告"},
			{"repeat <次数> <间隔> <命令>", "周期性重复执行命令"},
			{"watch <间隔> <命令>", "无限轮询直到 Ctrl+C"},
			{"sleep <时长>", "脚本休眠，例如 sleep 2s"},
			{"echo <文本>", "脚本输出文本"},
			{"source <脚本文件>", "逐行执行脚本文件"},
			{"save / load <文件>", "保存 / 恢复控制台状态"},
			{"back", "取消模块选择"},
			{"banner / dashboard", "重绘横幅或仪表盘"},
			{"clear / history / env", "清屏 / 命令历史 / 参数总览"},
			{"exit", "退出控制台"},
		},
		52,
	))

	printSection(c.out, c.color, "工作流")
	fmt.Fprintf(c.out, "  %s1.%s search web          # 找模块\n", colorCode(c.color, palette.Green), colorCode(c.color, palette.Reset))
	fmt.Fprintf(c.out, "  %s2.%s use web              # 选中\n", colorCode(c.color, palette.Green), colorCode(c.color, palette.Reset))
	fmt.Fprintf(c.out, "  %s3.%s set URL https://...  # 配参\n", colorCode(c.color, palette.Green), colorCode(c.color, palette.Reset))
	fmt.Fprintf(c.out, "  %s4.%s run                  # 执行\n\n", colorCode(c.color, palette.Green), colorCode(c.color, palette.Reset))
}

/*
printCommandHelp 输出单条命令的语法说明。

参数:
  - command (string): 命令名称。

返回:
  - 无。
*/
func (c *Console) printCommandHelp(command string) {
	topics := map[string]string{
		"use":      "use <序号|名称>\n  选中模块并载入默认参数。序号来自 show modules。",
		"set":      "set <参数> <值>\n  设置当前模块参数。含空格的值用双引号包裹。",
		"setg":     "setg <参数> <值>\n  设置全局参数，切换模块后仍保留。",
		"run":      "run\n  执行当前模块。主动模块会要求输入 yes 确认授权。",
		"search":   "search <关键词>\n  在名称、别名、类别与描述中检索，多关键词为与关系。",
		"show":     "show modules | options | categories | globals\n  查看模块、参数、类别或全局变量。",
		"sessions": "sessions\n  查看本次控制台会话的模块执行记录。",
		"report":   "report [文件路径]\n  把本次会话的执行记录、模块参数与命令历史导出为 Markdown 报告，默认 nezha-report.md。",
		"repeat":   "repeat <次数> <间隔> <命令...>\n  周期性重复执行命令，例如 repeat 5 1s run；Ctrl+C 中断剩余循环。",
		"watch":    "watch <间隔> <命令...>\n  以固定间隔无限执行命令，例如 watch 5s run；Ctrl+C 停止。",
		"sleep":    "sleep <时长>\n  按 Go 时长语法休眠，例如 sleep 500ms / sleep 2s / sleep 1m。",
		"source":   "source <脚本文件>\n  逐行执行脚本文件中的命令，错误不中断后续行。",
		"save":     "save <状态文件>\n  把全局参数、当前模块参数与命令历史导出为 JSON（权限 0600）。",
		"load":     "load <状态文件>\n  从 JSON 状态文件恢复参数与历史；含模块名时自动选中。",
		"echo":     "echo <文本...>\n  原样输出文本，用于脚本进度标记。",
		"back":     "back\n  取消模块选择，参数仍保留在全局变量中。",
	}

	topic, ok := topics[strings.ToLower(command)]
	if !ok {
		c.warn("没有 %s 的帮助条目", command)
		return
	}
	printSection(c.out, c.color, "用法")
	fmt.Fprintln(c.out, topic)
	fmt.Fprintln(c.out)
}

/*
cmdShow 处理 show 子命令。

参数:
  - arguments ([]string): show 之后的参数。

返回:
  - 无。
*/
func (c *Console) cmdShow(arguments []string) {
	topic := "modules"
	if len(arguments) > 0 {
		topic = strings.ToLower(arguments[0])
	}

	switch topic {
	case "modules", "all":
		c.printModules(c.registry.List())
	case "options":
		c.printOptions()
	case "categories":
		c.printCategories()
	case "globals":
		c.cmdEnv()
	default:
		c.warn("未知 show 目标: %s", topic)
	}
}

/*
printModules 渲染模块清单。

参数:
  - entries ([]*core.Entry): 待展示模块。

返回:
  - 无。
*/
func (c *Console) printModules(entries []*core.Entry) {
	if len(entries) == 0 {
		c.warn("没有匹配的模块")
		return
	}

	rows := make([][]string, 0, len(entries))
	for _, entry := range entries {
		impact := dash(entry.Meta.Impact)
		rows = append(rows, []string{
			strconv.Itoa(entry.Index),
			entry.Meta.Name,
			entry.Meta.Category,
			impact,
			entry.Meta.Summary,
		})
	}

	printSection(c.out, c.color, fmt.Sprintf("模块 %d", len(rows)))
	fmt.Fprint(c.out, renderTable(
		[]string{"#", "模块", "类别", "影响", "说明"},
		rows,
		44,
	))
	fmt.Fprintf(c.out, "%s使用 use <序号|名称> 选中模块。%s\n",
		colorCode(c.color, palette.Gray),
		colorCode(c.color, palette.Reset),
	)
}

/*
printOptions 渲染当前模块的参数表。

参数:
  - 无。

返回:
  - 无。
*/
func (c *Console) printOptions() {
	if c.selected == nil {
		c.warn("尚未选择模块，先执行 use <序号|名称>")
		return
	}

	rows := make([][]string, 0, len(c.selected.Meta.Options))
	for _, option := range c.selected.Meta.Options {
		value := c.options.Get(option.Name)
		if value == "" {
			value = option.Default
		}
		if isSensitiveOption(option.Name) && value != "" {
			value = "********"
		}

		required := "否"
		if option.Required {
			required = "是"
		}
		rows = append(rows, []string{
			option.Name,
			required,
			dash(option.Default),
			dash(value),
			option.Description,
		})
	}

	printSection(c.out, c.color, "参数 · "+c.selected.Meta.Name)
	fmt.Fprint(c.out, renderTable(
		[]string{"参数", "必填", "默认", "当前", "说明"},
		rows,
		40,
	))
}

/*
printCategories 渲染模块类别与数量。

参数:
  - 无。

返回:
  - 无。
*/
func (c *Console) printCategories() {
	counts := make(map[string]int, 8)
	for _, entry := range c.registry.List() {
		counts[entry.Meta.Category]++
	}

	names := make([]string, 0, len(counts))
	for name := range counts {
		names = append(names, name)
	}
	sort.Strings(names)

	rows := make([][]string, 0, len(names))
	for _, name := range names {
		rows = append(rows, []string{name, strconv.Itoa(counts[name])})
	}

	printSection(c.out, c.color, "类别")
	fmt.Fprint(c.out, renderTable([]string{"类别", "模块数"}, rows, 30))
}

/*
cmdSearch 按关键词检索模块并渲染结果。

参数:
  - keyword (string): 检索词，可为空。

返回:
  - 无。
*/
func (c *Console) cmdSearch(keyword string) {
	entries := c.registry.Search(keyword)
	if keyword == "" {
		c.info("未提供关键词，展示全部模块")
	}
	c.printModules(entries)
}

/*
cmdUse 选中模块并载入默认参数与全局参数。

参数:
  - arguments ([]string): use 之后的参数。

返回:
  - 无。
*/
func (c *Console) cmdUse(arguments []string) {
	if len(arguments) == 0 {
		c.warn("用法: use <序号|名称>")
		return
	}

	key := strings.Join(arguments, " ")
	entry, ok := c.registry.Get(key)
	if !ok {
		c.warn("找不到模块: %s", key)
		return
	}

	c.selectEntry(entry)

	c.success("已选中 %s", entry.Meta.Name)
	c.printModuleCard(entry)
}

/*
SelectModule 在不输出提示的情况下选中模块，供 -m 启动参数使用。

参数:
  - name (string): 模块名、别名或序号。

返回:
  - error: 模块不存在时返回错误。
*/
func (c *Console) SelectModule(name string) error {
	entry, ok := c.registry.Get(name)
	if !ok {
		return fmt.Errorf("找不到模块: %s", name)
	}
	c.selectEntry(entry)
	return nil
}

/*
selectEntry 载入模块默认参数，并用全局参数覆盖同名项。

参数:
  - entry (*core.Entry): 待选中的模块。

返回:
  - 无。
*/
func (c *Console) selectEntry(entry *core.Entry) {
	c.selected = entry
	c.options = core.Defaults(entry.Meta)
	for _, option := range entry.Meta.Options {
		if value, exists := c.globals[option.Name]; exists && value != "" {
			c.options[option.Name] = value
		}
	}
}

/*
cmdBack 取消当前模块选择。

参数:
  - 无。

返回:
  - 无。
*/
func (c *Console) cmdBack() {
	if c.selected == nil {
		c.info("当前没有选中模块")
		return
	}
	name := c.selected.Meta.Name
	c.selected = nil
	c.options = make(model.Options)
	c.info("已退出模块 %s", name)
}

/*
cmdInfo 输出当前模块的完整信息卡。

参数:
  - 无。

返回:
  - 无。
*/
func (c *Console) cmdInfo() {
	if c.selected == nil {
		c.warn("尚未选择模块，先执行 use <序号|名称>")
		return
	}
	c.printModuleCard(c.selected)
}

/*
printModuleCard 渲染模块详情与参数摘要。

参数:
  - entry (*core.Entry): 模块记录。

返回:
  - 无。
*/
func (c *Console) printModuleCard(entry *core.Entry) {
	printSection(c.out, c.color, "模块 · "+entry.Meta.Name)
	rows := [][]string{
		{"名称", entry.Meta.Name},
		{"类别", entry.Meta.Category},
		{"影响", dash(entry.Meta.Impact)},
		{"作者", dash(entry.Meta.Author)},
		{"说明", entry.Meta.Description},
	}
	fmt.Fprint(c.out, renderTable([]string{"字段", "值"}, rows, 60))

	if len(entry.Meta.Options) > 0 {
		printSection(c.out, c.color, "参数")
		optionRows := make([][]string, 0, len(entry.Meta.Options))
		for _, option := range entry.Meta.Options {
			required := "否"
			if option.Required {
				required = "是"
			}
			optionRows = append(optionRows, []string{
				option.Name,
				required,
				dash(option.Default),
				option.Description,
			})
		}
		fmt.Fprint(c.out, renderTable([]string{"参数", "必填", "默认", "说明"}, optionRows, 40))
	}

	if len(entry.Meta.References) > 0 {
		fmt.Fprintf(c.out, "%s参考: %s%s\n",
			colorCode(c.color, palette.Gray),
			strings.Join(entry.Meta.References, " · "),
			colorCode(c.color, palette.Reset),
		)
	}
	fmt.Fprintln(c.out)
}

/*
cmdSet 设置当前模块参数或全局参数。

参数:
  - arguments ([]string): 参数名与值。
  - global (bool): true 表示写入全局参数。

返回:
  - 无。
*/
func (c *Console) cmdSet(arguments []string, global bool) {
	if len(arguments) < 2 {
		if global {
			c.warn("用法: setg <参数> <值>")
		} else {
			c.warn("用法: set <参数> <值>")
		}
		return
	}

	key := strings.ToUpper(arguments[0])
	value := strings.Join(arguments[1:], " ")

	if global {
		c.globals[key] = value
		if c.selected != nil && c.hasOption(key) {
			c.options[key] = value
		}
		c.success("全局参数 %s = %s", key, value)
		return
	}

	if c.selected == nil {
		c.warn("尚未选择模块；全局参数请使用 setg")
		return
	}
	if !c.hasOption(key) {
		c.warn("模块 %s 没有参数 %s；输入 show options 查看可用参数", c.selected.Meta.Name, key)
		return
	}

	c.options[key] = value
	c.success("%s = %s", key, value)
}

/*
hasOption 判断当前模块是否声明了指定参数。

参数:
  - key (string): 参数名。

返回:
  - bool: 存在时返回 true。
*/
func (c *Console) hasOption(key string) bool {
	if c.selected == nil {
		return false
	}
	for _, option := range c.selected.Meta.Options {
		if strings.EqualFold(option.Name, key) {
			return true
		}
	}
	return false
}

/*
cmdUnset 清除模块参数或全局参数，并恢复模块默认值。

参数:
  - arguments ([]string): 参数名。
  - global (bool): true 表示清除全局参数。

返回:
  - 无。
*/
func (c *Console) cmdUnset(arguments []string, global bool) {
	if len(arguments) == 0 {
		if global {
			c.warn("用法: unsetg <参数>")
		} else {
			c.warn("用法: unset <参数>")
		}
		return
	}

	key := strings.ToUpper(arguments[0])
	if global {
		delete(c.globals, key)
		c.success("已清除全局参数 %s", key)
		return
	}

	if c.selected == nil {
		c.warn("尚未选择模块")
		return
	}
	delete(c.options, key)

	for _, option := range c.selected.Meta.Options {
		if strings.EqualFold(option.Name, key) && option.Default != "" {
			c.options[option.Name] = option.Default
			break
		}
	}
	c.success("已清除参数 %s", key)
}

/*
cmdSessions 渲染本次控制台的模块执行记录。

参数:
  - 无。

返回:
  - 无。
*/
func (c *Console) cmdSessions() {
	if len(c.sessions) == 0 {
		c.info("本次会话还没有执行记录")
		return
	}

	rows := make([][]string, 0, len(c.sessions))
	for _, session := range c.sessions {
		status := "成功"
		if !session.OK {
			status = "失败"
		}
		rows = append(rows, []string{
			strconv.Itoa(session.Index),
			session.Module,
			session.Started.Format("15:04:05"),
			session.Duration.Round(time.Millisecond).String(),
			status,
			dash(session.Error),
		})
	}

	printSection(c.out, c.color, "执行记录")
	fmt.Fprint(c.out, renderTable(
		[]string{"#", "模块", "开始", "耗时", "状态", "错误"},
		rows,
		42,
	))
}

/*
cmdHistory 输出命令历史及序号；携带 -c 或 clear 时清空历史。

参数:
  - arguments ([]string): history 之后的参数。

返回:
  - 无。
*/
func (c *Console) cmdHistory(arguments []string) {
	if len(arguments) > 0 && (arguments[0] == "-c" || arguments[0] == "clear") {
		c.history = nil
		c.info("命令历史已清空")
		return
	}

	if len(c.history) == 0 {
		c.info("暂无命令历史")
		return
	}

	start := 0
	if len(c.history) > 20 {
		start = len(c.history) - 20
	}
	printSection(c.out, c.color, "命令历史")
	for index := start; index < len(c.history); index++ {
		fmt.Fprintf(c.out, "  %s%3d%s  %s\n",
			colorCode(c.color, palette.Gray),
			index+1,
			colorCode(c.color, palette.Reset),
			c.history[index],
		)
	}
}

/*
cmdReport 把本次会话的执行记录导出为 Markdown 报告。
报告包含应用版本、操作员、生成时间、会话记录与当前模块参数；
敏感参数在报告中同样脱敏。该命令移植自 QianKunQuan 的报告生成能力。

参数:
  - arguments ([]string): 可选输出路径，默认 nezha-report.md。

返回:
  - 无；写入失败时输出警告。
*/
func (c *Console) cmdReport(arguments []string) {
	path := "nezha-report.md"
	if len(arguments) > 0 && strings.TrimSpace(arguments[0]) != "" {
		path = strings.TrimSpace(arguments[0])
	}

	var builder strings.Builder
	builder.WriteString("# 哪吒网络安全终端 · 评估报告\n\n")
	builder.WriteString("> 在阴影中观察，在授权下行动。\n\n")
	builder.WriteString("| 项目 | 值 |\n|---|---|\n")
	fmt.Fprintf(&builder, "| 应用 | %s v%s |\n", config.AppName, config.AppVersion)
	fmt.Fprintf(&builder, "| 操作员 | %s |\n", c.operator)
	fmt.Fprintf(&builder, "| 生成时间 | %s |\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(&builder, "| 内置模块 | %d |\n\n", len(c.registry.List()))

	builder.WriteString("## 授权声明\n\n")
	builder.WriteString("本报告仅记录授权范围内的评估活动。主动模块执行前均经过 yes 授权确认；未获书面授权的目标严禁测试。\n\n")

	builder.WriteString("## 会话执行记录\n\n")
	if len(c.sessions) == 0 {
		builder.WriteString("本次会话没有模块执行记录。\n\n")
	} else {
		builder.WriteString("| # | 模块 | 开始 | 耗时 | 状态 | 错误 |\n|---|---|---|---|---|---|\n")
		for _, session := range c.sessions {
			status := "成功"
			if !session.OK {
				status = "失败"
			}
			detail := "-"
			if session.Error != "" {
				detail = session.Error
			}
			fmt.Fprintf(&builder, "| %d | %s | %s | %s | %s | %s |\n",
				session.Index,
				session.Module,
				session.Started.Format("15:04:05"),
				session.Duration.Round(time.Millisecond).String(),
				status,
				detail,
			)
		}
		builder.WriteString("\n")
	}

	if c.selected != nil {
		builder.WriteString("## 当前模块参数\n\n")
		builder.WriteString("| 参数 | 当前值 |\n|---|---|\n")
		for _, option := range c.selected.Meta.Options {
			value := c.options.Get(option.Name)
			if value == "" {
				value = option.Default
			}
			if isSensitiveOption(option.Name) && value != "" {
				value = "********"
			}
			fmt.Fprintf(&builder, "| %s | %s |\n", option.Name, value)
		}
		builder.WriteString("\n")
	}

	builder.WriteString("## 命令历史（最近 20 条）\n\n```text\n")
	start := 0
	if len(c.history) > 20 {
		start = len(c.history) - 20
	}
	for index := start; index < len(c.history); index++ {
		builder.WriteString(c.history[index] + "\n")
	}
	builder.WriteString("```\n")

	if err := os.WriteFile(path, []byte(builder.String()), 0o644); err != nil {
		c.warn("写入报告失败: %v", err)
		return
	}
	logger.Success("报告已导出: %s", path)
}
