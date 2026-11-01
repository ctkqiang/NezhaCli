// mitre 模块移植自 MITRERedTeam 项目：战术/技术目录检索与执行映射。
package mitre

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/ctkqiang/nezha_cli/internal/model"
	"github.com/ctkqiang/nezha_cli/internal/modulekit"
	"github.com/ctkqiang/nezha_cli/pkg/logger"
)

// executorModules 把技术执行器映射到本控制台的原生模块。
// 映射为空表示没有原生自动化路径，必须人工验证。
var executorModules = map[string]string{
	"domain-discovery":         "whois",
	"subdomain-enumeration":    "subdomain",
	"certificate-transparency": "subdomain",
	"whois-enumeration":        "whois",
	"dns-enumeration":          "dns",
	"reverse-dns":              "dns",
	"live-host-discovery":      "lan",
	"port-discovery":           "portscan",
	"directory-enumeration":    "webdir",
	"endpoint-discovery":       "webdir",
	"git-exposure":             "webdir",
	"secret-discovery":         "webdir",
	"cve-detection":            "vecmap",
}

// Module 是 MITRE 战术目录模块。
type Module struct{}

/*
New 创建 MITRE 战术目录模块实例。

参数:
  - 无。

返回:
  - model.Module: 模块实例。
*/
func New() model.Module {
	return &Module{}
}

/*
Meta 返回 MITRE 战术目录模块的元数据。

参数:
  - 无。

返回:
  - model.Meta: 模块名称、类别、说明与参数声明。
*/
func (m *Module) Meta() model.Meta {
	return model.Meta{
		Name:     "mitre",
		Aliases:  []string{"tactics", "techniques", "mitreredteam"},
		Category: modulekit.CategorySystem,
		Summary:  "MITRE 战术/技术目录与执行映射",
		Description: "检索内置 BB01-BB25 战术目录与 27 条技术，并映射到本控制台原生模块。\n" +
			"适用于授权评估的规划阶段：浏览战术、按条件过滤技术、查看单条详情。\n" +
			"只做目录检索与命令规划，不自动编排任何超出声明范围的动作；\n" +
			"数据与上游 catalog/*.json 一致，显式执行、证据优先。\n" +
			"可与 whois/dns/portscan 等模块配合，按目录映射落地执行。",
		Usage: "use mitre\n" +
			"set TACTIC BB01\n" +
			"set QUERY dns\n" +
			"run",
		Author: modulekit.Author,
		References: []string{
			"https://github.com/ctkqiang/NezhaCli",
			"https://attack.mitre.org/",
		},
		Options: []model.Option{
			modulekit.Option("TACTIC", "按战术过滤；支持编号如 BB01 或中文名如 侦察", false, ""),
			modulekit.Option("QUERY", "按编号/名称/描述/执行器检索；可与 TACTIC 叠加过滤", false, ""),
			modulekit.Option("TECHNIQUE", "查看单条技术详情如 BB10.001；设置后优先于其它过滤条件", false, ""),
		},
	}
}

/*
Run 输出战术总览、过滤后的技术列表或单条技术详情。

参数:
  - ctx (context.Context): 执行上下文。
  - options (model.Options): 已合并默认值的模块参数。
  - out (io.Writer): 结果输出目标。

返回:
  - error: 指定的技术编号不存在时返回错误。
*/
func (m *Module) Run(ctx context.Context, options model.Options, out io.Writer) error {
	_ = ctx

	techniqueID := strings.ToUpper(strings.TrimSpace(options.Get("TECHNIQUE")))
	if techniqueID != "" {
		technique, ok := findTechnique(techniqueID)
		if !ok {
			return fmt.Errorf("技术 %s 不在目录中", techniqueID)
		}
		printTechniqueDetail(out, technique)
		return nil
	}

	tacticFilter := strings.TrimSpace(options.Get("TACTIC"))
	query := strings.ToLower(strings.TrimSpace(options.Get("QUERY")))

	if tacticFilter == "" && query == "" {
		printTactics(out)
		return nil
	}

	matched := filterTechniques(tacticFilter, query)
	rows := make([][]string, 0, len(matched))
	for _, technique := range matched {
		rows = append(rows, []string{
			technique.ID,
			technique.Name,
			tacticName(technique.Tactic),
			modeLabel(technique.Mode),
			modulekit.Etc(strings.Join(technique.MITRE, ","), 18),
			moduleLabel(technique.Executor),
		})
	}

	modulekit.Section(out, fmt.Sprintf("技术 · 命中 %d", len(rows)))
	if len(rows) == 0 {
		fmt.Fprintln(out, "没有匹配的技术，可先执行 show categories 之外的检索条件。")
		return nil
	}
	modulekit.Table(out, []string{"编号", "名称", "战术", "模式", "ATT&CK", "原生模块"}, rows, 38)

	logger.Info("mitre 目录检索完成：命中 %d 条技术", len(rows))
	return nil
}

/*
printTactics 输出全部战术总览。

参数:
  - out (io.Writer): 结果输出目标。

返回:
  - 无。
*/
func printTactics(out io.Writer) {
	rows := make([][]string, 0, len(Tactics))
	for _, tactic := range Tactics {
		count := 0
		for _, technique := range Techniques {
			if technique.Tactic == tactic.ID {
				count++
			}
		}
		rows = append(rows, []string{tactic.ID, tactic.Name, fmt.Sprintf("%d 条已定义", count), modulekit.Etc(tactic.Description, 44)})
	}

	modulekit.Section(out, fmt.Sprintf("战术目录 %d", len(Tactics)))
	modulekit.Table(out, []string{"编号", "战术", "技术", "说明"}, rows, 44)
	fmt.Fprintln(out, "使用 set TACTIC BBxx 查看该战术下已定义的技术；set TECHNIQUE BBxx.xxx 查看单条详情。")
}

/*
printTechniqueDetail 输出单条技术的详情与执行建议。

参数:
  - out (io.Writer): 结果输出目标。
  - technique (Technique): 目标技术。

返回:
  - 无。
*/
func printTechniqueDetail(out io.Writer, technique Technique) {
	tools := "-"
	if len(technique.Tools) > 0 {
		tools = strings.Join(technique.Tools, ", ")
	}
	mitreIDs := "-"
	if len(technique.MITRE) > 0 {
		mitreIDs = strings.Join(technique.MITRE, ", ")
	}

	modulekit.Section(out, "技术 · "+technique.ID+" "+technique.Name)
	modulekit.KeyValues(out, [][2]string{
		{"战术", tacticName(technique.Tactic)},
		{"模式", modeLabel(technique.Mode)},
		{"上游工具", tools},
		{"ATT&CK", mitreIDs},
		{"原生模块", moduleLabel(technique.Executor)},
		{"说明", technique.Description},
	}, 56)

	if technique.Executor == "sql-injection" {
		fmt.Fprintln(out, "提示: SQL 注入没有原生自动化检测器；先 use payloads 挑选盲注字典，再人工构造验证。")
	}
}

/*
filterTechniques 按战术与关键词过滤技术列表。

参数:
  - tacticFilter (string): 战术过滤条件，支持编号或名称。
  - query (string): 关键词，命中编号、名称或描述。

返回:
  - []Technique: 过滤后的技术列表。
*/
func filterTechniques(tacticFilter string, query string) []Technique {
	tacticID := normalizeTactic(tacticFilter)
	matched := make([]Technique, 0, len(Techniques))
	for _, technique := range Techniques {
		if tacticID != "" && technique.Tactic != tacticID {
			continue
		}
		if query != "" {
			haystack := strings.ToLower(technique.ID + " " + technique.Name + " " + technique.Description + " " + technique.Executor)
			if !strings.Contains(haystack, query) {
				continue
			}
		}
		matched = append(matched, technique)
	}
	return matched
}

/*
findTechnique 按编号查找技术。

参数:
  - id (string): 技术编号。

返回:
  - Technique: 匹配的技术。
  - bool: 是否存在。
*/
func findTechnique(id string) (Technique, bool) {
	for _, technique := range Techniques {
		if strings.EqualFold(technique.ID, id) {
			return technique, true
		}
	}
	return Technique{}, false
}

/*
normalizeTactic 把战术名称归一化为编号。

参数:
  - value (string): 编号或名称。

返回:
  - string: 战术编号；无法匹配时原样返回（由过滤逻辑兜底）。
*/
func normalizeTactic(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	upper := strings.ToUpper(value)
	if strings.HasPrefix(upper, "BB") {
		return upper
	}
	for _, tactic := range Tactics {
		if tactic.Name == value {
			return tactic.ID
		}
	}
	return value
}

/*
tacticName 返回战术编号对应的中文名称。

参数:
  - id (string): 战术编号。

返回:
  - string: 战术名称，未知编号返回编号本身。
*/
func tacticName(id string) string {
	for _, tactic := range Tactics {
		if tactic.ID == id {
			return id + " " + tactic.Name
		}
	}
	return id
}

/*
modeLabel 返回技术执行模式的中文标签。

参数:
  - mode (string): 上游模式字段。

返回:
  - string: 中文标签。
*/
func modeLabel(mode string) string {
	switch mode {
	case "active":
		return "主动"
	case "passive":
		return "被动"
	case "manual":
		return "人工"
	default:
		return mode
	}
}

/*
moduleLabel 返回执行器映射到的原生模块名，无映射时返回“人工”。

参数:
  - executor (string): 执行器名称。

返回:
  - string: 原生模块名或“人工”。
*/
func moduleLabel(executor string) string {
	if moduleName, ok := executorModules[executor]; ok {
		return moduleName
	}
	return "人工"
}
