// payloads 模块移植自作者的 BlindSQL 项目：盲注 payload 加载器。
package payloads

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ctkqiang/nezha_cli/internal/model"
	"github.com/ctkqiang/nezha_cli/internal/modulekit"
	"github.com/ctkqiang/nezha_cli/pkg/logger"
)

// Module 是盲注 payload 库模块。
type Module struct{}

/*
New 创建盲注 payload 库模块实例。

参数:
  - 无。

返回:
  - model.Module: 模块实例。
*/
func New() model.Module {
	return &Module{}
}

/*
Meta 返回盲注 payload 库模块的元数据。

参数:
  - 无。

返回:
  - model.Meta: 模块名称、类别、说明与参数声明。
*/
func (m *Module) Meta() model.Meta {
	return model.Meta{
		Name:     "payloads",
		Aliases:  []string{"blindsql", "payload"},
		Category: modulekit.CategoryWeb,
		Summary:  "盲注 payload 字典库",
		Description: "移植自作者的 BlindSQL 项目：内置布尔/时间盲注 payload 字典，\n" +
			"支持关键词过滤、计数与外部字典加载（每行一个 payload）。\n" +
			"完整 2465 行上游字典见 https://github.com/ctkqiang/BlindSQL 的 payload.txt；\n" +
			"本模块内置覆盖常用族的代表性子集。只输出字典内容，不主动发起请求。",
		Author: modulekit.Author,
		Options: []model.Option{
			modulekit.Option("QUERY", "过滤关键词，例如 OR 或 SLEEP；留空显示全部", false, ""),
			modulekit.Option("WORDLIST", "外部字典路径；存在时优先于内置字典", false, ""),
			modulekit.Option("LIMIT", "显示条目上限；0 表示不限制", false, "100"),
		},
		References: []string{"https://github.com/ctkqiang/BlindSQL"},
	}
}

/*
Run 加载并输出过滤后的 payload 列表。

参数:
  - ctx (context.Context): 执行上下文。
  - options (model.Options): 已合并默认值的模块参数。
  - out (io.Writer): 结果输出目标。

返回:
  - error: 外部字典读取失败时返回错误。
*/
func (m *Module) Run(ctx context.Context, options model.Options, out io.Writer) error {
	_ = ctx

	payloads := defaultPayloads()
	wordlist := strings.TrimSpace(options.Get("WORDLIST"))
	if wordlist != "" {
		loaded, err := loadWordlist(wordlist)
		if err != nil {
			return err
		}
		payloads = loaded
	}

	query := strings.ToLower(strings.TrimSpace(options.Get("QUERY")))
	matched := make([]string, 0, len(payloads))
	for _, payload := range payloads {
		if query == "" || strings.Contains(strings.ToLower(payload), query) {
			matched = append(matched, payload)
		}
	}

	limit := options.Int("LIMIT", 100)
	modulekit.Section(out, fmt.Sprintf("Payload 字典 · 命中 %d / %d", len(matched), len(payloads)))
	if wordlist != "" {
		fmt.Fprintf(out, "来源: %s\n", wordlist)
	} else {
		fmt.Fprintln(out, "来源: 内置字典（BlindSQL payload.txt 代表性子集）")
	}

	if len(matched) == 0 {
		fmt.Fprintln(out, "没有命中过滤条件的 payload。")
		return nil
	}

	for index, payload := range matched {
		if limit > 0 && index >= limit {
			fmt.Fprintf(out, "  … 其余 %d 条已省略（LIMIT=%d）\n", len(matched)-limit, limit)
			break
		}
		fmt.Fprintf(out, "%4d. %s\n", index+1, payload)
	}

	logger.Info("payload 字典输出完成：命中 %d 条", len(matched))
	return nil
}

/*
loadWordlist 按行读取外部字典，跳过空行与 # 注释行。

参数:
  - path (string): 字典文件路径。

返回:
  - []string: 读取到的 payload 列表。
  - error: 文件不存在或不可读时返回错误。
*/
func loadWordlist(path string) ([]string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取字典 %s 失败: %w", path, err)
	}

	payloads := make([]string, 0, 256)
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSuffix(line, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		payloads = append(payloads, line)
	}
	if len(payloads) == 0 {
		return nil, fmt.Errorf("字典 %s 为空", path)
	}
	return payloads, nil
}
