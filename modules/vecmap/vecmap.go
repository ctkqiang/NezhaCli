// vecmap 模块移植自作者的 vecmap 项目：向量数据库攻击面只读评估。
package vecmap

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ctkqiang/nezha_cli/internal/model"
	"github.com/ctkqiang/nezha_cli/internal/modulekit"
	"github.com/ctkqiang/nezha_cli/pkg/logger"
	"github.com/ctkqiang/nezha_cli/pkg/vecmap"
)

// Module 是向量数据库攻击面评估模块。
type Module struct{}

/*
New 创建向量数据库攻击面评估模块实例。

参数:
  - 无。

返回:
  - model.Module: 模块实例。
*/
func New() model.Module {
	return &Module{}
}

/*
Meta 返回向量数据库攻击面评估模块的元数据。

参数:
  - 无。

返回:
  - model.Meta: 模块名称、类别、说明与参数声明。
*/
func (m *Module) Meta() model.Meta {
	return model.Meta{
		Name:     "vecmap",
		Aliases:  []string{"vector", "vectordb"},
		Category: modulekit.CategoryRecon,
		Summary:  "向量数据库攻击面只读评估",
		Description: "对向量数据库实例执行只读指纹识别、集合索引枚举与 CVE 版本关联。\n" +
			"适用于评估 Qdrant、Milvus、Weaviate、Chroma、Elasticsearch 等实例的暴露面。\n" +
			"移植自作者的 vecmap 项目，纯 Go 实现；只发送 GET/HEAD/OPTIONS 与只读 POST，\n" +
			"不做任何破坏性操作，全部 CVE 结论附带官方来源链接。",
		Usage:  "use vecmap\nset TARGET http://10.0.0.5:6333\nset DEEP false\nrun",
		Author: modulekit.Author,
		Options: []model.Option{
			modulekit.Option("TARGET", "目标 URL 或 host:port 写法；缺协议自动补 http；示例 http://10.0.0.5:6333。", true, ""),
			modulekit.Option("ADAPTER", "探测适配器；取值 auto 或具体厂商名；auto 依次探测全部。", false, "auto"),
			modulekit.Option("TIMEOUT", "单次探测超时；支持 3s 等 Go 时长格式。", false, "3s"),
			modulekit.Option("DEEP", "是否枚举集合与索引；取值 true/false；只读操作不修改数据。", false, "true"),
		},
		References: []string{
			"https://github.com/ctkqiang/NezhaCli",
			"https://qdrant.tech/documentation/",
			"https://milvus.io/docs/",
		},
	}
}

/*
Run 执行指纹识别、集合枚举与 CVE 关联。

参数:
  - ctx (context.Context): 探测上下文，Ctrl+C 时立即停止。
  - options (model.Options): 已合并默认值的模块参数。
  - out (io.Writer): 结果输出目标。

返回:
  - error: 目标解析失败、指纹识别失败时返回错误。
*/
func (m *Module) Run(ctx context.Context, options model.Options, out io.Writer) error {
	target, err := vecmap.ParseTarget(options.Get("TARGET"))
	if err != nil {
		return err
	}

	timeout := options.Duration("TIMEOUT", 3*time.Second)
	adapter := strings.ToLower(options.String("ADAPTER", "auto"))

	modulekit.Section(out, "目标")
	modulekit.KeyValues(out, [][2]string{
		{"目标", target.Raw},
		{"适配器", adapter},
		{"超时", timeout.String()},
	}, 60)

	result, err := vecmap.Identify(ctx, target, adapter, timeout)
	if err != nil {
		return fmt.Errorf("指纹识别失败: %w", err)
	}
	if result.Vendor == vecmap.VendorUnknown {
		return fmt.Errorf("未能在目标上识别出受支持的向量数据库")
	}

	logger.Success("识别到 %s%s", result.Vendor, versionSuffix(result.Version))

	modulekit.Section(out, "指纹")
	modulekit.KeyValues(out, [][2]string{
		{"厂商", string(result.Vendor)},
		{"版本", dash(result.Version)},
		{"需要认证", yesNo(result.AuthRequired)},
		{"Server 头", dash(result.Server)},
	}, 60)

	if len(result.Evidence) > 0 {
		modulekit.Section(out, "证据")
		for _, evidence := range result.Evidence {
			fmt.Fprintf(out, "  · %s\n", evidence)
		}
	}

	if options.Bool("DEEP", true) {
		collections, enumerateErr := vecmap.Enumerate(ctx, target, result.Vendor, timeout)
		if enumerateErr != nil {
			logger.Warn("集合枚举失败: %v", enumerateErr)
		} else {
			rows := make([][]string, 0, len(collections))
			for _, collection := range collections {
				fields := "-"
				if len(collection.Fields) > 0 {
					fields = modulekit.Etc(strings.Join(collection.Fields, ", "), 40)
				}
				count := "-"
				if collection.Count > 0 {
					count = fmt.Sprintf("%d", collection.Count)
				}
				rows = append(rows, []string{collection.Name, count, fields})
			}
			modulekit.Section(out, fmt.Sprintf("集合与索引 %d", len(rows)))
			if len(rows) == 0 {
				fmt.Fprintln(out, "未枚举到集合（可能需要认证）。")
			} else {
				modulekit.Table(out, []string{"名称", "文档数", "字段"}, rows, 46)
			}
		}
	}

	cves := vecmap.MatchCVE(result.Vendor, result.Version)
	modulekit.Section(out, fmt.Sprintf("CVE 关联 %d", len(cves)))
	if len(cves) == 0 {
		fmt.Fprintln(out, "当前版本未命中内置 CVE 库（版本为空时只按厂商过滤）。")
		return nil
	}

	cveRows := make([][]string, 0, len(cves))
	for _, entry := range cves {
		mitreID := "-"
		if technique, ok := vecmap.LookupMITRE(entry.TTP); ok {
			mitreID = fmt.Sprintf("%s %s", technique.ID, technique.NameZH)
		}
		cveRows = append(cveRows, []string{
			entry.ID,
			vecmap.SeverityLabel(entry.Severity),
			fmt.Sprintf("%.1f", entry.CVSS),
			modulekit.Etc(entry.TitleZH, 34),
			mitreID,
		})
	}
	modulekit.Table(out, []string{"编号", "级别", "CVSS", "标题", "ATT&CK"}, cveRows, 40)

	fmt.Fprintln(out)
	fmt.Fprintln(out, "  修复建议（按条目逐一核对官方来源）:")
	for _, entry := range cves {
		fmt.Fprintf(out, "  · %s -> 修复: %s | %s\n", entry.ID, dash(entry.Fixed), entry.Reference)
	}

	return nil
}

/*
versionSuffix 生成带版本的日志后缀。

参数:
  - version (string): 版本号。

返回:
  - string: 形如 " v1.12.3" 的后缀，版本为空时返回空串。
*/
func versionSuffix(version string) string {
	if strings.TrimSpace(version) == "" {
		return ""
	}
	return " v" + version
}

/*
dash 把空字符串归一化为占位符。

参数:
  - value (string): 原始值。

返回:
  - string: 原始值或 "-"。
*/
func dash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}

/*
yesNo 把布尔值转换为中文是否。

参数:
  - value (bool): 布尔值。

返回:
  - string: "是" 或 "否"。
*/
func yesNo(value bool) string {
	if value {
		return "是"
	}
	return "否"
}
