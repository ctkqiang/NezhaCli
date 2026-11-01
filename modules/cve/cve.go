// cve 模块移植自作者的 CVE-Exploits 仓库：漏洞 PoC/Exploit 库目录。
package cve

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/ctkqiang/nezha_cli/internal/model"
	"github.com/ctkqiang/nezha_cli/internal/modulekit"
	"github.com/ctkqiang/nezha_cli/pkg/logger"
)

// ExploitEntry 描述 CVE-Exploits 仓库中的一条 PoC/Exploit。
type ExploitEntry struct {
	ID          string
	Target      string
	Language    string
	Description string
	CVSS        string
	Native      string
}

// Exploits 是 CVE-Exploits 仓库的目录数据。
// 仅收录可从仓库结构确认的信息；未写 README 的条目只标注语言与路径。
var Exploits = []ExploitEntry{
	{
		ID: "CVE-2025-14847", Target: "MongoDB zlib 压缩协议", Language: "Go", CVSS: "8.7",
		Description: "未授权远程堆内存信息泄露（MongoBleed），可泄露数据库凭证与 API 密钥。",
		Native:      "cve_2025_14847",
	},
	{
		ID: "CVE-2025-4334", Target: "WordPress 插件注册接口", Language: "Go", CVSS: "9.8",
		Description: "未认证权限提升：构造 role=administrator 注册请求创建管理员账户。",
		Native:      "cve_2025_4334",
	},
	{
		ID: "CVE-2025-66478", Target: "Next.js App Router（React2Shell）", Language: "Go/TypeScript", CVSS: "10.0",
		Description: "RSC 反序列化原型链污染导致远程代码执行；本控制台内置检测（非完整利用）。",
		Native:      "cve_2025_66478",
	},
	{
		ID: "CVE-2025-55182", Target: "Next.js Server Actions（React2Shell）", Language: "TypeScript/Bun", CVSS: "10.0",
		Description: "Server Actions 反序列化原型污染导致 RCE；PoC 位于仓库 CVE-2025-55182/。",
	},
	{
		ID: "CNVD-2026-13173", Target: "QuestDB 时间序列数据库", Language: "C++", CVSS: "中",
		Description: "认证配置失效导致未授权访问敏感数据；PoC 位于仓库 CNVD-2026-13173/。",
	},
	{
		ID: "CVE-2026-63030", Target: "WordPress（wp2shell）", Language: "C", CVSS: "严重",
		Description: "与 CVE-2026-60137 组合的预认证 RCE：路由混淆 + SQL 注入 + oEmbed 缓存投毒。",
	},
	{
		ID: "CVE-2023-41064", Target: "Apple ImageIO WebP", Language: "Objective-C/Swift", CVSS: "8.8",
		Description: "WebP 解码越界写（BLASTPASS 组件）；PoC 位于仓库 CVE-2023-41064/。",
	},
	{
		ID: "CVE-2023-21980", Target: "未知（仅 PoC 源码）", Language: "C", CVSS: "-",
		Description: "PoC 源码位于仓库 CVE-2023-21980/，详见源码注释。",
	},
	{
		ID: "CVE-2025-49844", Target: "未知（仅 PoC 源码）", Language: "Lua", CVSS: "-",
		Description: "PoC 源码位于仓库 CVE-2025-49844/，详见源码注释。",
	},
	{
		ID: "CVE-2025-9074", Target: "未知（仅 PoC 源码）", Language: "Python", CVSS: "-",
		Description: "PoC 源码位于仓库 CVE-2025-9074/，详见源码注释。",
	},
	{
		ID: "CVE-2026-1207", Target: "未知（仅 PoC 源码）", Language: "Ruby", CVSS: "-",
		Description: "PoC 源码位于仓库 CVE-2026-1207/，详见源码注释。",
	},
	{
		ID: "CVE-2026-22036", Target: "未知（仅 PoC 源码）", Language: "JavaScript", CVSS: "-",
		Description: "客户端/服务端/监控三件套位于仓库 CVE-2026-22036/，详见源码注释。",
	},
}

// Module 是 CVE 漏洞利用库目录模块。
type Module struct{}

/*
New 创建 CVE 漏洞利用库目录模块实例。

参数:
  - 无。

返回:
  - model.Module: 模块实例。
*/
func New() model.Module {
	return &Module{}
}

/*
Meta 返回 CVE 漏洞利用库目录模块的元数据。

参数:
  - 无。

返回:
  - model.Meta: 模块名称、类别、说明与参数声明。
*/
func (m *Module) Meta() model.Meta {
	return model.Meta{
		Name:     "cve",
		Aliases:  []string{"cves", "exploits", "poc"},
		Category: modulekit.CategoryWeb,
		Summary:  "CVE PoC/Exploit 库目录",
		Description: "列出 CVE-Exploits 仓库中的 PoC/Exploit 目录，标明编号、CVSS、语言与目标。\n" +
			"适用于检索漏洞库、查看单条详情，并定位本控制台已内置的原生检测模块。\n" +
			"纯 Go 实现、无外部依赖；只输出静态目录数据，不发起任何网络请求。\n" +
			"三个 Go 实现的 PoC 已原生集成：cve_2025_14847（MongoBleed）、cve_2025_4334（WordPress 提权）、\n" +
			"cve_2025_66478（React2Shell 检测），其余条目保留在仓库目录中按需查阅。",
		Usage:  "use cve\nset ID CVE-2025-14847\nrun",
		Author: modulekit.Author,
		Options: []model.Option{
			modulekit.Option("QUERY", "按编号或目标过滤，大小写不敏感；留空显示全部条目", false, ""),
			modulekit.Option("ID", "查看单条详情，例如 CVE-2025-14847；不存在时报错", false, ""),
		},
		References: []string{
			"https://github.com/ctkqiang/NezhaCli",
			"https://attack.mitre.org/",
		},
	}
}

/*
Run 输出漏洞库目录或单条详情。

参数:
  - ctx (context.Context): 执行上下文。
  - options (model.Options): 已合并默认值的模块参数。
  - out (io.Writer): 结果输出目标。

返回:
  - error: 指定的编号不在目录中时返回错误。
*/
func (m *Module) Run(ctx context.Context, options model.Options, out io.Writer) error {
	_ = ctx

	id := strings.ToUpper(strings.TrimSpace(options.Get("ID")))
	if id != "" {
		entry, ok := findEntry(id)
		if !ok {
			return fmt.Errorf("编号 %s 不在目录中", id)
		}
		printEntryDetail(out, entry)
		return nil
	}

	query := strings.ToLower(strings.TrimSpace(options.Get("QUERY")))
	rows := make([][]string, 0, len(Exploits))
	for _, entry := range Exploits {
		if query != "" && !strings.Contains(strings.ToLower(entry.ID+" "+entry.Target), query) {
			continue
		}
		rows = append(rows, []string{
			entry.ID,
			entry.CVSS,
			entry.Language,
			modulekit.Etc(entry.Target, 34),
			nativeLabel(entry.Native),
		})
	}

	modulekit.Section(out, fmt.Sprintf("CVE-Exploits 库 · 命中 %d / %d", len(rows), len(Exploits)))
	if len(rows) == 0 {
		fmt.Fprintln(out, "没有匹配的条目。")
		return nil
	}
	modulekit.Table(out, []string{"编号", "CVSS", "语言", "目标", "内置模块"}, rows, 40)

	logger.Info("cve 目录检索完成：命中 %d 条", len(rows))
	return nil
}

/*
printEntryDetail 输出单条漏洞详情。

参数:
  - out (io.Writer): 结果输出目标。
  - entry (ExploitEntry): 目标条目。

返回:
  - 无。
*/
func printEntryDetail(out io.Writer, entry ExploitEntry) {
	modulekit.Section(out, "漏洞 · "+entry.ID)
	modulekit.KeyValues(out, [][2]string{
		{"目标", entry.Target},
		{"语言", entry.Language},
		{"CVSS", entry.CVSS},
		{"内置模块", nativeLabel(entry.Native)},
		{"说明", entry.Description},
	}, 56)
	if entry.Native != "" {
		fmt.Fprintf(out, "提示: use %s 直接使用内置模块；主动利用类模块执行前必须输入 yes 确认授权。\n", entry.Native)
	}
}

/*
findEntry 按编号查找条目。

参数:
  - id (string): 漏洞编号。

返回:
  - ExploitEntry: 匹配的条目。
  - bool: 是否存在。
*/
func findEntry(id string) (ExploitEntry, bool) {
	for _, entry := range Exploits {
		if strings.EqualFold(entry.ID, id) {
			return entry, true
		}
	}
	return ExploitEntry{}, false
}

/*
nativeLabel 把内置模块名归一化为展示文本。

参数:
  - native (string): 内置模块名。

返回:
  - string: 模块名或 "-"。
*/
func nativeLabel(native string) string {
	if strings.TrimSpace(native) == "" {
		return "-"
	}
	return native
}
