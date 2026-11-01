// dns 模块实现域名 A、AAAA、CNAME、MX、NS 与 TXT 记录查询。
package dns

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/ctkqiang/nezha_cli/internal/model"
	"github.com/ctkqiang/nezha_cli/internal/modulekit"
	"github.com/ctkqiang/nezha_cli/pkg/logger"
	"github.com/ctkqiang/nezha_cli/pkg/recon"
)

// Module 是 DNS 情报模块。
type Module struct{}

/*
New 创建 DNS 情报模块实例。

参数:
  - 无。

返回:
  - model.Module: 模块实例。
*/
func New() model.Module {
	return &Module{}
}

/*
Meta 返回 DNS 情报模块的元数据。

参数:
  - 无。

返回:
  - model.Meta: 模块名称、类别、说明与参数声明。
*/
func (m *Module) Meta() model.Meta {
	return model.Meta{
		Name:     "dns",
		Aliases:  []string{"lookup", "resolve"},
		Category: modulekit.CategoryRecon,
		Summary:  "域名 DNS 记录与解析结果",
		Description: "使用 Go 标准库解析器查询目标域名的 A、AAAA、CNAME、MX、NS 与 TXT 记录。\n" +
			"不调用 dig、nslookup 等外部命令，适合在最小化 Termux 环境中运行。",
		Author: modulekit.Author,
		Options: []model.Option{
			modulekit.Option("DOMAIN", "目标域名，例如 example.com", true, ""),
		},
	}
}

/*
Run 查询目标域名的 DNS 记录并输出结果。

参数:
  - ctx (context.Context): 查询上下文。
  - options (model.Options): 已合并默认值的模块参数。
  - out (io.Writer): 结果输出目标。

返回:
  - error: 域名为空或全部记录类型查询失败时返回错误。
*/
func (m *Module) Run(ctx context.Context, options model.Options, out io.Writer) error {
	domain := strings.TrimSpace(options.Get("DOMAIN"))
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimSuffix(domain, "/")
	if domain == "" {
		return fmt.Errorf("域名不能为空")
	}

	records, err := recon.LookupDNS(ctx, domain)
	if err != nil {
		return err
	}

	rows := make([][]string, 0, len(records))
	for _, record := range records {
		values := strings.Join(record.Values, ", ")
		if values == "" {
			values = "-"
		}
		rows = append(rows, []string{record.Type, modulekit.Etc(values, 64)})
	}

	modulekit.Section(out, "DNS · "+domain)
	modulekit.Table(out, []string{"类型", "值"}, rows, 68)
	logger.Info("DNS 查询完成：%d 类记录", len(rows))
	return nil
}
