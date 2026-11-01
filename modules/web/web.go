// web 模块实现 HTTP 安全响应头、Cookie 属性与标准情报文件审计。
package web

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ctkqiang/nezha_cli/internal/model"
	"github.com/ctkqiang/nezha_cli/internal/modulekit"
	"github.com/ctkqiang/nezha_cli/internal/netutil"
	"github.com/ctkqiang/nezha_cli/pkg/logger"
	websafe "github.com/ctkqiang/nezha_cli/pkg/web"
)

// Module 是 Web 安全头审计模块。
type Module struct{}

/*
New 创建 Web 安全头审计模块实例。

参数:
  - 无。

返回:
  - model.Module: 模块实例。
*/
func New() model.Module {
	return &Module{}
}

/*
Meta 返回 Web 安全头审计模块的元数据。

参数:
  - 无。

返回:
  - model.Meta: 模块名称、类别、说明与参数声明。
*/
func (m *Module) Meta() model.Meta {
	return model.Meta{
		Name:     "web",
		Aliases:  []string{"headers"},
		Category: modulekit.CategoryWeb,
		Summary:  "HTTP 安全头、Cookie 与标准文件审计",
		Description: "对目标 URL 发起只读 GET 请求，审计 CSP、HSTS、X-Frame-Options 等安全响应头，\n" +
			"检查 Cookie 的 Secure、HttpOnly 与 SameSite 属性，并枚举 robots.txt、sitemap.xml、\n" +
			"security.txt 与 Allow 方法。不发送任何漏洞利用载荷。",
		Author: modulekit.Author,
		Options: []model.Option{
			modulekit.Option("URL", "目标 URL，可省略 http://", true, ""),
			modulekit.Option("TIMEOUT", "单次 HTTP 请求超时", false, "10s"),
			modulekit.Option("DEEP", "是否检查标准文件与 Allow 方法", false, "true"),
		},
	}
}

/*
Run 执行 HTTP 安全头审计并输出结果。

参数:
  - ctx (context.Context): 请求上下文。
  - options (model.Options): 已合并默认值的模块参数。
  - out (io.Writer): 结果输出目标。

返回:
  - error: URL 非法或请求失败时返回错误。
*/
func (m *Module) Run(ctx context.Context, options model.Options, out io.Writer) error {
	parsed, err := netutil.NormalizeURL(options.Get("URL"), "http")
	if err != nil {
		return err
	}
	timeout := options.Duration("TIMEOUT", 10*time.Second)

	report, err := websafe.AuditHeaders(ctx, parsed.String(), timeout)
	if err != nil {
		return err
	}

	modulekit.Section(out, "目标")
	modulekit.KeyValues(out, [][2]string{
		{"请求 URL", report.URL},
		{"最终 URL", report.FinalURL},
		{"状态码", fmt.Sprintf("%d", report.StatusCode)},
		{"Server", dash(report.Server)},
		{"X-Powered-By", dash(report.PoweredBy)},
	}, 64)

	findingRows := make([][]string, 0, len(report.Findings))
	for _, finding := range report.Findings {
		status := "缺失"
		if finding.Present {
			status = "存在"
		}
		findingRows = append(findingRows, []string{
			finding.Name,
			status,
			finding.Severity,
			modulekit.Etc(dash(finding.Value), 40),
			modulekit.Etc(finding.Advice, 40),
		})
	}
	modulekit.Section(out, fmt.Sprintf("安全响应头 %d", len(findingRows)))
	modulekit.Table(out, []string{"响应头", "状态", "级别", "值", "建议"}, findingRows, 42)

	if len(report.Cookies) > 0 {
		cookieRows := make([][]string, 0, len(report.Cookies))
		for _, cookie := range report.Cookies {
			cookieRows = append(cookieRows, []string{
				cookie.Name,
				yesNo(cookie.Secure),
				yesNo(cookie.HTTPOnly),
				dash(cookie.SameSite),
			})
		}
		modulekit.Section(out, fmt.Sprintf("Cookie %d", len(cookieRows)))
		modulekit.Table(out, []string{"名称", "Secure", "HttpOnly", "SameSite"}, cookieRows, 36)
	}

	if options.Bool("DEEP", true) {
		if err := runDeep(ctx, out, parsed.String(), timeout); err != nil {
			logger.Warn("深度检查未完成：%v", err)
		}
	}

	logger.Info("Web 安全头审计完成：%d 项检查，%d 条 Cookie", len(report.Findings), len(report.Cookies))
	return nil
}

/*
runDeep 检查标准情报文件与 Allow 方法。

参数:
  - ctx (context.Context): 请求上下文。
  - out (io.Writer): 结果输出目标。
  - target (string): 目标 URL。
  - timeout (time.Duration): 单次请求超时。

返回:
  - error: 标准文件或方法检查失败时返回错误。
*/
func runDeep(ctx context.Context, out io.Writer, target string, timeout time.Duration) error {
	files, err := websafe.FetchWellKnown(ctx, target, timeout)
	if err != nil {
		return err
	}

	fileRows := make([][]string, 0, len(files))
	for _, file := range files {
		status := "未发现"
		if file.Found {
			status = fmt.Sprintf("%d", file.StatusCode)
		}
		snippet := file.Snippet
		if file.Error != "" {
			snippet = file.Error
		}
		fileRows = append(fileRows, []string{
			file.Path,
			status,
			dash(file.ContentType),
			modulekit.Etc(dash(snippet), 44),
		})
	}
	modulekit.Section(out, "标准情报文件")
	modulekit.Table(out, []string{"路径", "状态", "类型", "摘要"}, fileRows, 46)

	methods, err := websafe.AuditMethods(ctx, target, timeout)
	if err != nil {
		return err
	}
	modulekit.Section(out, "HTTP 方法")
	modulekit.KeyValues(out, [][2]string{
		{"状态码", fmt.Sprintf("%d", methods.StatusCode)},
		{"Allow", dash(methods.Allow)},
		{"方法", dash(strings.Join(methods.Methods, ", "))},
	}, 64)
	return nil
}

/*
dash 在值为空时返回占位符。

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
yesNo 把布尔值转换为中文状态。

参数:
  - value (bool): 布尔值。

返回:
  - string: “是”或“否”。
*/
func yesNo(value bool) string {
	if value {
		return "是"
	}
	return "否"
}
