// tls 模块实现目标站点 TLS 证书与握手参数检查。
package tls

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ctkqiang/nezha_cli/internal/model"
	"github.com/ctkqiang/nezha_cli/internal/modulekit"
	"github.com/ctkqiang/nezha_cli/pkg/logger"
	websafe "github.com/ctkqiang/nezha_cli/pkg/web"
)

// Module 是 TLS 证书检查模块。
type Module struct{}

/*
New 创建 TLS 证书检查模块实例。

参数:
  - 无。

返回:
  - model.Module: 模块实例。
*/
func New() model.Module {
	return &Module{}
}

/*
Meta 返回 TLS 证书检查模块的元数据。

参数:
  - 无。

返回:
  - model.Meta: 模块名称、类别、说明与参数声明。
*/
func (m *Module) Meta() model.Meta {
	return model.Meta{
		Name:     "tls",
		Aliases:  []string{"cert", "ssl"},
		Category: modulekit.CategoryWeb,
		Summary:  "TLS 证书、有效期与信任链检查",
		Description: "与目标主机建立 TLS 连接，提取协议版本、密码套件、主题、签发者、有效期与 SAN。\n" +
			"握手阶段关闭默认链校验，因此可检查自签名与过期证书，并单独报告 Trusted 状态。",
		Author: modulekit.Author,
		Options: []model.Option{
			modulekit.Option("TARGET", "目标主机或 https:// URL", true, ""),
			modulekit.Option("PORT", "TLS 端口；URL 自带端口时优先使用 URL", false, "443"),
			modulekit.Option("TIMEOUT", "连接与握手超时", false, "10s"),
		},
	}
}

/*
Run 连接目标并输出证书信息。

参数:
  - ctx (context.Context): 连接上下文。
  - options (model.Options): 已合并默认值的模块参数。
  - out (io.Writer): 结果输出目标。

返回:
  - error: 目标非法、连接失败或握手失败时返回错误。
*/
func (m *Module) Run(ctx context.Context, options model.Options, out io.Writer) error {
	host, port, err := parseTarget(options.Get("TARGET"), options.Int("PORT", 443))
	if err != nil {
		return err
	}
	timeout := options.Duration("TIMEOUT", 10*time.Second)

	info, err := websafe.InspectTLS(ctx, host, port, timeout)
	if err != nil {
		return err
	}

	trusted := "否"
	if info.Trusted {
		trusted = "是"
	}
	valid := "否"
	if info.Valid {
		valid = "是"
	}

	modulekit.Section(out, "TLS · "+host)
	modulekit.KeyValues(out, [][2]string{
		{"目标", fmt.Sprintf("%s:%d", info.Host, info.Port)},
		{"TLS 版本", info.TLSVersion},
		{"密码套件", info.CipherSuite},
		{"主题", info.Subject},
		{"通用名", dash(info.CommonName)},
		{"签发者", info.Issuer},
		{"生效时间", info.NotBefore.Format("2006-01-02 15:04:05 MST")},
		{"到期时间", info.NotAfter.Format("2006-01-02 15:04:05 MST")},
		{"剩余天数", fmt.Sprintf("%d", info.DaysLeft)},
		{"证书有效", valid},
		{"系统信任", trusted},
		{"校验错误", dash(info.VerifyError)},
	}, 72)

	if len(info.DNSNames) > 0 {
		modulekit.Section(out, "SAN")
		rows := make([][]string, 0, len(info.DNSNames))
		for _, name := range info.DNSNames {
			rows = append(rows, []string{name})
		}
		modulekit.Table(out, []string{"域名"}, rows, 64)
	}

	if !info.Trusted {
		logger.Warn("证书未通过系统信任链校验：%s", dash(info.VerifyError))
	}
	if info.DaysLeft >= 0 && info.DaysLeft < 30 {
		logger.Warn("证书将在 %d 天内到期", info.DaysLeft)
	}

	logger.Info("TLS 检查完成：%s，剩余 %d 天", info.TLSVersion, info.DaysLeft)
	return nil
}

/*
parseTarget 从主机或 URL 中提取主机名与端口。

参数:
  - raw (string): 目标主机或 URL。
  - defaultPort (int): 未显式指定端口时使用的端口。

返回:
  - string: 主机名。
  - int: 端口。
  - error: 目标为空或端口非法时返回错误。
*/
func parseTarget(raw string, defaultPort int) (string, int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", 0, fmt.Errorf("目标不能为空")
	}

	host := raw
	port := defaultPort
	if strings.Contains(raw, "://") {
		parsed, err := url.Parse(raw)
		if err != nil {
			return "", 0, fmt.Errorf("URL 解析失败: %w", err)
		}
		host = parsed.Hostname()
		if parsed.Port() != "" {
			value, err := strconv.Atoi(parsed.Port())
			if err != nil {
				return "", 0, fmt.Errorf("URL 端口非法: %s", parsed.Port())
			}
			port = value
		}
	}

	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return "", 0, fmt.Errorf("目标缺少主机名")
	}
	if port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("端口超出范围: %d", port)
	}
	return host, port, nil
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
